# Verifying signatures

The plugin produces standard ES256 compact JWS, so your backend can verify it
with any JWS library that supports ES256 and a P-256 public key in JWK form.
This page lists exactly what the plugin emits, so you know what to check, and
shows the verification the package's own tests run.

::: info What the plugin does not do
`flutter_sign_keypair` runs on the device. It has no server component, and it
does not decide your enrolment, freshness or revocation rules. Those belong in
your backend.
:::

## What your backend receives

### At enrolment: the public key

`SecureKey.publicKey.toJson()` (or `getPublicKeyJwk()`) gives you:

```json
{
  "crv": "P-256",
  "kty": "EC",
  "x": "<43 base64url characters>",
  "y": "<43 base64url characters>"
}
```

- `x` and `y` are the 32-byte affine coordinates, base64url **without
  padding**. A coordinate that starts with zero bytes is still padded to the
  full 32 bytes before encoding.
- The members are exactly these four, in RFC 7638 canonical order, so the
  serialised JSON can be hashed directly to compute a JWK thumbprint, a
  convenient stable id for a device key.

With the two-key model, register **both** public keys and remember which is
which: the point of the user-present key is that your backend can require it
for sensitive operations and reject the ambient key there.

### On each request: a compact JWS

```text
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<signature>
```

| Segment   | Contents                                                                          |
| --------- | --------------------------------------------------------------------------------- |
| header    | always `{"alg":"ES256","typ":"JWT"}`, base64url without padding                   |
| payload   | `jsonEncode` of the map you passed, UTF-8, base64url without padding              |
| signature | 64 bytes, `r‖s` (IEEE P1363), each 32 bytes big-endian, base64url without padding |

The signature covers the ASCII bytes of `header.payload`, hashed with SHA-256.
The header carries no `kid`, so your backend has to know which device key to
verify against from something else in the request (the payload, or your own
device identifier).

## Checks to make

1. Split the token into exactly three segments.
2. Decode the header and require `alg` to be `ES256`. Never let the token
   choose the algorithm.
3. Decode the signature and require exactly 64 bytes.
4. Verify the ECDSA P-256 / SHA-256 signature over `header.payload` with the
   device's registered public key.
5. Only then trust the payload. `signCompactJws` adds no claims of its own (no
   `iat`, `exp` or nonce), so check whatever freshness and binding fields you
   put in it, for example a timestamp within a short window, and the request
   method and path.

Do not compare signatures for equality or use them as cache keys: hardware
signers use a random `k`, so the same payload signs differently each time.

## Verification in Dart

This is the check the plugin's on-device integration test
([`example/integration_test/secure_signer_test.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/example/integration_test/secure_signer_test.dart))
runs against signatures made by the secure element, using `pointycastle`. It
works anywhere Dart runs, including a Dart backend:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';
import 'package:pointycastle/export.dart' as pc;

final pc.ECDomainParameters _domain = pc.ECDomainParameters('prime256v1');

pc.ECPublicKey publicKeyFromJwk(EcPublicJwk jwk) => pc.ECPublicKey(
  _domain.curve.createPoint(_toBigInt(jwk.xBytes), _toBigInt(jwk.yBytes)),
  _domain,
);

bool verifyCompactJws(String jws, pc.ECPublicKey publicKey) {
  final List<String> parts = jws.split('.');
  if (parts.length != 3) return false;
  final Uint8List signature = base64Url.decode(base64.normalize(parts[2]));
  if (signature.length != 64) return false;

  final pc.ECDSASigner verifier = pc.ECDSASigner(
    pc.SHA256Digest(),
    pc.HMac(pc.SHA256Digest(), 64),
  )..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKey));
  return verifier.verifySignature(
    utf8.encode('${parts[0]}.${parts[1]}'),
    pc.ECSignature(
      _toBigInt(Uint8List.sublistView(signature, 0, 32)),
      _toBigInt(Uint8List.sublistView(signature, 32, 64)),
    ),
  );
}

BigInt _toBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (final int byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}
```

On a server you will usually start from the stored JWK map:
`publicKeyFromJwk(EcPublicJwk.fromJson(storedJwk))`. `fromJson` rejects
anything that is not an EC P-256 key.

This snippet checks the signature only (steps 1, 3 and 4 above). Add the
header and payload checks your backend needs.

## Verifiers that want DER

JWS libraries expect the 64-byte `r‖s` form, which is what the plugin emits.
Some lower-level ECDSA APIs (`java.security.Signature`, OpenSSL's
`dgst -verify`, Apple's `.ecdsaSignatureMessageX962SHA256`) expect ASN.1 DER
instead. Convert with the codec the package exports:

```dart
final Uint8List der = EcdsaSignatureCodec.p1363ToDer(p1363Signature);
```

Feeding the raw 64 bytes to a DER verifier, or DER to a JWS verifier, fails,
and the failure looks like a bad signature.

## The proof behind it

The package's test suite pins this format down:

- `test/jws_compatibility_test.dart` checks that the package's JWS verifies
  against the same public key as an independent reference ES256 signer, and is
  byte-identical to it for the same key and payload (the software signer uses
  deterministic `k`, which makes byte equality testable). It covers several
  payload shapes, including accented French text, and the negative cases: a
  tampered payload and a different key both fail.
- The on-device integration test verifies a real keystore signature against
  the JWK the plugin reported, checks that a forged payload fails, and checks
  that signatures from two keys never verify under each other's key.

More on how the claims are tested is on [Testing & proof](./testing).
