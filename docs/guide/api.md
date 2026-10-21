# API overview

Everything is exported from one library:

```dart
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';
```

The package is not on pub.dev, so there is no hosted API reference. The doc
comments in [`lib/`](https://github.com/vaam-apps/flutter-sign-keypair/tree/main/lib)
are the authoritative reference. This page lists every public member and what it does.

## `SignKeypair`

The app-facing API, in
[`lib/flutter_sign_keypair.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/lib/flutter_sign_keypair.dart).

```dart
SignKeypair({SignKeypairPlatform? platform})
```

With no argument it installs the default backend for the current platform, if
none is installed yet. Passing `platform` replaces
`SignKeypairPlatform.instance`, which is shared by every `SignKeypair` in the
process; that is meant for tests and custom backends.

### Constants

| Member                    | Value                   | Meaning                                        |
| ------------------------- | ----------------------- | ---------------------------------------------- |
| `defaultKeyId`            | `'device'`              | The ambient key, used when a call names no key |
| `defaultUserPresentKeyId` | `'device_user_present'` | The user-present key, the one that prompts     |

### Methods

```dart
Future<SignerCapabilities> capabilities();
Future<bool> isHardwareBackingAvailable();

Future<SecureKey> generateKey({
  String keyId = defaultKeyId,
  bool requireHardware = false,
  bool overwrite = false,
  KeyProtection protection = KeyProtection.ambient,
});
Future<DeviceKeyPair> generateDeviceKeys({
  String ambientKeyId = defaultKeyId,
  String userPresentKeyId = defaultUserPresentKeyId,
  bool requireHardware = false,
  bool overwrite = false,
});

Future<SecureKey?> getKey({String keyId = defaultKeyId});
Future<bool> hasKey({String keyId = defaultKeyId});
Future<Map<String, dynamic>?> getPublicKeyJwk({String keyId = defaultKeyId});

Future<String> signCompactJws({
  required Map<String, dynamic> payload,
  String keyId = defaultKeyId,
  String? reason,
});
Future<Uint8List> signRaw({
  required Uint8List signingInput,
  String keyId = defaultKeyId,
  String? reason,
});

Future<void> deleteKey({String keyId = defaultKeyId});

static String base64UrlNoPadding(List<int> bytes);
```

| Method                         | What it does                                                                                                           |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `capabilities()`               | Probes what this device can do right now. Call it once at startup and log it                                           |
| `isHardwareBackingAvailable()` | Whether a key generated now would be hardware-backed                                                                   |
| `generateKey()`                | Creates one P-256 key. `requireHardware` fails instead of returning a weaker key; `overwrite` replaces an existing one |
| `generateDeviceKeys()`         | Creates both keys of the two-key model, rolling the ambient key back if the user-present one fails                     |
| `getKey()`                     | The existing key handle, or `null` when there is none                                                                  |
| `hasKey()`                     | Whether a key exists under `keyId`                                                                                     |
| `getPublicKeyJwk()`            | The public key as a JWK map, ready to send to your backend, or `null`                                                  |
| `signCompactJws()`             | Signs a JSON payload and returns a compact ES256 JWS                                                                   |
| `signRaw()`                    | Signs bytes you supply and returns the 64-byte IEEE P1363 `r‖s` signature                                              |
| `deleteKey()`                  | Deletes the key. Deleting a key that does not exist is a no-op                                                         |
| `base64UrlNoPadding()`         | base64url without padding, as RFC 7515 requires                                                                        |

`reason` is the localized sentence shown in the authentication prompt when the
key is user-present. Ambient keys ignore it. See
[Getting started](./getting-started#first-signature) for why you should always
pass it.

::: info Overwriting a key
`overwrite: true` replaces a key, which changes its public key. Whatever
registration your backend holds for the old key stops working until you
register the new `SecureKey.publicKey`.
:::

## Models

All in [`lib/src/models.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/lib/src/models.dart).

### `SecureKey`

A handle to a key held by the platform. It never carries private key material.

| Member             | Type          | Meaning                                                   |
| ------------------ | ------------- | --------------------------------------------------------- |
| `keyId`            | `String`      | The id to pass to later sign and delete calls             |
| `publicKey`        | `EcPublicJwk` | The public half, for device registration                  |
| `backing`          | `KeyBacking`  | Where the private half lives, as reported by the platform |
| `isHardwareBacked` | `bool`        | Shortcut for `backing.isHardwareBacked`                   |

### `DeviceKeyPair`

What `generateDeviceKeys()` returns: `ambient` and `userPresent`, both
`SecureKey`s. Its `isHardwareBacked` is true only when **both** keys are: the
pair is as trustworthy as its weaker key.

### `EcPublicJwk`

An EC P-256 public key in JWK form (RFC 7517, RFC 7518 §6.2).

| Member                                        | Meaning                                                                                      |
| --------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `x`, `y`                                      | The coordinates, base64url without padding (43 characters each)                              |
| `xBytes`, `yBytes`                            | The raw 32-byte coordinates                                                                  |
| `toJson()`                                    | `{crv: 'P-256', kty: 'EC', x, y}`, in RFC 7638 canonical order, ready to thumbprint          |
| `EcPublicJwk.fromCoordinates(x: ..., y: ...)` | Builds one from raw 32-byte coordinates; throws `ArgumentError` for any other length         |
| `EcPublicJwk.fromJson(map)`                   | Parses a JWK map; throws `FormatException` unless it is `kty: EC`, `crv: P-256` with `x`/`y` |

Two `EcPublicJwk`s are equal when their `x` and `y` are.

### `SignerCapabilities`

| Member                 | Meaning                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `platform`             | `android`, `ios`, `macos` or `dart-software`                            |
| `bestAvailableBacking` | The strongest `KeyBacking` a `generateKey` call would produce right now |
| `isHardwareBacked`     | Whether a key generated now would be hardware-backed                    |

### `KeyBacking`

`strongBox`, `secureEnclave`, `trustedExecutionEnvironment`, `keychain`,
`software`, in decreasing order of assurance. `isHardwareBacked` is true for
the first three only. `wireName` and `KeyBacking.fromWire()` map to and from
the channel's tags; an unknown tag becomes `software`. See
[How it works](./how-it-works#key-backing).

### `KeyProtection`

`ambient` (never prompts) and `userPresent` (prompts on every use).
`requiresUserPresence` tells them apart. `KeyProtection.fromWire()` returns
`null` for an unknown tag, deliberately with no default. See
[the two-key model](./how-it-works#the-two-key-model).

### `SecureSignerException` and `SignerErrorCode`

Every platform failure arrives as a `SecureSignerException` with a `code`
(`SignerErrorCode`), the `rawCode` string exactly as the platform sent it, a
`message` that never contains key material, and optional `details`. The codes,
and how to handle each, are on the [Errors](./errors) page.

## Software fallback

In [`lib/src/software_signer.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/lib/src/software_signer.dart).

### `SoftwareSecureSigner`

```dart
SoftwareSecureSigner({SoftwareKeyStore? store, Random? random})
```

The pure-Dart ES256 signer, used by default on web, Windows and Linux. It
implements `SignKeypairPlatform`, and:

- reports `platform: 'dart-software'` and `KeyBacking.software` for everything;
- refuses `requireHardware: true` and any `KeyProtection.userPresent` key with
  `hardwareUnavailable`, rather than issuing a key that cannot keep its
  promise;
- signs with RFC 6979 deterministic `k`;
- keeps parsed keys in an in-process cache, so a hot signing path does not
  re-read the store.

It adds one method of its own:

```dart
Future<SecureKey> importKey({
  required String keyId,
  required Uint8List privateScalar, // 32 bytes
  bool overwrite = false,
})
```

`importKey` adopts an existing raw P-256 private scalar, for devices that
already registered a key generated outside this package. The key stays a
software key and reports `KeyBacking.software`: a key that has existed outside
a secure element cannot be put into one. It throws `ArgumentError` for a
scalar that is not 32 bytes or is out of range. See
[Migrating devices](./migration).

### `SoftwareKeyStore` and `InMemorySoftwareKeyStore`

Where `SoftwareSecureSigner` keeps its keys:

```dart
abstract class SoftwareKeyStore {
  Future<String?> read(String keyId);
  Future<void> write(String keyId, String value);
  Future<void> delete(String keyId); // deleting a missing key is a no-op
}
```

The default, `InMemorySoftwareKeyStore`, lives as long as the process: keys
are gone after a restart. To keep software keys, implement `SoftwareKeyStore`
over storage your app already trusts and pass it in. The value written is a
JSON string that **contains the private scalar** (`d`, `x`, `y` as unpadded
base64url), so store it accordingly.

## Lower-level pieces

### `SignKeypairPlatform`

The backend contract, in
[`lib/src/platform_interface.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/lib/src/platform_interface.dart).
It is a `PlatformInterface`, so an out-of-tree package can register its own
backend (a Windows or Linux implementation, say) by assigning
`SignKeypairPlatform.instance`. An implementation provides `capabilities()`,
`generateKey(...)`, `getKey(keyId)`, `sign(...)` and `deleteKey(keyId)`.

Its contract, from the doc comments:

- `generateKey` with `requireHardware: true` must throw `hardwareUnavailable`
  rather than return a software key.
- An implementation that cannot enforce `KeyProtection.userPresent` must refuse
  rather than fall back to an ambient key.
- `sign` receives the raw signing input, hashes it with SHA-256 itself, and
  returns a 64-byte IEEE P1363 signature.
- Deleting a key that does not exist is a no-op.

`SignKeypairPlatform.hasInstance` tells you whether a backend is installed;
reading `instance` before one is throws a `StateError`.

### `MethodChannelSignKeypair` and `SignerMethod`

The backend for Android, iOS and macOS. It talks over the method channel
`com.vaam/flutter_sign_keypair` (exposed as `MethodChannelSignKeypair.channel`).
`SignerMethod` names the five channel methods: `capabilities`, `generateKey`,
`getKey`, `sign` and `deleteKey`.

It maps a `PlatformException` to `SecureSignerException`, a missing plugin to
`unsupportedPlatform`, and rejects a native signature that is not 64 bytes.

### `EcdsaSignatureCodec`

The signature encoding conversions, in
[`lib/src/asn1.dart`](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/lib/src/asn1.dart):

| Member                                  | Meaning                                                    |
| --------------------------------------- | ---------------------------------------------------------- |
| `EcdsaSignatureCodec.derToP1363(der)`   | ASN.1 DER `SEQUENCE { r, s }` to 64-byte `r‖s`             |
| `EcdsaSignatureCodec.p1363ToDer(p1363)` | 64-byte `r‖s` to DER, for a verifier that only accepts DER |
| `coordinateLength`, `p1363Length`       | `32` and `64`                                              |

Both throw `FormatException` on malformed input instead of reading out of
bounds.
