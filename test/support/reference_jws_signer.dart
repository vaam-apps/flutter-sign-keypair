import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// The signing path that ships today, reproduced verbatim.
///
/// Copied from `mobile/lib/core/crypto/jws_signer.dart` (`_signPayload`,
/// `_p1363Encode`, `_bigIntToBytes32`, `_bytesToBigInt`) so the package's output
/// can be pinned against the exact bytes the BFF accepts in production. It is
/// deliberately a copy rather than an import: `mobile/` is a separate pubspec,
/// and this package must be testable without resolving the whole app.
///
/// If `jws_signer.dart` changes, this file must change with it — and the
/// compatibility tests will fail loudly if it does not.
class ReferenceJwsSigner {
  const ReferenceJwsSigner._();

  static final pc.ECDomainParameters _domain = pc.ECDomainParameters(
    'prime256v1',
  );

  static final String _jwsHeaderEncoded = _base64UrlNoPadding(
    utf8.encode(jsonEncode(<String, String>{'alg': 'ES256', 'typ': 'JWT'})),
  );

  /// Produce a compact ES256 JWS exactly as the app does today.
  static String sign({
    required Map<String, dynamic> payload,
    required Uint8List privateScalar,
  }) {
    final String payloadEncoded = _base64UrlNoPadding(
      utf8.encode(jsonEncode(payload)),
    );
    final String signingInput = '$_jwsHeaderEncoded.$payloadEncoded';
    final Uint8List signingInputBytes = utf8.encode(signingInput);

    final pc.ECPrivateKey privateKey = pc.ECPrivateKey(
      _bytesToBigInt(privateScalar),
      _domain,
    );
    final pc.ECDSASigner signer = pc.ECDSASigner(
      pc.SHA256Digest(),
      pc.HMac(pc.SHA256Digest(), 64),
    )..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey));
    final pc.ECSignature ecSig =
        signer.generateSignature(signingInputBytes) as pc.ECSignature;

    final Uint8List signatureBytes = _p1363Encode(ecSig.r, ecSig.s);
    return '$signingInput.${_base64UrlNoPadding(signatureBytes)}';
  }

  /// The public JWK the app's `KeyManager` would derive from the same scalar.
  static Map<String, String> publicJwk(Uint8List privateScalar) {
    final pc.ECPoint q = (_domain.G * _bytesToBigInt(privateScalar))!;
    return <String, String>{
      'x': _base64UrlNoPadding(_bigIntToBytes32(q.x!.toBigInteger()!)),
      'y': _base64UrlNoPadding(_bigIntToBytes32(q.y!.toBigInteger()!)),
    };
  }

  static String _base64UrlNoPadding(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static Uint8List _p1363Encode(BigInt r, BigInt s) {
    return Uint8List(64)
      ..setRange(0, 32, _bigIntToBytes32(r))
      ..setRange(32, 64, _bigIntToBytes32(s));
  }

  static Uint8List _bigIntToBytes32(BigInt n) {
    final String hex = n.toRadixString(16).padLeft(64, '0');
    return Uint8List.fromList(<int>[
      for (int i = 0; i < 32; i++)
        int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
    ]);
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (final int byte in bytes) {
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }
}

/// Rebuild a pointycastle public key from the JWK a signer reported.
///
/// This is the verifier's side of the contract: it only ever sees the JWK that
/// was registered with the BFF, never the private half.
pc.ECPublicKey publicKeyFromJwk(EcPublicJwk jwk) {
  final pc.ECDomainParameters domain = pc.ECDomainParameters('prime256v1');
  final pc.ECPoint point = domain.curve.createPoint(
    _toBigInt(jwk.xBytes),
    _toBigInt(jwk.yBytes),
  );
  return pc.ECPublicKey(point, domain);
}

/// Verify a compact ES256 JWS against [publicKey], the way a JWS verifier does.
bool verifyCompactJws(String jws, pc.ECPublicKey publicKey) {
  final List<String> parts = jws.split('.');
  if (parts.length != 3) return false;

  final Uint8List signingInput = utf8.encode('${parts[0]}.${parts[1]}');
  final Uint8List signature = base64Url.decode(base64.normalize(parts[2]));
  if (signature.length != 64) return false;

  final pc.ECDSASigner verifier = pc.ECDSASigner(
    pc.SHA256Digest(),
    pc.HMac(pc.SHA256Digest(), 64),
  )..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKey));

  return verifier.verifySignature(
    signingInput,
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
