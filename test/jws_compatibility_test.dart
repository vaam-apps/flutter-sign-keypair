import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

import 'support/reference_jws_signer.dart';

/// The most important test in this package.
///
/// A signer that is fast but produces signatures the BFF rejects is worse than
/// no signer at all. These tests pin the new package's output against the
/// implementation actually shipping in `mobile/lib/core/crypto/jws_signer.dart`,
/// reproduced verbatim in `support/reference_jws_signer.dart`.
void main() {
  // A fixed P-256 scalar, so failures are reproducible rather than flaky.
  final Uint8List privateScalar = Uint8List.fromList(
    List<int>.generate(32, (int i) => (i * 7 + 13) & 0xff),
  );

  late SoftwareSecureSigner platform;
  late SignKeypair signer;
  late SecureKey key;

  setUp(() async {
    platform = SoftwareSecureSigner(store: InMemorySoftwareKeyStore());
    signer = SignKeypair(platform: platform);
    key = await platform.importKey(
      keyId: SignKeypair.defaultKeyId,
      privateScalar: privateScalar,
    );
  });

  group('signature correctness vs the shipping pointycastle implementation', () {
    test('both signatures verify against the same public key', () async {
      final Map<String, dynamic> payload = <String, dynamic>{
        'timestamp_ms': 1753900000000,
        'device_id': 'device-abc',
        'method': 'POST',
        'path': '/bff/v1/payments/transfer',
      };

      final String packageJws = await signer.signCompactJws(payload: payload);
      final String referenceJws = ReferenceJwsSigner.sign(
        payload: payload,
        privateScalar: privateScalar,
      );

      final pc.ECPublicKey publicKey = publicKeyFromJwk(key.publicKey);

      // Both signatures must verify against the ONE public key the BFF holds.
      expect(
        verifyCompactJws(packageJws, publicKey),
        isTrue,
        reason:
            'flutter_sign_keypair produced a signature the verifier rejects',
      );
      expect(
        verifyCompactJws(referenceJws, publicKey),
        isTrue,
        reason:
            'the reference implementation itself failed to verify — '
            'the test harness is wrong, not the package',
      );
    });

    test('produces byte-identical output to jws_signer.dart', () async {
      final Map<String, dynamic> payload = <String, dynamic>{
        'nonce': 'a3f9c2',
        'timestamp_ms': 1753900000001,
        'device_id': 'device-abc',
        'user_id': 'user-42',
      };

      final String packageJws = await signer.signCompactJws(payload: payload);
      final String referenceJws = ReferenceJwsSigner.sign(
        payload: payload,
        privateScalar: privateScalar,
      );

      // Both use RFC 6979 deterministic k with HMAC-SHA256, so equal inputs
      // must give equal signatures — a strictly stronger claim than "verifies".
      expect(packageJws, referenceJws);
    });

    test('the protected header matches the one the BFF expects', () async {
      final String jws = await signer.signCompactJws(
        payload: <String, dynamic>{'x': 1},
      );
      final String header = jws.split('.').first;
      expect(
        utf8.decode(base64Url.decode(base64.normalize(header))),
        '{"alg":"ES256","typ":"JWT"}',
      );
    });

    test('the compact JWS has three unpadded base64url segments', () async {
      final String jws = await signer.signCompactJws(
        payload: <String, dynamic>{'device_id': 'd', 'timestamp_ms': 1},
      );
      final List<String> parts = jws.split('.');
      expect(parts, hasLength(3));
      for (final String part in parts) {
        expect(part, isNot(contains('=')), reason: 'padding leaked into JWS');
        expect(part, isNot(contains('+')));
        expect(part, isNot(contains('/')));
      }
      // Signature segment is 64 raw bytes -> 86 base64url chars, unpadded.
      expect(parts[2].length, 86);
    });

    test('signRaw returns exactly 64 bytes of IEEE P1363 r‖s', () async {
      final Uint8List signature = await signer.signRaw(
        signingInput: utf8.encode('the.signing.input'),
      );
      expect(signature, hasLength(64));
    });

    test('a tampered payload fails verification', () async {
      final String jws = await signer.signCompactJws(
        payload: <String, dynamic>{'amount': 1000, 'device_id': 'd'},
      );
      final List<String> parts = jws.split('.');
      final String forged = SignKeypair.base64UrlNoPadding(
        utf8.encode(
          jsonEncode(<String, dynamic>{'amount': 999999, 'device_id': 'd'}),
        ),
      );
      final String tampered = '${parts[0]}.$forged.${parts[2]}';

      expect(
        verifyCompactJws(tampered, publicKeyFromJwk(key.publicKey)),
        isFalse,
      );
    });

    test('a signature from a different key fails verification', () async {
      final SoftwareSecureSigner other = SoftwareSecureSigner(
        store: InMemorySoftwareKeyStore(),
      );
      final SecureKey otherKey = await other.generateKey(
        keyId: 'other',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(otherKey.publicKey, isNot(key.publicKey));

      final String jws = await signer.signCompactJws(
        payload: <String, dynamic>{'device_id': 'd'},
      );
      expect(
        verifyCompactJws(jws, publicKeyFromJwk(otherKey.publicKey)),
        isFalse,
      );
    });
  });

  group('every payload shape jws_signer.dart actually emits', () {
    // Guards against a payload whose JSON encoding differs between the two
    // implementations — int vs string, key ordering, unicode escaping.
    final List<(String, Map<String, dynamic>)> cases =
        <(String, Map<String, dynamic>)>[
          (
            'signChallenge',
            <String, dynamic>{
              'nonce': 'n0nc3',
              'timestamp_ms': 1753900000000,
              'device_id': 'dev',
              'user_id': 'usr',
            },
          ),
          (
            'signRequest',
            <String, dynamic>{
              'timestamp_ms': 1753900000000,
              'device_id': 'dev',
              'method': 'GET',
              'path': '/bff/v1/accounts/balance',
            },
          ),
          (
            'signCashoutQR',
            <String, dynamic>{
              'type': 'cashout',
              'nonce': 'qr-nonce',
              'amount': 50000,
              'customer_id': 'cust-1',
              'expires_at': 1753900600,
              'device_id': 'dev',
              'timestamp_ms': 1753900000000,
            },
          ),
          (
            'signVoucher',
            <String, dynamic>{
              'type': 'offline_voucher',
              'voucher_id': 'v-1',
              'amount': 25000,
              'max_amount': 100000,
              'expires_at': 1753986400,
              'created_at': 1753900000,
              'customer_id': 'cust-1',
              'device_id': 'dev',
              'timestamp_ms': 1753900000000,
            },
          ),
          (
            'accented text (Cameroon French copy reaches these payloads)',
            <String, dynamic>{
              'device_id': 'dév-îce',
              'label': 'Retrait d’espèces',
              'timestamp_ms': 1753900000000,
            },
          ),
        ];

    for (final (String name, Map<String, dynamic> payload) in cases) {
      test('$name matches the reference implementation', () async {
        expect(
          await signer.signCompactJws(payload: payload),
          ReferenceJwsSigner.sign(
            payload: payload,
            privateScalar: privateScalar,
          ),
        );
      });
    }
  });

  test('the derived public JWK matches the reference derivation', () async {
    final Map<String, dynamic> jwk = (await signer.getPublicKeyJwk())!;
    expect(jwk['kty'], 'EC');
    expect(jwk['crv'], 'P-256');
    expect(jwk['x'], ReferenceJwsSigner.publicJwk(privateScalar)['x']);
    expect(jwk['y'], ReferenceJwsSigner.publicJwk(privateScalar)['y']);
  });
}
