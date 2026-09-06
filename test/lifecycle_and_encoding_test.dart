import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

import 'support/reference_jws_signer.dart';

/// Key lifecycle, concurrency, and JWK encoding.
///
/// These run against [SoftwareSecureSigner] because it is the backend that can
/// be driven deterministically in a unit test. The native backends are covered
/// for the same behaviours by `SecureKeyStoreTest` (instrumented) and the
/// example's `integration_test`.
void main() {
  late SoftwareSecureSigner signer;

  setUp(() {
    signer = SoftwareSecureSigner(store: InMemorySoftwareKeyStore());
  });

  Future<SecureKey> generate([String keyId = 'k']) => signer.generateKey(
    keyId: keyId,
    requireHardware: false,
    overwrite: true,
    protection: KeyProtection.ambient,
  );

  Matcher throwsCode(SignerErrorCode code) => throwsA(
    isA<SecureSignerException>().having(
      (SecureSignerException e) => e.code,
      'code',
      code,
    ),
  );

  group('key lifecycle', () {
    test('generate -> sign -> delete -> sign fails cleanly', () async {
      await generate();
      final Uint8List signature = await signer.sign(
        keyId: 'k',
        payload: utf8.encode('payload'),
      );
      expect(signature, hasLength(64));

      await signer.deleteKey('k');

      // The important part: a *clean typed failure*, not a stale signature and
      // not a crash. A stale signature here would be the worst outcome — the
      // caller would believe a deleted credential still works.
      await expectLater(
        signer.sign(keyId: 'k', payload: utf8.encode('payload')),
        throwsCode(SignerErrorCode.keyNotFound),
      );
      expect(await signer.getKey('k'), isNull);
    });

    test('signing a key id that never existed fails cleanly', () async {
      await expectLater(
        signer.sign(keyId: 'never_created', payload: utf8.encode('x')),
        throwsCode(SignerErrorCode.keyNotFound),
      );
    });

    test('deleting a key id that never existed is a no-op', () async {
      await expectLater(signer.deleteKey('never_created'), completes);
    });

    test('generating twice with the same id needs overwrite', () async {
      await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      await expectLater(
        signer.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        ),
        throwsCode(SignerErrorCode.keyAlreadyExists),
      );
    });

    test('a refused generate leaves the original key intact', () async {
      final SecureKey first = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      await expectLater(
        signer.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        ),
        throwsCode(SignerErrorCode.keyAlreadyExists),
      );
      // The failed call must not have clobbered anything.
      expect((await signer.getKey('k'))!.publicKey, first.publicKey);
    });

    test(
      'overwrite replaces the key, and old signatures stop verifying',
      () async {
        final SecureKey first = await generate();
        final Uint8List payload = utf8.encode('same payload');
        final Uint8List firstSignature = await signer.sign(
          keyId: 'k',
          payload: payload,
        );

        final SecureKey second = await generate();
        expect(second.publicKey, isNot(first.publicKey));

        // The old signature must not verify under the new key — otherwise
        // "rotate the key" would not actually invalidate anything.
        expect(
          _verify(payload, firstSignature, second.publicKey),
          isFalse,
          reason: 'a rotated key still accepted the old signature',
        );
        expect(_verify(payload, firstSignature, first.publicKey), isTrue);
      },
    );

    test('a requireHardware failure leaves no key behind', () async {
      await expectLater(
        signer.generateKey(
          keyId: 'k',
          requireHardware: true,
          overwrite: false,
          protection: KeyProtection.ambient,
        ),
        throwsCode(SignerErrorCode.hardwareUnavailable),
      );
      expect(
        await signer.getKey('k'),
        isNull,
        reason: 'a rejected generate left a partially created key behind',
      );
    });
  });

  group('concurrency', () {
    test('two simultaneous signs on the same key both succeed', () async {
      final SecureKey key = await generate();
      final Uint8List payload = utf8.encode('concurrent payload');

      final List<Uint8List> results = await Future.wait(<Future<Uint8List>>[
        signer.sign(keyId: 'k', payload: payload),
        signer.sign(keyId: 'k', payload: payload),
        signer.sign(keyId: 'k', payload: payload),
      ]);

      for (final Uint8List signature in results) {
        expect(signature, hasLength(64));
        expect(_verify(payload, signature, key.publicKey), isTrue);
      }
      // The software signer uses RFC 6979 deterministic k, so identical inputs
      // must give identical outputs. A difference here would mean interleaved
      // state, not legitimate randomness.
      expect(results[1], results[0]);
      expect(results[2], results[0]);
    });

    test('concurrent signs on different keys do not cross-talk', () async {
      final SecureKey a = await signer.generateKey(
        keyId: 'a',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      final SecureKey b = await signer.generateKey(
        keyId: 'b',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(a.publicKey, isNot(b.publicKey));

      final Uint8List payload = utf8.encode('shared payload');
      final List<Uint8List> results = await Future.wait(<Future<Uint8List>>[
        signer.sign(keyId: 'a', payload: payload),
        signer.sign(keyId: 'b', payload: payload),
        signer.sign(keyId: 'a', payload: payload),
        signer.sign(keyId: 'b', payload: payload),
      ]);

      // Each signature must verify under ITS OWN key and not the other's.
      expect(_verify(payload, results[0], a.publicKey), isTrue);
      expect(_verify(payload, results[0], b.publicKey), isFalse);
      expect(_verify(payload, results[1], b.publicKey), isTrue);
      expect(_verify(payload, results[1], a.publicKey), isFalse);
      expect(results[2], results[0], reason: 'key a drifted between calls');
      expect(results[3], results[1], reason: 'key b drifted between calls');
    });

    test(
      'concurrent generate and sign on different keys are independent',
      () async {
        await signer.generateKey(
          keyId: 'stable',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        );
        final Uint8List payload = utf8.encode('p');

        final List<Object> results = await Future.wait(<Future<Object>>[
          signer.sign(keyId: 'stable', payload: payload),
          signer.generateKey(
            keyId: 'other',
            requireHardware: false,
            overwrite: false,
            protection: KeyProtection.ambient,
          ),
          signer.sign(keyId: 'stable', payload: payload),
        ]);

        expect(
          results[0],
          results[2],
          reason: 'generate disturbed another key',
        );
        expect((results[1] as SecureKey).keyId, 'other');
      },
    );

    test('a concurrent delete does not corrupt an in-flight sign', () async {
      await signer.generateKey(
        keyId: 'x',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      await signer.generateKey(
        keyId: 'y',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      final SecureKey y = (await signer.getKey('y'))!;
      final Uint8List payload = utf8.encode('p');

      final List<Object?> results = await Future.wait(<Future<Object?>>[
        signer.sign(keyId: 'y', payload: payload),
        signer.deleteKey('x'),
      ]);

      expect(_verify(payload, results[0]! as Uint8List, y.publicKey), isTrue);
      expect(await signer.getKey('x'), isNull);
      expect(await signer.getKey('y'), isNotNull);
    });
  });

  group('JWK encoding', () {
    test(
      'coordinates are exactly 32 bytes and 43 unpadded base64url chars',
      () async {
        // 32 bytes -> ceil(256/6) = 43 base64url characters, no padding.
        for (int i = 0; i < 25; i++) {
          final SecureKey key = await signer.generateKey(
            keyId: 'k$i',
            requireHardware: false,
            overwrite: false,
            protection: KeyProtection.ambient,
          );
          expect(key.publicKey.xBytes, hasLength(32), reason: 'key $i x');
          expect(key.publicKey.yBytes, hasLength(32), reason: 'key $i y');
          expect(key.publicKey.x, hasLength(43), reason: 'key $i x encoding');
          expect(key.publicKey.y, hasLength(43), reason: 'key $i y encoding');
        }
      },
    );

    test('encoding is base64url without padding', () async {
      final SecureKey key = await generate();
      for (final String coordinate in <String>[
        key.publicKey.x,
        key.publicKey.y,
      ]) {
        expect(coordinate, isNot(contains('=')), reason: 'padding leaked');
        expect(coordinate, isNot(contains('+')), reason: 'standard base64 "+"');
        expect(coordinate, isNot(contains('/')), reason: 'standard base64 "/"');
        expect(RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(coordinate), isTrue);
      }
    });

    test('a coordinate with a leading zero byte keeps its full length', () {
      // Same bug class as the DER work, on the PUBLIC key path: a coordinate
      // below 2^248 has a 0x00 top byte. Dropping it yields a 31-byte value
      // that the BFF rejects — or, worse, thumbprints differently, so the
      // device silently fails every signature check afterwards.
      final Uint8List x = Uint8List(32)
        ..setRange(1, 32, List<int>.filled(31, 0xab));
      final Uint8List y = Uint8List(32)
        ..setRange(0, 32, List<int>.filled(32, 0xcd));
      final EcPublicJwk jwk = EcPublicJwk.fromCoordinates(x: x, y: y);

      expect(jwk.xBytes, hasLength(32));
      expect(jwk.xBytes[0], 0x00, reason: 'the leading zero was dropped');
      expect(jwk.xBytes, x);
      expect(jwk.x, hasLength(43));
    });

    test('a coordinate that is all zeros still encodes to 32 bytes', () {
      final EcPublicJwk jwk = EcPublicJwk.fromCoordinates(
        x: Uint8List(32),
        y: Uint8List(32),
      );
      expect(jwk.xBytes, hasLength(32));
      expect(jwk.xBytes, everyElement(0));
      expect(jwk.x, hasLength(43));
    });

    test('a high-bit coordinate is unchanged', () {
      final Uint8List x = Uint8List.fromList(<int>[
        0xff,
        ...List<int>.filled(31, 0x01),
      ]);
      final EcPublicJwk jwk = EcPublicJwk.fromCoordinates(
        x: x,
        y: Uint8List(32),
      );
      expect(jwk.xBytes, x);
      expect(jwk.xBytes[0], 0xff);
    });

    test('toJson has exactly the four RFC 7638 members, in canonical order', () {
      final EcPublicJwk jwk = EcPublicJwk.fromCoordinates(
        x: Uint8List(32),
        y: Uint8List(32),
      );
      // RFC 7638 thumbprints the members in lexicographic order; emitting them
      // that way lets the encoded string be hashed directly.
      expect(jwk.toJson().keys.toList(), <String>['crv', 'kty', 'x', 'y']);
      expect(jwk.toJson()['crv'], 'P-256');
      expect(jwk.toJson()['kty'], 'EC');
    });

    test('the JWK round-trips through fromJson', () async {
      final SecureKey key = await generate();
      final EcPublicJwk parsed = EcPublicJwk.fromJson(key.publicKey.toJson());
      expect(parsed, key.publicKey);
      expect(parsed.xBytes, key.publicKey.xBytes);
    });

    test(
      'the reported JWK is the one signatures actually verify under',
      () async {
        // Ties the encoding tests to reality: an x/y that encode "correctly" but
        // describe the wrong point would pass every check above.
        final SecureKey key = await generate();
        final Uint8List payload = utf8.encode('payload');
        final Uint8List signature = await signer.sign(
          keyId: 'k',
          payload: payload,
        );
        expect(_verify(payload, signature, key.publicKey), isTrue);
      },
    );
  });
}

/// Verify a raw P1363 signature over [payload] under [jwk].
bool _verify(Uint8List payload, Uint8List signature, EcPublicJwk jwk) {
  final pc.ECDSASigner verifier = pc.ECDSASigner(
    pc.SHA256Digest(),
    pc.HMac(pc.SHA256Digest(), 64),
  )..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(publicKeyFromJwk(jwk)));
  return verifier.verifySignature(
    payload,
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
