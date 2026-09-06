import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

import 'support/reference_jws_signer.dart';

void main() {
  late SoftwareSecureSigner signer;

  setUp(() {
    signer = SoftwareSecureSigner(store: InMemorySoftwareKeyStore());
  });

  group('the fallback is honest about what it is', () {
    test('reports software backing, never hardware', () async {
      final SignerCapabilities capabilities = await signer.capabilities();
      expect(capabilities.platform, 'dart-software');
      expect(capabilities.bestAvailableBacking, KeyBacking.software);
      expect(capabilities.isHardwareBacked, isFalse);
    });

    test('generated keys are flagged as extractable software keys', () async {
      final SecureKey key = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(key.backing, KeyBacking.software);
      expect(key.isHardwareBacked, isFalse);
    });

    test(
      'requireHardware fails loudly rather than degrading silently',
      () async {
        expect(
          () => signer.generateKey(
            keyId: 'k',
            requireHardware: true,
            overwrite: false,
            protection: KeyProtection.ambient,
          ),
          throwsA(
            isA<SecureSignerException>().having(
              (SecureSignerException e) => e.code,
              'code',
              SignerErrorCode.hardwareUnavailable,
            ),
          ),
        );
      },
    );
  });

  group('key lifecycle', () {
    test('generate then read back the same public key', () async {
      final SecureKey created = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      final SecureKey? loaded = await signer.getKey('k');
      expect(loaded, isNotNull);
      expect(loaded!.publicKey, created.publicKey);
    });

    test('getKey returns null for an unknown id', () async {
      expect(await signer.getKey('nope'), isNull);
    });

    test('generating over an existing key requires overwrite', () async {
      await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(
        () => signer.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        ),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.keyAlreadyExists,
          ),
        ),
      );
    });

    test('overwrite replaces the key material', () async {
      final SecureKey first = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      final SecureKey second = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: true,
        protection: KeyProtection.ambient,
      );
      expect(second.publicKey, isNot(first.publicKey));
    });

    test('deleteKey removes it, and signing then fails', () async {
      await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      await signer.deleteKey('k');

      expect(await signer.getKey('k'), isNull);
      expect(
        () => signer.sign(keyId: 'k', payload: Uint8List(4)),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.keyNotFound,
          ),
        ),
      );
    });

    test('deleting a missing key is a no-op', () async {
      await expectLater(signer.deleteKey('missing'), completes);
    });

    test('keys survive a fresh signer over the same store', () async {
      final InMemorySoftwareKeyStore store = InMemorySoftwareKeyStore();
      final SecureKey created = await SoftwareSecureSigner(store: store)
          .generateKey(
            keyId: 'k',
            requireHardware: false,
            overwrite: false,
            protection: KeyProtection.ambient,
          );
      final SecureKey? reloaded = await SoftwareSecureSigner(
        store: store,
      ).getKey('k');
      expect(reloaded!.publicKey, created.publicKey);
    });
  });

  group('importKey (migration path for already-enrolled devices)', () {
    test('derives the same public key the app would have registered', () async {
      final Uint8List scalar = Uint8List.fromList(
        List<int>.generate(32, (int i) => (i + 1) & 0xff),
      );
      final SecureKey key = await signer.importKey(
        keyId: 'legacy',
        privateScalar: scalar,
      );
      final Map<String, String> expected = ReferenceJwsSigner.publicJwk(scalar);
      expect(key.publicKey.x, expected['x']);
      expect(key.publicKey.y, expected['y']);
    });

    test('an imported key is never claimed to be hardware-backed', () async {
      final SecureKey key = await signer.importKey(
        keyId: 'legacy',
        privateScalar: Uint8List.fromList(List<int>.filled(32, 9)),
      );
      expect(key.isHardwareBacked, isFalse);
    });

    test('rejects a scalar of the wrong length', () async {
      expect(
        () => signer.importKey(keyId: 'k', privateScalar: Uint8List(31)),
        throwsArgumentError,
      );
    });

    test('rejects a zero scalar', () async {
      expect(
        () => signer.importKey(keyId: 'k', privateScalar: Uint8List(32)),
        throwsArgumentError,
      );
    });
  });

  group('EcPublicJwk', () {
    test('round-trips coordinates through base64url', () {
      final Uint8List x = Uint8List.fromList(
        List<int>.generate(32, (int i) => i),
      );
      final Uint8List y = Uint8List.fromList(
        List<int>.generate(32, (int i) => 255 - i),
      );
      final EcPublicJwk jwk = EcPublicJwk.fromCoordinates(x: x, y: y);

      expect(jwk.xBytes, x);
      expect(jwk.yBytes, y);
      expect(jwk.toJson(), <String, dynamic>{
        'crv': 'P-256',
        'kty': 'EC',
        'x': jwk.x,
        'y': jwk.y,
      });
    });

    test('rejects coordinates that are not 32 bytes', () {
      expect(
        () => EcPublicJwk.fromCoordinates(x: Uint8List(31), y: Uint8List(32)),
        throwsArgumentError,
      );
    });

    test('rejects a JWK that is not EC P-256', () {
      expect(
        () => EcPublicJwk.fromJson(<String, dynamic>{
          'kty': 'RSA',
          'crv': 'P-256',
          'x': 'a',
          'y': 'b',
        }),
        throwsFormatException,
      );
    });
  });

  group('KeyBacking.isHardwareBacked', () {
    test('only secure-element backings count', () {
      expect(KeyBacking.strongBox.isHardwareBacked, isTrue);
      expect(KeyBacking.secureEnclave.isHardwareBacked, isTrue);
      expect(KeyBacking.trustedExecutionEnvironment.isHardwareBacked, isTrue);
      // A keychain item is OS-protected but not held by a secure element.
      expect(KeyBacking.keychain.isHardwareBacked, isFalse);
      expect(KeyBacking.software.isHardwareBacked, isFalse);
    });
  });
}
