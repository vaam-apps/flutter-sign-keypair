import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// ADR 0024's two-key split, from the Dart side.
///
/// The native halves — the Secure Enclave access control and the AndroidKeyStore
/// spec — cannot be exercised here; they need a real secure element and live in
/// `darwin_tests/` and `android/src/androidTest/`. What *is* testable off-device
/// is everything that decides which policy those halves are asked for, and every
/// place a wrong answer would be silent.
void main() {
  group('KeyProtection wire mapping', () {
    const Map<String, KeyProtection> vectors = <String, KeyProtection>{
      'ambient': KeyProtection.ambient,
      'user_present': KeyProtection.userPresent,
    };

    vectors.forEach((String wire, KeyProtection expected) {
      test('"$wire" <-> ${expected.name}', () {
        expect(KeyProtection.fromWire(wire), expected);
        expect(expected.wireName, wire);
      });
    });

    test('the vector table covers every enum value', () {
      expect(
        vectors.values.toSet(),
        KeyProtection.values.toSet(),
        reason:
            'a KeyProtection member was added without a wire vector — add it '
            'here AND in Wire.kt / Wire.swift and their tests',
      );
    });

    test('every enum value round-trips', () {
      for (final KeyProtection protection in KeyProtection.values) {
        expect(KeyProtection.fromWire(protection.wireName), protection);
      }
    });

    test('wire names are unique', () {
      final List<String> names = KeyProtection.values
          .map((KeyProtection p) => p.wireName)
          .toList();
      expect(names.toSet(), hasLength(names.length));
    });

    // The asymmetry with KeyBacking, asserted rather than described. Both
    // guesses are harmful here — `ambient` would hand a tier-3 caller a key
    // that signs silently, `userPresent` would make the request interceptor
    // prompt on every background poll — so the parse must refuse.
    group('an unrecognised tag resolves to null, never to a member', () {
      for (final String? tag in <String?>[
        null,
        '',
        'AMBIENT', // wrong case
        'userPresent', // camelCase instead of snake_case
        'user-present', // hyphen instead of underscore
        'user_present ', // trailing space
        'presence',
      ]) {
        test('"$tag" -> null', () {
          expect(KeyProtection.fromWire(tag), isNull);
        });
      }
    });

    test('requiresUserPresence classifies every member', () {
      expect(KeyProtection.ambient.requiresUserPresence, isFalse);
      expect(KeyProtection.userPresent.requiresUserPresence, isTrue);
    });
  });

  group('the software fallback refuses to fake user presence', () {
    late SoftwareSecureSigner signer;

    setUp(() => signer = SoftwareSecureSigner());

    test('generateKey(userPresent) throws rather than degrading', () async {
      await expectLater(
        signer.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.userPresent,
        ),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.hardwareUnavailable,
          ),
        ),
      );
    });

    test('and leaves no key behind under that id', () async {
      await expectLater(
        signer.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.userPresent,
        ),
        throwsA(isA<SecureSignerException>()),
      );
      // A refusal that still wrote a key would be worse than no refusal: the
      // caller would catch the error, and a later getKey would hand back a
      // software key sitting under the tier-3 alias.
      expect(await signer.getKey('k'), isNull);
    });

    test('an ambient key is still produced normally', () async {
      final SecureKey key = await signer.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(key.backing, KeyBacking.software);
    });
  });

  group('the two default key ids are distinct', () {
    // One alias cannot hold both policies: the platform bakes the access
    // control into the key at creation, so a shared id would mean rewriting —
    // and destroying — one key every time the other was needed.
    test('ambient and user-present do not collide', () {
      expect(
        SignKeypair.defaultKeyId,
        isNot(SignKeypair.defaultUserPresentKeyId),
      );
    });
  });

  group('generateDeviceKeys', () {
    test('returns both keys when the platform can make both', () async {
      final _RecordingPlatform platform = _RecordingPlatform();
      final SignKeypair signer = SignKeypair(platform: platform);

      final DeviceKeyPair pair = await signer.generateDeviceKeys();

      expect(pair.ambient.keyId, SignKeypair.defaultKeyId);
      expect(pair.userPresent.keyId, SignKeypair.defaultUserPresentKeyId);
      expect(platform.requested, <KeyProtection>[
        KeyProtection.ambient,
        KeyProtection.userPresent,
      ]);
    });

    test(
      'reports the pair as hardware-backed only when both halves are',
      () async {
        final _RecordingPlatform platform = _RecordingPlatform(
          backingFor: (KeyProtection p) => p == KeyProtection.ambient
              ? KeyBacking.strongBox
              : KeyBacking.software,
        );
        final SignKeypair signer = SignKeypair(platform: platform);

        final DeviceKeyPair pair = await signer.generateDeviceKeys();

        expect(pair.ambient.isHardwareBacked, isTrue);
        expect(
          pair.isHardwareBacked,
          isFalse,
          reason: 'the pair is only as trustworthy as its weaker key',
        );
      },
    );

    // The hazard ADR 0024 names: a device holding an ambient key the server has
    // never seen looks enrolled to itself and unknown to the BFF, so every
    // request 401s and the client cannot tell that from a revocation.
    test(
      'rolls the ambient key back when the user-present key fails',
      () async {
        final _RecordingPlatform platform = _RecordingPlatform(
          failOn: KeyProtection.userPresent,
        );
        final SignKeypair signer = SignKeypair(platform: platform);

        await expectLater(
          signer.generateDeviceKeys(),
          throwsA(
            isA<SecureSignerException>().having(
              (SecureSignerException e) => e.code,
              'code',
              SignerErrorCode.userAuthenticationRequired,
            ),
          ),
        );

        expect(
          await platform.getKey(SignKeypair.defaultKeyId),
          isNull,
          reason: 'the half-enrolled ambient key must not survive',
        );
      },
    );

    // The other half of that rule, and the more dangerous one to get wrong:
    // deleting a key the device was already authenticating with would turn a
    // failed tier-3 upgrade into a full lockout.
    test(
      'keeps a pre-existing ambient key when the user-present key fails',
      () async {
        final _RecordingPlatform platform = _RecordingPlatform(
          failOn: KeyProtection.userPresent,
        );
        await platform.generateKey(
          keyId: SignKeypair.defaultKeyId,
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        );
        final SignKeypair signer = SignKeypair(platform: platform);

        await expectLater(
          signer.generateDeviceKeys(overwrite: true),
          throwsA(isA<SecureSignerException>()),
        );

        expect(
          await platform.getKey(SignKeypair.defaultKeyId),
          isNotNull,
          reason: "the device's live identity must survive a failed upgrade",
        );
      },
    );

    test('surfaces the original cause, not the rollback', () async {
      final _RecordingPlatform platform = _RecordingPlatform(
        failOn: KeyProtection.userPresent,
        failDelete: true,
      );
      final SignKeypair signer = SignKeypair(platform: platform);

      await expectLater(
        signer.generateDeviceKeys(),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.userAuthenticationRequired,
          ),
        ),
      );
    });
  });
}

/// A platform that records what was asked of it and can be made to fail.
///
/// Hand-written rather than mocked: the assertions here are about *which
/// protection was requested for which alias*, which is exactly the detail a
/// generated stub tends to swallow.
class _RecordingPlatform extends SignKeypairPlatform {
  _RecordingPlatform({this.failOn, this.backingFor, this.failDelete = false});

  /// Refuse to create a key with this protection.
  final KeyProtection? failOn;

  /// What backing to report per protection; defaults to StrongBox for both.
  final KeyBacking Function(KeyProtection)? backingFor;

  /// Make deleteKey throw, to prove the rollback cannot mask the real cause.
  final bool failDelete;

  final List<KeyProtection> requested = <KeyProtection>[];
  final Map<String, SecureKey> _keys = <String, SecureKey>{};

  @override
  Future<SignerCapabilities> capabilities() async => const SignerCapabilities(
    platform: 'recording',
    bestAvailableBacking: KeyBacking.strongBox,
  );

  @override
  Future<SecureKey> generateKey({
    required String keyId,
    required bool requireHardware,
    required bool overwrite,
    required KeyProtection protection,
  }) async {
    requested.add(protection);
    if (protection == failOn) {
      throw SecureSignerException(
        SignerErrorCode.userAuthenticationRequired,
        'no screen lock on this fake device',
      );
    }
    final SecureKey key = SecureKey(
      keyId: keyId,
      publicKey: const EcPublicJwk(x: 'eA', y: 'eQ'),
      backing: backingFor?.call(protection) ?? KeyBacking.strongBox,
    );
    _keys[keyId] = key;
    return key;
  }

  @override
  Future<SecureKey?> getKey(String keyId) async => _keys[keyId];

  @override
  Future<Uint8List> sign({
    required String keyId,
    required Uint8List payload,
    String? reason,
  }) async => Uint8List(64);

  @override
  Future<void> deleteKey(String keyId) async {
    if (failDelete) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'delete refused',
      );
    }
    _keys.remove(keyId);
  }
}
