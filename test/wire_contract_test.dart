import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// The wire contract, pinned.
///
/// Strings cross the method channel because that is all a channel can carry.
/// The mapping is duplicated once per language — Dart here, Kotlin in
/// `Wire.kt`, Swift in `Wire.swift` — and duplication is exactly what drifts.
/// These vectors are asserted verbatim in all three suites, so a rename on one
/// side fails a test on that side instead of failing a device at runtime.
///
/// If you change a string here you must change it in `Wire.kt` and `Wire.swift`
/// and in `WireContractTest.kt` and `WireContractTests.swift`. That is the
/// point: five deliberate edits, not one silent one.
void main() {
  group('KeyBacking wire mapping', () {
    // The canonical tags. Kotlin emits strongbox/tee/software; Swift emits
    // secure_enclave/keychain/software; Dart must understand all five.
    const Map<String, KeyBacking> vectors = <String, KeyBacking>{
      'strongbox': KeyBacking.strongBox,
      'secure_enclave': KeyBacking.secureEnclave,
      'tee': KeyBacking.trustedExecutionEnvironment,
      'keychain': KeyBacking.keychain,
      'software': KeyBacking.software,
    };

    vectors.forEach((String wire, KeyBacking expected) {
      test('"$wire" <-> ${expected.name}', () {
        expect(KeyBacking.fromWire(wire), expected);
        expect(expected.wireName, wire);
      });
    });

    test('every enum value round-trips — fails if a member is added blind', () {
      // Iterating `.values` is what makes this test survive a future edit: a new
      // member with a typo'd or duplicated wireName fails here rather than
      // silently mapping to `software` on a real device.
      for (final KeyBacking backing in KeyBacking.values) {
        expect(
          KeyBacking.fromWire(backing.wireName),
          backing,
          reason: '${backing.name} does not round-trip',
        );
      }
    });

    test('the vector table covers every enum value', () {
      expect(
        vectors.values.toSet(),
        KeyBacking.values.toSet(),
        reason:
            'a KeyBacking member was added without a wire vector — add it '
            'here AND in Wire.kt / Wire.swift and their tests',
      );
    });

    test('wire names are unique', () {
      final List<String> names = KeyBacking.values
          .map((KeyBacking b) => b.wireName)
          .toList();
      expect(names.toSet(), hasLength(names.length));
    });

    group('an unrecognised tag degrades to software, never upward', () {
      // This is the security-relevant direction. Under-reporting strength is
      // harmless; over-reporting is a false guarantee a caller would log.
      for (final String? tag in <String?>[
        null,
        '',
        'quantum',
        'STRONGBOX', // wrong case — must NOT match
        'strong_box', // plausible typo
        'secureEnclave', // camelCase instead of snake_case
        'tee ', // trailing space
        'Software',
      ]) {
        test('"$tag" -> software', () {
          final KeyBacking backing = KeyBacking.fromWire(tag);
          expect(backing, KeyBacking.software);
          expect(
            backing.isHardwareBacked,
            isFalse,
            reason: 'an unvalidated string must never yield a hardware claim',
          );
        });
      }
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

    test('every value has an explicit answer', () {
      // The getter is an exhaustive switch with no default, so this cannot
      // throw — but asserting it pins the intent if someone adds a default.
      for (final KeyBacking backing in KeyBacking.values) {
        expect(() => backing.isHardwareBacked, returnsNormally);
      }
    });
  });

  group('SignerErrorCode wire mapping', () {
    const Map<String, SignerErrorCode> vectors = <String, SignerErrorCode>{
      'key_not_found': SignerErrorCode.keyNotFound,
      'key_already_exists': SignerErrorCode.keyAlreadyExists,
      'hardware_unavailable': SignerErrorCode.hardwareUnavailable,
      'keystore_failure': SignerErrorCode.keystoreFailure,
      'user_authentication_required':
          SignerErrorCode.userAuthenticationRequired,
      'user_authentication_cancelled':
          SignerErrorCode.userAuthenticationCancelled,
      'key_invalidated': SignerErrorCode.keyInvalidated,
      'unsupported_platform': SignerErrorCode.unsupportedPlatform,
      'unknown': SignerErrorCode.unknown,
    };

    vectors.forEach((String wire, SignerErrorCode expected) {
      test('"$wire" <-> ${expected.name}', () {
        expect(SignerErrorCode.fromWire(wire), expected);
        expect(expected.wireName, wire);
      });
    });

    test('every enum value round-trips', () {
      for (final SignerErrorCode code in SignerErrorCode.values) {
        expect(SignerErrorCode.fromWire(code.wireName), code);
      }
    });

    test('the vector table covers every enum value', () {
      expect(vectors.values.toSet(), SignerErrorCode.values.toSet());
    });

    test('wire names are unique', () {
      final List<String> names = SignerErrorCode.values
          .map((SignerErrorCode c) => c.wireName)
          .toList();
      expect(names.toSet(), hasLength(names.length));
    });

    for (final String? tag in <String?>[null, '', 'nope', 'KEY_NOT_FOUND']) {
      test('an unrecognised code "$tag" becomes unknown', () {
        expect(SignerErrorCode.fromWire(tag), SignerErrorCode.unknown);
      });
    }

    test('the native sides only emit codes this side understands', () {
      // Kotlin's ErrorCode and Swift's ErrorCode both have exactly these
      // seven. `unsupported_platform` and `unknown` are Dart-side only:
      // the first comes from MissingPluginException, the second is the
      // catch-all. Pinned so adding a native code without a Dart member is
      // caught here.
      //
      // `key_invalidated` is emitted by Android only — iOS destroys a
      // `.biometryCurrentSet` key outright, so the same event surfaces there as
      // `key_not_found` on the user-present alias while the ambient one still
      // resolves. Listed anyway: a code either side can emit must have a Dart
      // member, and one-platform codes are the ones most likely to be missed.
      const Set<String> nativeCodes = <String>{
        'key_not_found',
        'key_already_exists',
        'hardware_unavailable',
        'keystore_failure',
        'user_authentication_required',
        'user_authentication_cancelled',
        'key_invalidated',
      };
      for (final String code in nativeCodes) {
        expect(
          SignerErrorCode.fromWire(code),
          isNot(SignerErrorCode.unknown),
          reason: 'native emits "$code" but Dart has no member for it',
        );
      }
      expect(
        SignerErrorCode.values
            .where((SignerErrorCode c) => c != SignerErrorCode.unknown)
            .where(
              (SignerErrorCode c) => c != SignerErrorCode.unsupportedPlatform,
            )
            .map((SignerErrorCode c) => c.wireName)
            .toSet(),
        nativeCodes,
      );
    });
  });

  group('SignerMethod wire mapping', () {
    const Map<String, SignerMethod> vectors = <String, SignerMethod>{
      'capabilities': SignerMethod.capabilities,
      'generateKey': SignerMethod.generateKey,
      'getKey': SignerMethod.getKey,
      'sign': SignerMethod.sign,
      'deleteKey': SignerMethod.deleteKey,
    };

    vectors.forEach((String wire, SignerMethod expected) {
      test('"$wire" <-> ${expected.name}', () {
        expect(expected.wireName, wire);
      });
    });

    test('the vector table covers every enum value', () {
      expect(vectors.values.toSet(), SignerMethod.values.toSet());
    });

    test('wire names are unique', () {
      final List<String> names = SignerMethod.values
          .map((SignerMethod m) => m.wireName)
          .toList();
      expect(names.toSet(), hasLength(names.length));
    });

    test('method names are camelCase, unlike the snake_case tags', () {
      // Not cosmetic: the Kotlin and Swift sides parse these verbatim, and
      // `generate_key` vs `generateKey` is a runtime-only failure on one
      // platform. Pinned so the convention cannot drift halfway.
      for (final SignerMethod method in SignerMethod.values) {
        expect(
          method.wireName,
          isNot(contains('_')),
          reason: '${method.name} broke the camelCase convention',
        );
      }
    });
  });

  group('SecureSignerException', () {
    test('keeps the raw code when it recognises it', () {
      final SecureSignerException e = SecureSignerException.fromWire(
        'key_not_found',
        'nope',
      );
      expect(e.code, SignerErrorCode.keyNotFound);
      expect(e.rawCode, 'key_not_found');
    });

    test('preserves an unrecognised raw code for diagnosis', () {
      final SecureSignerException e = SecureSignerException.fromWire(
        'some_future_native_code',
        'nope',
      );
      expect(e.code, SignerErrorCode.unknown);
      expect(
        e.rawCode,
        'some_future_native_code',
        reason: 'flattening the raw code away makes the failure undiagnosable',
      );
      expect(e.toString(), contains('some_future_native_code'));
    });

    test('a null wire code becomes unknown without throwing', () {
      final SecureSignerException e = SecureSignerException.fromWire(null, 'x');
      expect(e.code, SignerErrorCode.unknown);
      expect(e.rawCode, 'unknown');
    });

    test('toString names the enum, not the raw string, for known codes', () {
      expect(
        SecureSignerException(
          SignerErrorCode.hardwareUnavailable,
          'no secure element',
        ).toString(),
        'SecureSignerException(hardwareUnavailable): no secure element',
      );
    });
  });
}
