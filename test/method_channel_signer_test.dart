import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// Pins the Dart <-> native wire contract.
///
/// The Kotlin and Swift sides both read these argument names and emit these
/// backing tags; if either drifts, the failure on a real device is an opaque
/// `MissingPluginException` or a silently software-backed key. Cheaper to catch
/// here.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final List<MethodCall> calls = <MethodCall>[];
  late MethodChannelSignKeypair platform;
  Object? Function(MethodCall) respond = (MethodCall call) => null;

  setUp(() {
    calls.clear();
    platform = MethodChannelSignKeypair();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(MethodChannelSignKeypair.channel, (
          MethodCall call,
        ) async {
          calls.add(call);
          return respond(call);
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(MethodChannelSignKeypair.channel, null);
  });

  final Map<Object?, Object?> nativeKey = <Object?, Object?>{
    'keyId': 'k',
    'x': 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    'y': 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    'backing': 'strongbox',
  };

  group('generateKey', () {
    test('sends the arguments the native side reads', () async {
      respond = (_) => nativeKey;
      await platform.generateKey(
        keyId: 'k',
        requireHardware: true,
        overwrite: true,
        protection: KeyProtection.ambient,
      );

      expect(calls.single.method, 'generateKey');
      expect(calls.single.arguments, <String, Object?>{
        'keyId': 'k',
        'requireHardware': true,
        'overwrite': true,
        'protection': 'ambient',
      });
    });

    test('decodes the backing tag', () async {
      respond = (_) => nativeKey;
      final SecureKey key = await platform.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      expect(key.backing, KeyBacking.strongBox);
      expect(key.isHardwareBacked, isTrue);
    });

    test(
      'an unrecognised backing tag degrades to software, not hardware',
      () async {
        respond = (_) => <Object?, Object?>{...nativeKey, 'backing': 'quantum'};
        final SecureKey key = await platform.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        );
        expect(
          key.isHardwareBacked,
          isFalse,
          reason:
              'an unknown backing must never be reported as hardware-backed',
        );
      },
    );

    test('each native tag maps to the right enum', () async {
      const Map<String, KeyBacking> expected = <String, KeyBacking>{
        'strongbox': KeyBacking.strongBox,
        'secure_enclave': KeyBacking.secureEnclave,
        'tee': KeyBacking.trustedExecutionEnvironment,
        'keychain': KeyBacking.keychain,
        'software': KeyBacking.software,
      };
      for (final MapEntry<String, KeyBacking> entry in expected.entries) {
        respond = (_) => <Object?, Object?>{...nativeKey, 'backing': entry.key};
        final SecureKey key = await platform.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        );
        expect(key.backing, entry.value, reason: 'tag "${entry.key}"');
      }
    });
  });

  group('sign', () {
    test('passes the payload through and returns the signature', () async {
      final Uint8List signature = Uint8List.fromList(
        List<int>.generate(64, (int i) => i),
      );
      respond = (_) => signature;

      final Uint8List result = await platform.sign(
        keyId: 'k',
        payload: Uint8List.fromList(<int>[1, 2, 3]),
      );

      expect(result, signature);
      expect(calls.single.method, 'sign');
      expect(
        (calls.single.arguments as Map<Object?, Object?>)['payload'],
        Uint8List.fromList(<int>[1, 2, 3]),
      );
    });

    test('rejects a native signature that is not 64 bytes', () async {
      // A DER signature leaking through instead of P1363 would land here — the
      // BFF would reject it, so fail at the boundary with a readable message.
      respond = (_) => Uint8List(70);
      expect(
        () => platform.sign(keyId: 'k', payload: Uint8List(4)),
        throwsA(
          isA<SecureSignerException>()
              .having(
                (SecureSignerException e) => e.code,
                'code',
                SignerErrorCode.keystoreFailure,
              )
              .having(
                (SecureSignerException e) => e.message,
                'message',
                contains('70 bytes'),
              ),
        ),
      );
    });
  });

  group('getKey', () {
    test('returns null when the native side has no key', () async {
      respond = (_) => null;
      expect(await platform.getKey('k'), isNull);
    });
  });

  group('error mapping', () {
    test('a PlatformException keeps its code', () async {
      respond = (_) => throw PlatformException(
        code: 'key_not_found',
        message: 'No key stored under "k"',
      );
      expect(
        () => platform.sign(keyId: 'k', payload: Uint8List(4)),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.keyNotFound,
          ),
        ),
      );
    });

    test('a missing plugin becomes unsupported_platform', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(MethodChannelSignKeypair.channel, null);
      expect(
        () => platform.capabilities(),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.unsupportedPlatform,
          ),
        ),
      );
    });
  });

  group('capabilities', () {
    test('decodes platform and backing', () async {
      respond = (_) => <Object?, Object?>{
        'platform': 'android',
        'backing': 'tee',
      };
      final SignerCapabilities capabilities = await platform.capabilities();
      expect(capabilities.platform, 'android');
      expect(
        capabilities.bestAvailableBacking,
        KeyBacking.trustedExecutionEnvironment,
      );
      expect(capabilities.isHardwareBacked, isTrue);
    });
  });

  group('error mapping — every code the native sides can emit', () {
    // Kotlin's SignerErrorCode and Swift's SignerErrorCode both emit exactly
    // these four. Each must arrive on the Dart side as its typed member, not as
    // a generic failure.
    const Map<String, SignerErrorCode> nativeCodes = <String, SignerErrorCode>{
      'key_not_found': SignerErrorCode.keyNotFound,
      'key_already_exists': SignerErrorCode.keyAlreadyExists,
      'hardware_unavailable': SignerErrorCode.hardwareUnavailable,
      'keystore_failure': SignerErrorCode.keystoreFailure,
    };

    nativeCodes.forEach((String wire, SignerErrorCode expected) {
      test('"$wire" maps to ${expected.name}', () async {
        respond = (_) => throw PlatformException(code: wire, message: 'boom');
        await expectLater(
          platform.sign(keyId: 'k', payload: Uint8List(4)),
          throwsA(
            isA<SecureSignerException>()
                .having((SecureSignerException e) => e.code, 'code', expected)
                .having((SecureSignerException e) => e.rawCode, 'rawCode', wire)
                .having(
                  (SecureSignerException e) => e.message,
                  'message',
                  'boom',
                ),
          ),
        );
      });
    });

    test(
      'a code neither side knows becomes unknown, raw code preserved',
      () async {
        respond = (_) => throw PlatformException(
          code: 'some_future_native_code',
          message: 'from a newer plugin build',
        );
        await expectLater(
          platform.capabilities(),
          throwsA(
            isA<SecureSignerException>()
                .having(
                  (SecureSignerException e) => e.code,
                  'code',
                  SignerErrorCode.unknown,
                )
                .having(
                  (SecureSignerException e) => e.rawCode,
                  'rawCode',
                  'some_future_native_code',
                ),
          ),
        );
      },
    );

    test('the platform details payload survives', () async {
      respond = (_) => throw PlatformException(
        code: 'keystore_failure',
        message: 'boom',
        details: <String, Object?>{'errno': 42},
      );
      await expectLater(
        platform.deleteKey('k'),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.details,
            'details',
            <String, Object?>{'errno': 42},
          ),
        ),
      );
    });

    test(
      'an empty native message still produces a readable exception',
      () async {
        respond = (_) => throw PlatformException(code: 'key_not_found');
        await expectLater(
          platform.getKey('k'),
          throwsA(
            isA<SecureSignerException>().having(
              (SecureSignerException e) => e.message,
              'message',
              isNotEmpty,
            ),
          ),
        );
      },
    );

    test('every method surfaces native errors, not just sign()', () async {
      respond = (_) =>
          throw PlatformException(code: 'keystore_failure', message: 'x');
      final List<Future<Object?>> calls = <Future<Object?>>[
        platform.capabilities(),
        platform.generateKey(
          keyId: 'k',
          requireHardware: false,
          overwrite: false,
          protection: KeyProtection.ambient,
        ),
        platform.getKey('k'),
        platform.sign(keyId: 'k', payload: Uint8List(4)),
        platform.deleteKey('k'),
      ];
      for (final Future<Object?> call in calls) {
        await expectLater(call, throwsA(isA<SecureSignerException>()));
      }
    });
  });

  group('method names on the wire', () {
    test('each API call sends its enum wire name', () async {
      respond = (MethodCall call) =>
          call.method == 'sign' ? Uint8List(64) : nativeKey;

      await platform.capabilities();
      await platform.generateKey(
        keyId: 'k',
        requireHardware: false,
        overwrite: false,
        protection: KeyProtection.ambient,
      );
      await platform.getKey('k');
      await platform.sign(keyId: 'k', payload: Uint8List(4));
      await platform.deleteKey('k');

      expect(
        calls.map((MethodCall c) => c.method).toList(),
        SignerMethod.values.map((SignerMethod m) => m.wireName).toList(),
        reason: 'the channel method names drifted from SignerMethod',
      );
    });
  });

  group('channel concurrency', () {
    test('concurrent calls do not cross-talk between key ids', () async {
      // Method channels serialise, but "should" is not "does". Each response is
      // derived from its own request, so a mixed-up pairing is detectable.
      respond = (MethodCall call) {
        final String keyId =
            (call.arguments as Map<Object?, Object?>)['keyId']! as String;
        return Uint8List(64)..fillRange(0, 64, keyId.codeUnitAt(0));
      };

      final List<Uint8List> results = await Future.wait(<Future<Uint8List>>[
        platform.sign(keyId: 'a', payload: Uint8List(1)),
        platform.sign(keyId: 'b', payload: Uint8List(1)),
        platform.sign(keyId: 'c', payload: Uint8List(1)),
        platform.sign(keyId: 'a', payload: Uint8List(1)),
      ]);

      expect(results[0].every((int b) => b == 'a'.codeUnitAt(0)), isTrue);
      expect(results[1].every((int b) => b == 'b'.codeUnitAt(0)), isTrue);
      expect(results[2].every((int b) => b == 'c'.codeUnitAt(0)), isTrue);
      expect(results[3], results[0]);
      expect(calls, hasLength(4));
    });

    test('one failing call does not poison its neighbours', () async {
      respond = (MethodCall call) {
        final String keyId =
            (call.arguments as Map<Object?, Object?>)['keyId']! as String;
        if (keyId == 'bad') {
          throw PlatformException(code: 'key_not_found', message: 'nope');
        }
        return Uint8List(64);
      };

      final List<Object?> results = await Future.wait(<Future<Object?>>[
        platform.sign(keyId: 'good', payload: Uint8List(1)),
        platform
            .sign(keyId: 'bad', payload: Uint8List(1))
            .then<Object?>((Uint8List v) => v)
            .catchError((Object e) => e),
        platform.sign(keyId: 'good2', payload: Uint8List(1)),
      ]);

      expect(results[0], isA<Uint8List>());
      expect(
        results[1],
        isA<SecureSignerException>().having(
          (SecureSignerException e) => e.code,
          'code',
          SignerErrorCode.keyNotFound,
        ),
      );
      expect(results[2], isA<Uint8List>());
    });
  });
}
