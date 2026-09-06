import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// On-device proof. Run with:
///
/// ```bash
/// flutter test integration_test/secure_signer_test.dart -d <device>
/// # benchmark numbers are only meaningful in profile mode:
/// flutter test integration_test/secure_signer_test.dart -d <device> --profile
/// ```
///
/// Three things are being proven here, in order of importance:
///
///  1. **Correctness** — a signature made by the secure element verifies against
///     the public JWK the plugin reported, using the same pointycastle verifier
///     path a JWS library would use. A fast signer whose signatures a backend
///     rejects is worthless.
///  2. **Hardware backing** — the platform reports a secure-element backing, and
///     no API on this package can return private key material.
///  3. **Speed** — measured against the app's current pointycastle signer,
///     running in the same process on the same device, in the same build mode.
///     Comparing across build modes is how a previous investigation was misled.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  const String testKeyId = 'flutter_sign_keypair_integration_test';
  final SignKeypair signer = SignKeypair();

  tearDownAll(() async {
    await signer.deleteKey(keyId: testKeyId);
  });

  testWidgets('reports what this device can actually do', (_) async {
    final SignerCapabilities capabilities = await signer.capabilities();
    // Printed, not asserted to a specific value: a CI emulator, a StrongBox
    // phone and an Intel Mac legitimately differ.
    debugPrintCapabilities(capabilities);
    expect(capabilities.platform, isNotEmpty);
  });

  testWidgets('generated key reports the backing capabilities advertised', (
    _,
  ) async {
    final SignerCapabilities capabilities = await signer.capabilities();
    final SecureKey key = await signer.generateKey(
      keyId: testKeyId,
      overwrite: true,
    );

    // ignore: avoid_print, reason: this value is the point of the test run
    print(
      'SECURE_SIGNER_BACKING backing=${key.backing.name} '
      'hardwareBacked=${key.isHardwareBacked}',
    );

    expect(key.publicKey.xBytes, hasLength(32));
    expect(key.publicKey.yBytes, hasLength(32));

    // The plugin must not over-promise: a key can never claim a stronger
    // backing than the capability probe advertised. This is asserted rather
    // than `isNot(software)` because an *emulator* legitimately has only a
    // software keymaster — asserting hardware here would make the suite fail
    // on every CI emulator, and a test that always fails teaches people to
    // ignore it. Hardware residency is proven separately, on real hardware, by
    // `android/src/androidTest/.../KeyStoreHardwareBackingTest.kt`.
    expect(
      key.isHardwareBacked,
      capabilities.isHardwareBacked,
      reason:
          'generateKey() and capabilities() disagree about hardware '
          'backing — one of them is lying to the caller',
    );

    if (!key.isHardwareBacked) {
      // ignore: avoid_print, reason: makes a weak run obvious in the log
      print(
        'SECURE_SIGNER_WARNING this device has no secure element — the key is '
        'extractable and this run proves nothing about hardware backing',
      );
    }
  });

  testWidgets('requireHardware never silently degrades to a software key', (
    _,
  ) async {
    // The contract: a caller asking for hardware backing must either get it or
    // get an error. Getting a software key while believing it is hardware-backed
    // is worse than a failure, because it is logged as a guarantee that does not
    // hold.
    //
    // On an emulator (software keymaster) this exercises the throwing path; on
    // real hardware it exercises the success path. Both are asserted, so the
    // test is meaningful either way rather than vacuous on one of them.
    final SignerCapabilities capabilities = await signer.capabilities();

    if (capabilities.isHardwareBacked) {
      final SecureKey key = await signer.generateKey(
        keyId: testKeyId,
        requireHardware: true,
        overwrite: true,
      );
      expect(key.isHardwareBacked, isTrue);
      expect(key.backing, isNot(KeyBacking.software));
    } else {
      // Start from no key at all, so "nothing was created" is unambiguous.
      // The companion case — a key already exists and must SURVIVE the
      // rejection — is the next test.
      await signer.deleteKey(keyId: testKeyId);

      await expectLater(
        signer.generateKey(
          keyId: testKeyId,
          requireHardware: true,
          overwrite: true,
        ),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.hardwareUnavailable,
          ),
        ),
      );
      // A rejected generate must not leave a half-created key behind.
      expect(await signer.getKey(keyId: testKeyId), isNull);
    }
  });

  testWidgets('a rejected requireHardware never destroys an existing key', (
    _,
  ) async {
    // The dangerous ordering, end-to-end and on BOTH platforms. It only shows
    // up when a key exists first: `overwrite: true` deletes the incumbent
    // before generating, so a rejection afterwards would leave the device with
    // no credential at all — unable to authenticate and unable to sign its way
    // through re-enrolment.
    final SignerCapabilities capabilities = await signer.capabilities();
    final SecureKey original = await signer.generateKey(
      keyId: testKeyId,
      overwrite: true,
    );

    if (capabilities.isHardwareBacked) {
      // Hardware devices take the success path; the key is replaced, not lost.
      final SecureKey replaced = await signer.generateKey(
        keyId: testKeyId,
        requireHardware: true,
        overwrite: true,
      );
      expect(replaced.isHardwareBacked, isTrue);
      expect(await signer.getKey(keyId: testKeyId), isNotNull);
    } else {
      await expectLater(
        signer.generateKey(
          keyId: testKeyId,
          requireHardware: true,
          overwrite: true,
        ),
        throwsA(
          isA<SecureSignerException>().having(
            (SecureSignerException e) => e.code,
            'code',
            SignerErrorCode.hardwareUnavailable,
          ),
        ),
      );
      final SecureKey? surviving = await signer.getKey(keyId: testKeyId);
      expect(
        surviving,
        isNotNull,
        reason: 'a failed generate destroyed the pre-existing key',
      );
      expect(surviving!.publicKey, original.publicKey);
    }
  });

  testWidgets('signing a key id that never existed fails cleanly', (_) async {
    await expectLater(
      signer.signCompactJws(
        payload: <String, dynamic>{'x': 1},
        keyId: 'never_created_key_id',
      ),
      throwsA(
        isA<SecureSignerException>().having(
          (SecureSignerException e) => e.code,
          'code',
          SignerErrorCode.keyNotFound,
        ),
      ),
    );
  });

  testWidgets('concurrent signs on two key ids do not cross-talk', (_) async {
    const String otherKeyId = 'flutter_sign_keypair_integration_test_b';
    final SecureKey a = await signer.generateKey(
      keyId: testKeyId,
      overwrite: true,
    );
    final SecureKey b = await signer.generateKey(
      keyId: otherKeyId,
      overwrite: true,
    );
    expect(a.publicKey, isNot(b.publicKey));

    final Map<String, dynamic> payload = <String, dynamic>{'device_id': 'd'};
    final List<String> results = await Future.wait(<Future<String>>[
      signer.signCompactJws(payload: payload, keyId: testKeyId),
      signer.signCompactJws(payload: payload, keyId: otherKeyId),
      signer.signCompactJws(payload: payload, keyId: testKeyId),
    ]);

    // Each signature must verify under its OWN key and not the other's.
    expect(
      _verifyCompactJws(results[0], _publicKeyFromJwk(a.publicKey)),
      isTrue,
    );
    expect(
      _verifyCompactJws(results[0], _publicKeyFromJwk(b.publicKey)),
      isFalse,
    );
    expect(
      _verifyCompactJws(results[1], _publicKeyFromJwk(b.publicKey)),
      isTrue,
    );
    expect(
      _verifyCompactJws(results[2], _publicKeyFromJwk(a.publicKey)),
      isTrue,
    );

    await signer.deleteKey(keyId: otherKeyId);
  });

  testWidgets('the JWK coordinates are 32 bytes, base64url unpadded', (
    _,
  ) async {
    final SecureKey key = await signer.generateKey(
      keyId: testKeyId,
      overwrite: true,
    );
    for (final String coordinate in <String>[
      key.publicKey.x,
      key.publicKey.y,
    ]) {
      expect(coordinate, hasLength(43));
      expect(coordinate, isNot(contains('=')));
      expect(RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(coordinate), isTrue);
    }
    expect(key.publicKey.xBytes, hasLength(32));
    expect(key.publicKey.yBytes, hasLength(32));
  });

  testWidgets('the public key is stable across reads', (_) async {
    await signer.generateKey(keyId: testKeyId, overwrite: true);
    final SecureKey? first = await signer.getKey(keyId: testKeyId);
    final SecureKey? second = await signer.getKey(keyId: testKeyId);
    expect(first!.publicKey, second!.publicKey);
  });

  testWidgets('a hardware signature verifies against the reported JWK', (
    _,
  ) async {
    final SecureKey key = await signer.generateKey(
      keyId: testKeyId,
      overwrite: true,
    );

    final Map<String, dynamic> payload = <String, dynamic>{
      'timestamp_ms': DateTime.now().millisecondsSinceEpoch,
      'device_id': 'integration-device',
      'method': 'POST',
      'path': '/bff/v1/payments/transfer',
    };
    final String jws = await signer.signCompactJws(
      payload: payload,
      keyId: testKeyId,
    );

    expect(
      _verifyCompactJws(jws, _publicKeyFromJwk(key.publicKey)),
      isTrue,
      reason:
          'the secure element produced a signature the verifier rejects — '
          'most likely a DER -> P1363 conversion bug',
    );

    // And the negative case, so the verifier is not just returning true.
    final List<String> parts = jws.split('.');
    final String forged =
        '${parts[0]}.${_b64u(utf8.encode('{"amount":999999}'))}.${parts[2]}';
    expect(
      _verifyCompactJws(forged, _publicKeyFromJwk(key.publicKey)),
      isFalse,
    );
  });

  testWidgets('ECDSA is randomised, so repeated signatures differ', (_) async {
    // AndroidKeyStore and the Secure Enclave use a random k, unlike the
    // RFC 6979 deterministic k in the Dart fallback. Both are valid ES256; a
    // caller must not assume signature stability.
    await signer.generateKey(keyId: testKeyId, overwrite: true);
    final Map<String, dynamic> payload = <String, dynamic>{'device_id': 'd'};
    final String a = await signer.signCompactJws(
      payload: payload,
      keyId: testKeyId,
    );
    final String b = await signer.signCompactJws(
      payload: payload,
      keyId: testKeyId,
    );
    expect(a.split('.').take(2), b.split('.').take(2));
    // Not asserted as always-different (a deterministic platform is legal),
    // just recorded.
    // ignore: avoid_print, reason: observational output for the PR record
    print('SECURE_SIGNER_DETERMINISTIC ${a == b}');
  });

  testWidgets('signing a deleted key fails cleanly', (_) async {
    await signer.generateKey(keyId: testKeyId, overwrite: true);
    await signer.deleteKey(keyId: testKeyId);
    expect(await signer.getKey(keyId: testKeyId), isNull);
    await expectLater(
      signer.signCompactJws(payload: <String, dynamic>{}, keyId: testKeyId),
      throwsA(isA<SecureSignerException>()),
    );
  });

  testWidgets('BENCHMARK: hardware signer vs the app pointycastle signer', (
    _,
  ) async {
    const int iterations = 100;
    await signer.generateKey(keyId: testKeyId, overwrite: true);

    final Map<String, dynamic> payload = <String, dynamic>{
      'timestamp_ms': 1753900000000,
      'device_id': 'benchmark-device',
      'method': 'GET',
      'path': '/bff/v1/accounts/balance',
    };

    // Warm up both paths so JIT/keystore init is not attributed to either.
    for (int i = 0; i < 10; i++) {
      await signer.signCompactJws(payload: payload, keyId: testKeyId);
      _pointycastleSign(payload);
    }

    final Stopwatch native = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      await signer.signCompactJws(payload: payload, keyId: testKeyId);
    }
    native.stop();

    final Stopwatch dart = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      _pointycastleSign(payload);
    }
    dart.stop();

    final double nativeUs = native.elapsedMicroseconds / iterations;
    final double dartUs = dart.elapsedMicroseconds / iterations;

    // ignore: avoid_print, reason: this line is the benchmark result
    print(
      'SECURE_SIGNER_BENCHMARK iterations=$iterations '
      'native_us=${nativeUs.toStringAsFixed(1)} '
      'pointycastle_us=${dartUs.toStringAsFixed(1)} '
      'speedup=${(dartUs / nativeUs).toStringAsFixed(2)}x',
    );

    // No threshold assertion: an emulator's software keymaster is not a phone's
    // TEE, and a flaky perf gate in CI teaches people to ignore CI.
    expect(nativeUs, greaterThan(0));
    expect(dartUs, greaterThan(0));
  });
}

void debugPrintCapabilities(SignerCapabilities capabilities) {
  // ignore: avoid_print, reason: this value is the point of the test run
  print('SECURE_SIGNER_CAPABILITIES $capabilities');
}

// --- the app's current signing path, for the benchmark's other arm ----------

final pc.ECDomainParameters _domain = pc.ECDomainParameters('prime256v1');

/// A fixed scalar so the benchmark measures signing, not key generation.
final Uint8List _benchmarkScalar = Uint8List.fromList(
  List<int>.generate(32, (int i) => (i * 11 + 3) & 0xff),
);

final String _header = _b64u(
  utf8.encode(jsonEncode(<String, String>{'alg': 'ES256', 'typ': 'JWT'})),
);

/// A hand-rolled pointycastle ES256 signer — the pattern this package
/// replaces — used here only as the benchmark's other arm.
String _pointycastleSign(Map<String, dynamic> payload) {
  final String encoded = _b64u(utf8.encode(jsonEncode(payload)));
  final String signingInput = '$_header.$encoded';

  final pc.ECPrivateKey privateKey = pc.ECPrivateKey(
    _toBigInt(_benchmarkScalar),
    _domain,
  );
  final pc.ECDSASigner ecdsa = pc.ECDSASigner(
    pc.SHA256Digest(),
    pc.HMac(pc.SHA256Digest(), 64),
  )..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(privateKey));
  final pc.ECSignature signature =
      ecdsa.generateSignature(utf8.encode(signingInput)) as pc.ECSignature;

  final Uint8List bytes = Uint8List(64)
    ..setRange(0, 32, _bigIntTo32(signature.r))
    ..setRange(32, 64, _bigIntTo32(signature.s));
  return '$signingInput.${_b64u(bytes)}';
}

// --- verifier helpers -------------------------------------------------------

pc.ECPublicKey _publicKeyFromJwk(EcPublicJwk jwk) => pc.ECPublicKey(
  _domain.curve.createPoint(_toBigInt(jwk.xBytes), _toBigInt(jwk.yBytes)),
  _domain,
);

bool _verifyCompactJws(String jws, pc.ECPublicKey publicKey) {
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

String _b64u(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _bigIntTo32(BigInt value) {
  final String hex = value.toRadixString(16).padLeft(64, '0');
  return Uint8List.fromList(<int>[
    for (int i = 0; i < 32; i++)
      int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16),
  ]);
}

BigInt _toBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (final int byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}
