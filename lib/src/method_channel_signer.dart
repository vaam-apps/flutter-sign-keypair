import 'package:flutter/services.dart';

import 'models.dart';
import 'platform_interface.dart';

/// The methods this plugin's channel understands.
///
/// A method channel can only carry primitives, so the name crosses the wire as
/// a string — but [wireName] is the only place one is written, and the Kotlin
/// and Swift sides each have exactly one matching enum. Adding a method is a
/// compile error in all three rather than a typo that fails at runtime on one
/// platform only.
enum SignerMethod {
  capabilities('capabilities'),
  generateKey('generateKey'),
  getKey('getKey'),
  sign('sign'),
  deleteKey('deleteKey');

  const SignerMethod(this.wireName);

  /// The method name sent over the channel.
  final String wireName;
}

/// Talks to the native AndroidKeyStore / Secure Enclave implementations.
class MethodChannelSignKeypair extends SignKeypairPlatform {
  /// The single channel shared by every native implementation in this package.
  static const MethodChannel channel = MethodChannel(
    'com.vaam/flutter_sign_keypair',
  );

  @override
  Future<SignerCapabilities> capabilities() async {
    final Map<Object?, Object?>? result = await _invoke<Map<Object?, Object?>>(
      SignerMethod.capabilities,
    );
    if (result == null) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'Native capabilities() returned null',
      );
    }
    return SignerCapabilities(
      platform: result['platform'] as String? ?? 'unknown',
      // The one wire -> enum boundary for backing tags on the Dart side.
      bestAvailableBacking: KeyBacking.fromWire(result['backing'] as String?),
    );
  }

  @override
  Future<SecureKey> generateKey({
    required String keyId,
    required bool requireHardware,
    required bool overwrite,
    required KeyProtection protection,
  }) async {
    final Map<Object?, Object?>? result = await _invoke<Map<Object?, Object?>>(
      SignerMethod.generateKey,
      <String, Object?>{
        'keyId': keyId,
        'requireHardware': requireHardware,
        'overwrite': overwrite,
        'protection': protection.wireName,
      },
    );
    if (result == null) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'Native generateKey() returned null',
      );
    }
    return _decodeKey(keyId, result);
  }

  @override
  Future<SecureKey?> getKey(String keyId) async {
    final Map<Object?, Object?>? result = await _invoke<Map<Object?, Object?>>(
      SignerMethod.getKey,
      <String, Object?>{'keyId': keyId},
    );
    if (result == null) return null;
    return _decodeKey(keyId, result);
  }

  @override
  Future<Uint8List> sign({
    required String keyId,
    required Uint8List payload,
    String? reason,
  }) async {
    final Uint8List? signature = await _invoke<Uint8List>(
      SignerMethod.sign,
      <String, Object?>{
        'keyId': keyId,
        'payload': payload,
        // Omitted rather than sent as null when absent, so the native side can
        // tell "no reason given" from "empty reason" and fall back to its own
        // default string only in the first case.
        'reason': ?reason,
      },
    );
    if (signature == null) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'Native sign() returned null',
      );
    }
    // The native side already converts DER -> P1363; assert the contract so a
    // regression there surfaces here rather than as an opaque signature
    // rejection at the backend.
    if (signature.length != 64) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'Native sign() returned ${signature.length} bytes, expected 64 '
        '(IEEE P1363 r‖s)',
      );
    }
    return signature;
  }

  @override
  Future<void> deleteKey(String keyId) async {
    await _invoke<void>(SignerMethod.deleteKey, <String, Object?>{
      'keyId': keyId,
    });
  }

  Future<T?> _invoke<T>(
    SignerMethod method, [
    Map<String, Object?>? arguments,
  ]) async {
    try {
      return await channel.invokeMethod<T>(method.wireName, arguments);
    } on MissingPluginException catch (e) {
      throw SecureSignerException(
        SignerErrorCode.unsupportedPlatform,
        'No native secure signer is registered for this platform',
        details: e.message,
      );
    } on PlatformException catch (e) {
      // The one wire -> enum boundary for error codes. An unrecognised code
      // becomes SignerErrorCode.unknown with the raw string preserved, rather
      // than being guessed at.
      throw SecureSignerException.fromWire(
        e.code,
        e.message ?? 'Native secure signer failed',
        details: e.details,
      );
    }
  }

  static SecureKey _decodeKey(String keyId, Map<Object?, Object?> result) {
    final Object? x = result['x'];
    final Object? y = result['y'];
    if (x is! String || y is! String) {
      throw SecureSignerException(
        SignerErrorCode.keystoreFailure,
        'Native key payload is missing base64url "x"/"y" coordinates',
      );
    }
    return SecureKey(
      keyId: result['keyId'] as String? ?? keyId,
      publicKey: EcPublicJwk(x: x, y: y),
      backing: KeyBacking.fromWire(result['backing'] as String?),
    );
  }
}
