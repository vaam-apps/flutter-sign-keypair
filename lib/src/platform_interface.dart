import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'models.dart';

/// The contract every backend — native or software — implements.
///
/// This is the federated-plugin seam: an out-of-tree package can register its
/// own backend by assigning [SignKeypairPlatform.instance], without the
/// app-facing API changing. The default is resolved in
/// `flutter_sign_keypair.dart` (method channel on Android/iOS/macOS, the
/// pure-Dart software signer everywhere else).
abstract class SignKeypairPlatform extends PlatformInterface {
  SignKeypairPlatform() : super(token: _token);

  static final Object _token = Object();

  static SignKeypairPlatform? _instance;

  /// The active backend.
  static SignKeypairPlatform get instance {
    final SignKeypairPlatform? current = _instance;
    if (current == null) {
      throw StateError(
        'SignKeypairPlatform.instance was read before it was set. '
        'Use the SignKeypair facade, which installs a default.',
      );
    }
    return current;
  }

  static set instance(SignKeypairPlatform value) {
    PlatformInterface.verify(value, _token);
    _instance = value;
  }

  /// True once a backend has been installed.
  static bool get hasInstance => _instance != null;

  /// Probe what this platform can actually do, right now, on this device.
  Future<SignerCapabilities> capabilities();

  /// Create a P-256 keypair under [keyId].
  ///
  /// When [requireHardware] is true the call must throw
  /// [SecureSignerException.hardwareUnavailable] rather than quietly returning
  /// a software key.
  ///
  /// [protection] decides whether the secure element demands a live human
  /// before signing. An implementation that cannot enforce
  /// [KeyProtection.userPresent] must **refuse** rather than fall back to
  /// [KeyProtection.ambient] — a key that silently signs when the caller asked
  /// for a prompt is the exact failure the two-key split exists to prevent.
  Future<SecureKey> generateKey({
    required String keyId,
    required bool requireHardware,
    required bool overwrite,
    required KeyProtection protection,
  });

  /// Fetch the handle for an existing key, or `null` when there is none.
  Future<SecureKey?> getKey(String keyId);

  /// Sign [payload] with the key at [keyId].
  ///
  /// [payload] is the raw JWS signing input (`base64url(header).base64url(body)`
  /// as UTF-8 bytes) — the implementation applies SHA-256 itself. The result is
  /// a 64-byte IEEE P1363 `r‖s` signature, which is what JWS ES256 requires.
  ///
  /// [reason] is the localized sentence shown in the authentication prompt when
  /// the key is [KeyProtection.userPresent]. It is ignored for ambient keys,
  /// which never prompt. The platform's own default prompt copy is not
  /// localized to the caller's app, so a user-present call that omits this
  /// shows whatever generic string the implementation falls back to — pass
  /// [reason] to show the caller's own copy instead.
  Future<Uint8List> sign({
    required String keyId,
    required Uint8List payload,
    String? reason,
  });

  /// Remove the key at [keyId]. Removing a key that does not exist is a no-op.
  Future<void> deleteKey(String keyId);
}
