/// Hardware-backed ES256 signing for device-bound authentication.
///
/// See `README.md` for the why. The short version: a naive Dart-only signer
/// has to pull the raw private scalar into Dart heap memory on every
/// signature. This package moves both the key and the signing operation into
/// AndroidKeyStore / the Secure Enclave, so the scalar never exists outside
/// the secure element.
library;

import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'src/method_channel_signer.dart';
import 'src/models.dart';
import 'src/platform_interface.dart';
import 'src/software_signer.dart';

export 'src/asn1.dart' show EcdsaSignatureCodec;
export 'src/method_channel_signer.dart'
    show MethodChannelSignKeypair, SignerMethod;
export 'src/models.dart';
export 'src/platform_interface.dart';
export 'src/software_signer.dart'
    show InMemorySoftwareKeyStore, SoftwareKeyStore, SoftwareSecureSigner;

/// The app-facing API.
///
/// Shaped around one specific job — build a JSON payload, wrap it in a fixed
/// ES256 header, sign, emit compact JWS — rather than a general-purpose
/// crypto surface.
///
/// ```dart
/// final signer = SignKeypair();
/// final key = await signer.generateKey();          // one-time, at enrolment
/// await registerDevice(key.publicKey.toJson());    // send the JWK to your backend
/// final jws = await signer.signCompactJws(payload: {'nonce': n, ...});
/// ```
class SignKeypair {
  /// Uses the platform default backend unless one is passed in (tests).
  SignKeypair({SignKeypairPlatform? platform}) {
    if (platform != null) {
      SignKeypairPlatform.instance = platform;
    } else if (!SignKeypairPlatform.hasInstance) {
      SignKeypairPlatform.instance = _defaultPlatform();
    }
  }

  /// The key id used when a caller does not name one — the *ambient* key,
  /// meant to be signed with on every request, including from a background
  /// interceptor or polling timer.
  ///
  /// Stable on purpose: a device that already holds a key under this id keeps
  /// it and gains the user-present key alongside, rather than being forced
  /// through a re-enrolment ceremony to pick up a new alias. See
  /// `MIGRATION.md` for why an existing key can never move to hardware
  /// backing in place.
  static const String defaultKeyId = 'device';

  /// The key id for the *user-present* key — the one that prompts.
  ///
  /// A separate alias rather than a flag on the same one, because the platform
  /// stores the protection policy *with* the key: one alias cannot be both
  /// prompting and silent, and rewriting it to switch would destroy the key.
  static const String defaultUserPresentKeyId = 'device_user_present';

  /// The fixed JWS protected header for ES256, pre-encoded once.
  ///
  /// A JWS verifier expects exactly `{"alg":"ES256","typ":"JWT"}`; key order is
  /// part of the encoded bytes, so it is not reordered here.
  static final String _protectedHeader = base64UrlNoPadding(
    utf8.encode(jsonEncode(<String, String>{'alg': 'ES256', 'typ': 'JWT'})),
  );

  SignKeypairPlatform get _platform => SignKeypairPlatform.instance;

  /// What this device can actually do. Probe once at startup and log it.
  Future<SignerCapabilities> capabilities() => _platform.capabilities();

  /// True when a key generated right now would be non-extractable.
  Future<bool> isHardwareBackingAvailable() async =>
      (await capabilities()).isHardwareBacked;

  /// Create one device signing key.
  ///
  /// Set [requireHardware] to make a device without a secure element fail loudly
  /// instead of silently getting a software key. Set [overwrite] to replace an
  /// existing key — that invalidates whatever device registration your backend
  /// holds for it, so it must be followed by re-registering [SecureKey.publicKey].
  ///
  /// [protection] defaults to [KeyProtection.ambient], which is the key on the
  /// hot path. For the user-present key prefer [generateDeviceKeys], which
  /// enrols both as one unit — see its doc for why a bare pair of calls is the
  /// wrong shape at enrolment time.
  Future<SecureKey> generateKey({
    String keyId = defaultKeyId,
    bool requireHardware = false,
    bool overwrite = false,
    KeyProtection protection = KeyProtection.ambient,
  }) => _platform.generateKey(
    keyId: keyId,
    requireHardware: requireHardware,
    overwrite: overwrite,
    protection: protection,
  );

  /// Create both keys of the two-key model as a single unit, for enrolment.
  ///
  /// The hazard this closes: a device that registers one key and fails on the
  /// second must not end up half-enrolled. A device holding an ambient key
  /// the backend has never seen is worse than a device holding neither — it
  /// looks enrolled to itself and unknown to the server, so every request is
  /// rejected and the client cannot tell that from a revocation.
  ///
  /// So if the user-present key fails — no biometric enrolled, no screen lock,
  /// a keymaster that refuses the spec — the ambient key created moments earlier
  /// is deleted and the original error is rethrown. The caller gets a device in
  /// the state it started in.
  ///
  /// The rollback deliberately does **not** run when the ambient key already
  /// existed and [overwrite] was false: that key is the device's live identity
  /// and deleting it would turn a failed user-present-key upgrade into a full
  /// lockout.
  Future<DeviceKeyPair> generateDeviceKeys({
    String ambientKeyId = defaultKeyId,
    String userPresentKeyId = defaultUserPresentKeyId,
    bool requireHardware = false,
    bool overwrite = false,
  }) async {
    final bool ambientPreexisting = await hasKey(keyId: ambientKeyId);

    final SecureKey ambient = await generateKey(
      keyId: ambientKeyId,
      requireHardware: requireHardware,
      overwrite: overwrite,
    );

    try {
      final SecureKey userPresent = await generateKey(
        keyId: userPresentKeyId,
        requireHardware: requireHardware,
        overwrite: overwrite,
        protection: KeyProtection.userPresent,
      );
      return DeviceKeyPair(ambient: ambient, userPresent: userPresent);
    } catch (_) {
      // Best-effort: if the rollback itself fails there is nothing further to
      // try, and swallowing it here keeps the original cause — the reason the
      // user-present key could not be made — as the error the caller sees.
      if (!ambientPreexisting) {
        try {
          await deleteKey(keyId: ambientKeyId);
        } on SecureSignerException {
          // Deliberately ignored; see above.
        }
      }
      rethrow;
    }
  }

  /// The existing key handle, or `null` when the device is not enrolled.
  Future<SecureKey?> getKey({String keyId = defaultKeyId}) =>
      _platform.getKey(keyId);

  /// Whether a key exists under [keyId].
  Future<bool> hasKey({String keyId = defaultKeyId}) async =>
      await _platform.getKey(keyId) != null;

  /// The public key as a JWK map, ready to POST to device registration.
  Future<Map<String, dynamic>?> getPublicKeyJwk({
    String keyId = defaultKeyId,
  }) async => (await _platform.getKey(keyId))?.publicKey.toJson();

  /// Sign raw bytes, returning a 64-byte IEEE P1363 `r‖s` signature.
  ///
  /// Prefer [signCompactJws] — this is the escape hatch for callers that build
  /// their own signing input.
  Future<Uint8List> signRaw({
    required Uint8List signingInput,
    String keyId = defaultKeyId,
    String? reason,
  }) => _platform.sign(keyId: keyId, payload: signingInput, reason: reason);

  /// Sign [payload] and return a compact ES256 JWS: `header.payload.signature`.
  ///
  /// This is meant for a hot path — a request interceptor that signs every
  /// authenticated call — which is why [keyId] defaults to the ambient key
  /// that never prompts.
  ///
  /// For an operation that should demand a live human, pass
  /// [defaultUserPresentKeyId] and a localized [reason]; the platform shows it
  /// in the biometric prompt.
  Future<String> signCompactJws({
    required Map<String, dynamic> payload,
    String keyId = defaultKeyId,
    String? reason,
  }) async {
    final String encodedPayload = base64UrlNoPadding(
      utf8.encode(jsonEncode(payload)),
    );
    final String signingInput = '$_protectedHeader.$encodedPayload';
    final Uint8List signature = await _platform.sign(
      keyId: keyId,
      payload: utf8.encode(signingInput),
      reason: reason,
    );
    return '$signingInput.${base64UrlNoPadding(signature)}';
  }

  /// Delete the device key. The device must re-enrol afterwards.
  Future<void> deleteKey({String keyId = defaultKeyId}) =>
      _platform.deleteKey(keyId);

  /// base64url without padding, as RFC 7515 requires.
  static String base64UrlNoPadding(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  /// Pick the backend for the current target.
  ///
  /// Only Android, iOS and macOS have native implementations. Everything else —
  /// web, Windows, Linux — gets the pure-Dart signer, which reports
  /// [KeyBacking.software] so callers know the key is extractable.
  static SignKeypairPlatform _defaultPlatform() {
    if (kIsWeb) return SoftwareSecureSigner();
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
      case TargetPlatform.iOS:
      case TargetPlatform.macOS:
        return MethodChannelSignKeypair();
      case TargetPlatform.windows:
      case TargetPlatform.linux:
      case TargetPlatform.fuchsia:
        return SoftwareSecureSigner();
    }
  }
}
