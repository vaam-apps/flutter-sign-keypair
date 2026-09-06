import 'dart:convert';
import 'dart:typed_data';

/// Where the private key actually lives, in decreasing order of assurance.
///
/// This is reported by the platform, not assumed by the caller. Anything below
/// [KeyBacking.software] does not exist: `software` is the floor, and it is the
/// one value that means the raw private scalar is reachable from process memory.
enum KeyBacking {
  /// Android StrongBox — a discrete, tamper-resistant security chip.
  /// Requires `FEATURE_STRONGBOX_KEYSTORE` (API 28+).
  strongBox('strongbox'),

  /// Apple Secure Enclave — a separate coprocessor. P-256 only, which is
  /// exactly the curve this package signs with.
  secureEnclave('secure_enclave'),

  /// Android Trusted Execution Environment (TEE) — key material is held by
  /// secure-world firmware, outside the Android OS.
  trustedExecutionEnvironment('tee'),

  /// Apple Keychain with a hardware-protected item, but not the Secure Enclave
  /// itself (e.g. a Mac without a T2/Apple-silicon secure coprocessor).
  keychain('keychain'),

  /// Pure-Dart / in-process key. The private scalar exists in heap memory and
  /// is extractable. Used on web and on any platform with no native signer.
  software('software');

  const KeyBacking(this.wireName);

  /// The tag the native side puts on the method channel.
  ///
  /// A method channel can only carry primitives, so a string crosses the wire —
  /// but this is the **only** place that string is written, and
  /// [KeyBacking.fromWire] is the only place one is read. Every comparison
  /// elsewhere is on the enum. Adding a backing level is then a compile error
  /// here (the constructor demands a `wireName`) rather than a silent
  /// fallthrough somewhere downstream.
  final String wireName;

  /// Map a wire tag onto a backing level.
  ///
  /// An unrecognised tag becomes [KeyBacking.software]. That direction is
  /// deliberate and load-bearing: **under-reporting strength is safe,
  /// over-reporting is not.** A newer native build that learns a stronger
  /// backing this Dart side has never heard of must not be reported as
  /// hardware-backed on the strength of a string nobody validated.
  static KeyBacking fromWire(String? wire) {
    for (final KeyBacking backing in KeyBacking.values) {
      if (backing.wireName == wire) return backing;
    }
    return software;
  }

  /// True when the private key cannot be read out of the device.
  ///
  /// [KeyBacking.keychain] is deliberately excluded: a keychain item is
  /// protected by the OS, but it is not held by a secure element and the
  /// scalar can, in principle, be exported.
  ///
  /// Written as an exhaustive `switch` with **no** `default` on purpose. This
  /// is the one function in the package where getting a new backing level wrong
  /// is a false security claim, so adding a member above must fail to compile
  /// here until somebody decides which side of the line it falls on. A
  /// `default` would quietly answer for them.
  bool get isHardwareBacked => switch (this) {
    KeyBacking.strongBox ||
    KeyBacking.secureEnclave ||
    KeyBacking.trustedExecutionEnvironment => true,
    KeyBacking.keychain || KeyBacking.software => false,
  };
}

/// What the secure element demands before it will sign with a key.
///
/// This package splits one device credential into two keys because a single
/// key ends up serving two populations of request with opposite requirements:
/// a background interceptor or polling timer needs to sign silently, with no
/// prompt displayable at all, while a deliberate high-value action wants a
/// prompt and can afford one. The reason for the split is not that biometrics
/// are hard — it is that no single authentication policy correctly serves
/// both populations.
///
/// Both keys are generated in and never leave the secure element. They differ
/// only in whether the element demands a live human first.
enum KeyProtection {
  /// No user-presence binding. Signs the low- and medium-risk operations that
  /// happen silently, in the background, or on every request. Never prompts.
  ///
  /// Survives biometric re-enrolment, which is what lets a device authenticate
  /// its way through re-enrolling a destroyed [userPresent] key rather than
  /// falling back to a full out-of-band re-enrolment ceremony.
  ambient('ambient'),

  /// Bound to a live biometric or the device credential. Signs the operations
  /// that justify interrupting the user — high-value transfers, security or
  /// account changes. Prompts on every use.
  ///
  /// In-process malware can still *use* an [ambient] key, because a secure
  /// element signs whatever it is asked to; it cannot use this one. That is
  /// the property the split buys: the backend can require the stronger key
  /// for a sensitive operation and reject anything signed with the weaker one.
  userPresent('user_present');

  const KeyProtection(this.wireName);

  /// The tag that crosses the method channel.
  final String wireName;

  /// Whether the secure element will demand authentication before signing.
  ///
  /// Exhaustive `switch` with no `default`, for the same reason as
  /// [KeyBacking.isHardwareBacked]: a new member must be classified by a person.
  bool get requiresUserPresence => switch (this) {
    KeyProtection.ambient => false,
    KeyProtection.userPresent => true,
  };

  /// Parse a wire tag, or `null` when it is not one this build knows.
  ///
  /// **No default, unlike [KeyBacking.fromWire]** — and that asymmetry is the
  /// point. `KeyBacking` can degrade to `software` because under-reporting
  /// strength is harmless. Here *both* directions are harmful: guessing
  /// [ambient] hands a caller who asked for prompted protection a key that
  /// signs silently, and guessing [userPresent] hands a background
  /// interceptor a key that prompts on every poll. An unrecognised tag is a
  /// bug in the version pairing, so it fails loudly instead of being answered
  /// for.
  static KeyProtection? fromWire(String? wire) {
    for (final KeyProtection protection in KeyProtection.values) {
      if (protection.wireName == wire) return protection;
    }
    return null;
  }
}

/// An EC P-256 public key in JWK form (RFC 7517 / RFC 7518 §6.2).
///
/// `x` and `y` are base64url-encoded without padding, as the spec requires.
class EcPublicJwk {
  const EcPublicJwk({required this.x, required this.y});

  /// Build a JWK from the raw 32-byte affine coordinates.
  factory EcPublicJwk.fromCoordinates({
    required Uint8List x,
    required Uint8List y,
  }) {
    if (x.length != 32 || y.length != 32) {
      throw ArgumentError(
        'P-256 coordinates must be exactly 32 bytes '
        '(got x=${x.length}, y=${y.length})',
      );
    }
    return EcPublicJwk(x: _b64u(x), y: _b64u(y));
  }

  /// Parse a JWK map, rejecting anything that is not an EC P-256 public key.
  factory EcPublicJwk.fromJson(Map<String, dynamic> json) {
    final Object? kty = json['kty'];
    final Object? crv = json['crv'];
    if (kty != 'EC' || crv != 'P-256') {
      throw FormatException('Expected an EC P-256 JWK, got kty=$kty crv=$crv');
    }
    final Object? x = json['x'];
    final Object? y = json['y'];
    if (x is! String || y is! String) {
      throw const FormatException('JWK is missing string "x"/"y" coordinates');
    }
    return EcPublicJwk(x: x, y: y);
  }

  /// base64url, unpadded, X coordinate.
  final String x;

  /// base64url, unpadded, Y coordinate.
  final String y;

  /// Raw 32-byte X coordinate.
  Uint8List get xBytes => _b64uDecode(x);

  /// Raw 32-byte Y coordinate.
  Uint8List get yBytes => _b64uDecode(y);

  /// The JWK as a map, in the shape a device-registration endpoint typically
  /// accepts. Key order matches RFC 7638's canonical form for
  /// `kty`/`crv`/`x`/`y` so the encoded string can be thumbprinted directly.
  Map<String, dynamic> toJson() => <String, dynamic>{
    'crv': 'P-256',
    'kty': 'EC',
    'x': x,
    'y': y,
  };

  @override
  String toString() => 'EcPublicJwk(x: $x, y: $y)';

  @override
  bool operator ==(Object other) =>
      other is EcPublicJwk && other.x == x && other.y == y;

  @override
  int get hashCode => Object.hash(x, y);

  static String _b64u(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static Uint8List _b64uDecode(String value) =>
      base64Url.decode(value.padRight((value.length + 3) & ~3, '='));
}

/// A handle to a key held by the platform.
///
/// Deliberately does **not** carry private key material — on the hardware paths
/// there is none to carry, and the fallback keeps its scalar inside the signer.
class SecureKey {
  const SecureKey({
    required this.keyId,
    required this.publicKey,
    required this.backing,
  });

  /// Stable identifier used to address this key on later `sign`/`delete` calls.
  final String keyId;

  /// The public half, ready to send to a backend for device registration.
  final EcPublicJwk publicKey;

  /// Where the private half actually lives, as reported by the platform.
  final KeyBacking backing;

  /// Convenience mirror of [KeyBacking.isHardwareBacked].
  ///
  /// Callers that care (audit logs, risk scoring, "this device is less trusted"
  /// UI) should read this rather than assuming. A `false` here is not an error
  /// — it is the fallback working as designed — but it is a fact worth logging.
  bool get isHardwareBacked => backing.isHardwareBacked;

  @override
  String toString() =>
      'SecureKey(keyId: $keyId, backing: ${backing.name}, '
      'hardwareBacked: $isHardwareBacked)';
}

/// Both of a device's two-key-model keys, as produced by one enrolment.
///
/// Carried as a pair rather than two loose [SecureKey]s because an enrolment
/// ceremony typically registers both thumbprints together, so a revocation
/// can retire both — which only works if the server was told about both in
/// the first place.
class DeviceKeyPair {
  const DeviceKeyPair({required this.ambient, required this.userPresent});

  /// The silent, no-prompt key. [KeyProtection.ambient].
  final SecureKey ambient;

  /// The prompting key. [KeyProtection.userPresent].
  final SecureKey userPresent;

  /// True only when *both* halves are held by a secure element.
  ///
  /// Deliberately an `&&`: the pair is as trustworthy as its weaker key, and a
  /// caller logging "hardware-backed" on the strength of one of them would be
  /// recording something false about the other.
  bool get isHardwareBacked =>
      ambient.isHardwareBacked && userPresent.isHardwareBacked;

  @override
  String toString() =>
      'DeviceKeyPair(ambient: $ambient, userPresent: $userPresent)';
}

/// What the current platform can actually do, probed at runtime.
class SignerCapabilities {
  const SignerCapabilities({
    required this.platform,
    required this.bestAvailableBacking,
  });

  /// Human-readable platform tag, e.g. `android`, `ios`, `dart-software`.
  final String platform;

  /// The strongest [KeyBacking] a `generateKey` call would produce right now.
  final KeyBacking bestAvailableBacking;

  /// Whether a key generated now would be non-extractable.
  bool get isHardwareBacked => bestAvailableBacking.isHardwareBacked;

  @override
  String toString() =>
      'SignerCapabilities(platform: $platform, '
      'bestAvailableBacking: ${bestAvailableBacking.name})';
}

/// Why a signer operation failed.
///
/// Same wire↔enum discipline as [KeyBacking]: the string exists only on the
/// method channel, and callers `switch` on the enum.
enum SignerErrorCode {
  /// No key exists under the requested id.
  keyNotFound('key_not_found'),

  /// A key already exists under that id and `overwrite` was not set.
  keyAlreadyExists('key_already_exists'),

  /// Hardware backing was required but the device cannot provide it.
  hardwareUnavailable('hardware_unavailable'),

  /// The platform keystore refused the operation.
  keystoreFailure('keystore_failure'),

  /// A [KeyProtection.userPresent] key was requested or used, but the device
  /// has no biometric enrolled and no device credential (screen lock) set.
  ///
  /// Distinct from [hardwareUnavailable]: the secure element is present and
  /// willing, there is simply nothing to authenticate the user *against*. It is
  /// also recoverable by the user in Settings, which [hardwareUnavailable] is
  /// not — so the two must not share a code, or the UI cannot tell the customer
  /// anything useful.
  userAuthenticationRequired('user_authentication_required'),

  /// The user dismissed the authentication prompt, or it timed out.
  ///
  /// Not a failure of the key or the device — the expected outcome when someone
  /// changes their mind at a confirmation screen. Callers should treat it as a
  /// cancelled action, never as a reason to re-enrol or log out.
  userAuthenticationCancelled('user_authentication_cancelled'),

  /// The key was permanently destroyed by a change to the device's biometric
  /// enrolment or screen lock.
  ///
  /// This is the platform's biometric-invalidation flag firing as designed,
  /// and the whole reason it is carried by the user-present key alone: the
  /// [KeyProtection.ambient] key is untouched, so the device can still
  /// authenticate itself while it re-enrols this one. Recovery is to generate
  /// a fresh user-present key and register its thumbprint — **not** a full
  /// re-enrolment ceremony, and not a logout.
  keyInvalidated('key_invalidated'),

  /// This platform has no native implementation of the requested operation.
  unsupportedPlatform('unsupported_platform'),

  /// A code this Dart side does not know — e.g. a newer native build, or a
  /// `PlatformException` raised by something other than this plugin.
  ///
  /// Kept as a distinct member rather than folded into [keystoreFailure] so a
  /// caller can tell "the keystore refused" from "nobody here understands this",
  /// and so [SecureSignerException.rawCode] is the thing to read in a bug report.
  unknown('unknown');

  const SignerErrorCode(this.wireName);

  /// The `PlatformException.code` this maps to.
  final String wireName;

  /// Map a wire code onto an enum member, defaulting to [unknown].
  static SignerErrorCode fromWire(String? wire) {
    for (final SignerErrorCode code in SignerErrorCode.values) {
      if (code.wireName == wire) return code;
    }
    return unknown;
  }
}

/// Raised when the platform cannot satisfy a request.
class SecureSignerException implements Exception {
  SecureSignerException(
    this.code,
    this.message, {
    this.details,
    String? rawCode,
  }) : rawCode = rawCode ?? code.wireName;

  /// Build from whatever the platform channel produced.
  factory SecureSignerException.fromWire(
    String? wire,
    String message, {
    Object? details,
  }) => SecureSignerException(
    SignerErrorCode.fromWire(wire),
    message,
    details: details,
    rawCode: wire ?? SignerErrorCode.unknown.wireName,
  );

  /// Machine-readable reason. Switch on this.
  final SignerErrorCode code;

  /// The code exactly as the platform sent it.
  ///
  /// Equal to `code.wireName` for everything this package understands, and the
  /// raw unrecognised string when [code] is [SignerErrorCode.unknown] — so an
  /// unfamiliar failure is still diagnosable instead of being flattened away.
  final String rawCode;

  /// Human-readable explanation, safe to log — never contains key material.
  final String message;

  /// Optional platform-specific payload.
  final Object? details;

  @override
  String toString() =>
      'SecureSignerException(${code.name}'
      '${code == SignerErrorCode.unknown ? ' "$rawCode"' : ''}): $message';
}
