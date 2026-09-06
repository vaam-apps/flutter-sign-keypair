import Foundation

/// The wire vocabulary shared with the Dart side, as enums.
///
/// A method channel can only carry primitives, so strings do cross the wire.
/// What this file buys is that each string is written in exactly **one** place
/// and parsed in exactly one place; every comparison in the rest of the module
/// is on an enum. Swift `switch` over an enum is exhaustive by default, so
/// adding a member here is a compile error at each switch rather than a silent
/// fallthrough.
///
/// `CaseIterable` is for the wire-contract tests: it lets them assert that
/// EVERY member round-trips, so a member added without a vector fails the
/// suite instead of shipping unmapped.
///
/// These must stay in step with `lib/src/models.dart` (KeyBacking,
/// SignerErrorCode) and `lib/src/method_channel_signer.dart` (SignerMethod).
/// `EcdsaSignatureCodecTests`'s wire-contract cases pin the exact strings so a
/// rename on one side cannot drift past review.
enum SignerMethod: String, CaseIterable {
  case capabilities
  case generateKey
  case getKey
  case sign
  case deleteKey
}

/// Where a private key lives, strongest first.
///
/// `software` is the floor and the safe default: under-reporting strength is
/// harmless, over-reporting is a false security claim.
enum KeyBacking: String, CaseIterable {
  case secureEnclave = "secure_enclave"
  case keychain
  case software

  /// True when the key cannot be read out of the device.
  ///
  /// `keychain` is deliberately false: a keychain item is OS-protected but is
  /// not held by a secure element, and the scalar can in principle be exported.
  var isHardwareBacked: Bool {
    switch self {
    case .secureEnclave: return true
    case .keychain, .software: return false
    }
  }
}

/// What the secure element demands before it signs (ADR 0024).
///
/// Unlike `KeyBacking` this has **no safe default**: answering `ambient` for an
/// unrecognised tag would hand a caller who asked for tier-3 protection a key
/// that signs silently, and answering `userPresent` would make the Dio
/// interceptor prompt on every background poll. The parse therefore returns nil
/// and the call fails.
enum KeyProtection: String, CaseIterable {
  case ambient
  case userPresent = "user_present"

  /// Whether the Security framework will demand authentication before signing.
  var requiresUserPresence: Bool {
    switch self {
    case .ambient: return false
    case .userPresent: return true
    }
  }
}

/// Why an operation failed. Becomes `PlatformException.code` on the Dart side.
enum SignerErrorCode: String, CaseIterable {
  case keyNotFound = "key_not_found"
  case keyAlreadyExists = "key_already_exists"
  case hardwareUnavailable = "hardware_unavailable"
  case keystoreFailure = "keystore_failure"
  case userAuthenticationRequired = "user_authentication_required"
  case userAuthenticationCancelled = "user_authentication_cancelled"
  case keyInvalidated = "key_invalidated"
}

/// A typed failure carrying an [SignerErrorCode] rather than a bare string.
struct SignerError: Error {
  let code: SignerErrorCode
  let message: String

  init(_ code: SignerErrorCode, _ message: String) {
    self.code = code
    self.message = message
  }
}
