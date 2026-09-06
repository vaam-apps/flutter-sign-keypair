#if os(iOS)
import Flutter
import UIKit
#elseif os(macOS)
import FlutterMacOS
import AppKit
#endif

import Foundation
import Security
import LocalAuthentication

/// Secure Enclave / Keychain-backed ES256 signer for iOS and macOS.
///
/// This one file serves both platforms — `macos/.../FlutterSignKeypairPlugin.swift`
/// is a symlink to it — because the Security framework calls are identical and
/// only the Flutter module import and the registrar's messenger accessor differ.
///
/// The Secure Enclave supports exactly one curve: NIST P-256, which is also
/// the curve JWS ES256 requires, so the enclave path needs no protocol change
/// on top of it. When the enclave is unavailable (simulator, or
/// an Intel Mac without a T2), the key is created as an ordinary keychain key
/// and reported as `keychain` — which this package does *not* count as
/// hardware-backed.
public class FlutterSignKeypairPlugin: NSObject, FlutterPlugin {

  private static let channelName = "com.vaam/flutter_sign_keypair"
  private static let tagPrefix = "com.vaam.flutter_sign_keypair."
  private static let coordinateLength = 32


  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(iOS)
      let messenger = registrar.messenger()
    #else
      let messenger = registrar.messenger
    #endif
    let channel = FlutterMethodChannel(name: channelName, binaryMessenger: messenger)
    registrar.addMethodCallDelegate(FlutterSignKeypairPlugin(), channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    // The one wire -> enum boundary for method names. An unknown name is
    // rejected here, once; everything below switches on the enum.
    guard let method = SignerMethod(rawValue: call.method) else {
      return result(FlutterMethodNotImplemented)
    }

    do {
      // Swift requires this switch to be exhaustive, so adding a Method case
      // without handling it is a compile error rather than a runtime surprise
      // on one platform only.
      switch method {
      case .capabilities:
        result(capabilities())
      case .generateKey:
        let args = try arguments(call)
        result(
          try generateKey(
            keyId: try requireString(args, "keyId"),
            requireHardware: args["requireHardware"] as? Bool ?? false,
            overwrite: args["overwrite"] as? Bool ?? false,
            protection: try requireProtection(args)
          ))
      case .getKey:
        let args = try arguments(call)
        result(try describeKey(keyId: try requireString(args, "keyId")))
      case .sign:
        let args = try arguments(call)
        guard let payload = args["payload"] as? FlutterStandardTypedData else {
          throw SignerError(.keystoreFailure, "Missing required argument \"payload\"")
        }
        let signature = try sign(
          keyId: try requireString(args, "keyId"),
          payload: payload.data,
          reason: args["reason"] as? String)
        result(FlutterStandardTypedData(bytes: signature))
      case .deleteKey:
        let args = try arguments(call)
        try deleteKey(keyId: try requireString(args, "keyId"))
        result(nil)
      }
    } catch let error as SignerError {
      result(FlutterError(code: error.code.rawValue, message: error.message, details: nil))
    } catch {
      result(
        FlutterError(
          code: SignerErrorCode.keystoreFailure.rawValue,
          message: error.localizedDescription,
          details: nil))
    }
  }

  // MARK: - operations

  private func capabilities() -> [String: Any] {
    #if os(iOS)
      let platform = "ios"
    #else
      let platform = "macos"
    #endif
    return [
      "platform": platform,
      "backing": (isSecureEnclaveAvailable() ? KeyBacking.secureEnclave : KeyBacking.keychain).rawValue,
    ]
  }

  private func generateKey(
    keyId: String, requireHardware: Bool, overwrite: Bool, protection: KeyProtection
  ) throws
    -> [String: Any]
  {
    // Capability checks FIRST, before anything destructive.
    //
    // `overwrite = true` deletes the incumbent key below, so a rejection after
    // that point would leave the device with no credential at all — unable to
    // authenticate and unable to sign its way through re-enrolment. For a
    // device-bound banking key that is far worse than the failure the caller
    // asked for.
    let useEnclave = isSecureEnclaveAvailable()
    if requireHardware && !useEnclave {
      throw SignerError(
        .hardwareUnavailable,
        "The Secure Enclave is unavailable on this device and requireHardware was set")
    }

    // A user-present key on a device with no passcode and no biometric cannot
    // be created — SecAccessControlCreateWithFlags fails, and it fails *after*
    // the delete below unless we check here. Checking up front also lets the
    // caller distinguish "you need to set a screen lock" (recoverable in
    // Settings) from "this device has no secure element" (not recoverable at
    // all), which a single hardware_unavailable code could not express.
    if protection.requiresUserPresence && !isUserAuthenticationAvailable() {
      throw SignerError(
        .userAuthenticationRequired,
        "A user-present key needs a device passcode or an enrolled biometric, "
          + "and this device has neither")
    }

    if try loadPrivateKey(keyId: keyId) != nil {
      guard overwrite else {
        throw SignerError(.keyAlreadyExists, "A key already exists under \"\(keyId)\"")
      }
      try deleteKey(keyId: keyId)
    }

    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        accessibility(for: protection),
        accessControlFlags(for: protection, useEnclave: useEnclave),
        &error)
    else {
      throw SignerError(
        .keystoreFailure,
        "SecAccessControlCreateWithFlags failed: \(describe(error))")
    }

    var privateAttributes: [String: Any] = [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrAccessControl as String: access,
    ]
    #if os(macOS)
      // Without the data-protection keychain, macOS stores the key in the file
      // keychain, where the Secure Enclave token is not addressable.
      privateAttributes[kSecUseDataProtectionKeychain as String] = true
    #endif

    var attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecPrivateKeyAttrs as String: privateAttributes,
    ]
    if useEnclave {
      attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }

    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      throw SignerError(
        .keystoreFailure, "SecKeyCreateRandomKey failed: \(describe(error))")
    }

    return try describe(keyId: keyId, privateKey: privateKey, isEnclave: useEnclave)
  }

  private func describeKey(keyId: String) throws -> [String: Any]? {
    guard let privateKey = try loadPrivateKey(keyId: keyId) else { return nil }
    return try describe(keyId: keyId, privateKey: privateKey, isEnclave: isEnclaveKey(privateKey))
  }

  private func sign(keyId: String, payload: Data, reason: String?) throws -> Data {
    // The prompt, when there is one, is raised by the Security framework during
    // SecKeyCreateSignature — not here. All this does is caption it: without an
    // LAContext carrying `localizedReason`, iOS falls back to its own generic
    // system string, which is not French, in the middle of a French flow.
    //
    // Attaching a context to an ambient key is harmless (nothing consults it),
    // so this needs no branch on protection — which is just as well, because the
    // access control an existing key was created with cannot be read back.
    let context = LAContext()
    if let reason = reason, !reason.isEmpty {
      context.localizedReason = reason
    }

    guard let privateKey = try loadPrivateKey(keyId: keyId, context: context) else {
      throw SignerError(.keyNotFound, "No key stored under \"\(keyId)\"")
    }
    var error: Unmanaged<CFError>?
    // ...MessageX962SHA256 digests the message for us, matching
    // java.security's "SHA256withECDSA" and pointycastle's SHA-256 signer.
    guard
      let signature = SecKeyCreateSignature(
        privateKey, .ecdsaSignatureMessageX962SHA256, payload as CFData, &error) as Data?
    else {
      throw signingError(from: error)
    }
    // Security framework emits ASN.1 DER; JWS ES256 needs IEEE P1363 r‖s.
    // See EcdsaSignatureCodec — extracted so it is unit-testable without
    // a simulator, a Flutter engine or a keychain.
    return try EcdsaSignatureCodec.derToP1363(signature)
  }

  private func deleteKey(keyId: String) throws {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    ]
    #if os(macOS)
      query[kSecUseDataProtectionKeychain as String] = true
    #endif
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw SignerError(.keystoreFailure, "SecItemDelete failed with status \(status)")
    }
  }

  // MARK: - access control policy (the two-key model)

  /// When the keychain will let the item be read at all.
  ///
  /// **Ambient — `afterFirstUnlockThisDeviceOnly`.** A caller that signs
  /// background requests on a timer needs this key readable while the screen is
  /// locked, since polling keeps running after the user last unlocked the
  /// device. `whenUnlocked` would fail all of that traffic; `afterFirstUnlock`
  /// succeeds from the first unlock after a reboot onwards, which is what it
  /// needs.
  ///
  /// **User-present — `whenUnlockedThisDeviceOnly`.** This key only ever signs a
  /// deliberate tier-3 action, so by construction the screen is unlocked and a
  /// human is looking at it. Narrowing the window costs nothing here and removes
  /// the class of attack where a locked-but-booted phone is compelled to sign.
  /// It also stops the item being readable during the background-refresh and
  /// notification-handling windows, where the app runs but nobody is present.
  ///
  /// `ThisDeviceOnly` on both: it keeps the key out of iCloud Keychain and out
  /// of encrypted backups, so a device-bound credential stays bound to *this*
  /// device rather than restoring onto a new one.
  private func accessibility(for protection: KeyProtection) -> CFString {
    switch protection {
    case .ambient: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case .userPresent: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
  }

  /// What the Secure Enclave demands before it performs the signature.
  ///
  /// `.privateKeyUsage` is what makes an enclave key usable for signing at all,
  /// and on its own it prompts for nothing — that is the ambient key.
  ///
  /// The user-present key adds `[.biometryCurrentSet, .or, .devicePasscode]`,
  /// which reads as "a biometric from the enrolment set that existed when this
  /// key was made, OR the device passcode". Both halves are deliberate:
  ///
  /// - `.biometryCurrentSet` rather than `.biometryAny` is ADR 0024 §5 — a new
  ///   fingerprint must not inherit this key's authority.
  /// - `.or .devicePasscode` is ADR 0024 §6 — a meaningful share of the target
  ///   hardware has no working biometric sensor, and requiring one would lock
  ///   those customers out of tier 3 entirely.
  ///
  /// Worth being precise about what the combination actually does, because it is
  /// narrower than §5 alone implies: re-enrolling a biometric invalidates only
  /// the biometry branch. The passcode branch survives, so the key stays usable.
  /// That does not open the hole §5 describes — iOS requires the passcode before
  /// it will accept a new biometric enrolment, so an attacker who can enrol one
  /// already holds the credential the surviving branch asks for.
  private func accessControlFlags(for protection: KeyProtection, useEnclave: Bool)
    -> SecAccessControlCreateFlags
  {
    var flags: SecAccessControlCreateFlags = useEnclave ? [.privateKeyUsage] : []
    if protection.requiresUserPresence {
      flags.formUnion([.biometryCurrentSet, .or, .devicePasscode])
    }
    return flags
  }

  /// Whether this device can authenticate a human at all.
  ///
  /// `.deviceOwnerAuthentication` (not `...WithBiometrics`) is the policy that
  /// matches the access control above: it answers yes when there is a passcode,
  /// a biometric, or both — the same disjunction the key will be created with.
  /// Probing with the biometrics-only policy would reject a passcode-only device
  /// that this package is perfectly able to serve.
  private func isUserAuthenticationAvailable() -> Bool {
    LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
  }

  /// Map a signing failure onto a code the Dart side can act on.
  ///
  /// The distinction that matters to the app is cancelled-by-the-user versus
  /// anything else: a dismissed prompt is a customer changing their mind at a
  /// confirmation screen, and treating it as an auth failure would trigger
  /// re-enrolment or logout for what is a routine interaction.
  private func signingError(from error: Unmanaged<CFError>?) -> SignerError {
    let message = describe(error)
    guard let cfError = error?.takeUnretainedValue() else {
      return SignerError(.keystoreFailure, "SecKeyCreateSignature failed: \(message)")
    }
    let nsError = cfError as Error as NSError

    if nsError.domain == LAErrorDomain {
      switch LAError.Code(rawValue: nsError.code) {
      case .userCancel, .appCancel, .systemCancel, .userFallback:
        return SignerError(.userAuthenticationCancelled, message)
      case .passcodeNotSet, .biometryNotEnrolled, .biometryNotAvailable, .biometryLockout:
        return SignerError(.userAuthenticationRequired, message)
      default:
        return SignerError(.keystoreFailure, message)
      }
    }

    // OSStatus codes come back on NSOSStatusErrorDomain. errSecUserCanceled is
    // what the keychain reports when the prompt is dismissed before
    // LocalAuthentication gets involved.
    switch nsError.code {
    case Int(errSecUserCanceled):
      return SignerError(.userAuthenticationCancelled, message)
    case Int(errSecInteractionNotAllowed):
      // The item exists but is unreadable right now — a user-present key
      // reached from a background context, which is a caller bug rather than a
      // device problem.
      return SignerError(
        .userAuthenticationRequired,
        "This key requires user presence and cannot be used from the background: \(message)")
    default:
      return SignerError(.keystoreFailure, "SecKeyCreateSignature failed: \(message)")
    }
  }

  // MARK: - helpers

  private func describe(keyId: String, privateKey: SecKey, isEnclave: Bool) throws -> [String: Any]
  {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw SignerError(.keystoreFailure, "Could not derive the public key")
    }
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      throw SignerError(
        .keystoreFailure,
        "SecKeyCopyExternalRepresentation failed: \(describe(error))")
    }
    // X9.63 uncompressed point: 0x04 || X (32) || Y (32).
    guard raw.count == 1 + Self.coordinateLength * 2, raw.first == 0x04 else {
      throw SignerError(
        .keystoreFailure,
        "Unexpected public key encoding (\(raw.count) bytes)")
    }
    let x = raw.subdata(in: 1..<(1 + Self.coordinateLength))
    let y = raw.subdata(in: (1 + Self.coordinateLength)..<raw.count)

    return [
      "keyId": keyId,
      "x": base64Url(x),
      "y": base64Url(y),
      "backing": (isEnclave ? KeyBacking.secureEnclave : KeyBacking.keychain).rawValue,
    ]
  }

  private func loadPrivateKey(keyId: String, context: LAContext? = nil) throws -> SecKey? {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: tagData(keyId),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    if let context = context {
      query[kSecUseAuthenticationContext as String] = context
    }
    #if os(macOS)
      query[kSecUseDataProtectionKeychain as String] = true
    #endif

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
      guard let result = item else { return nil }
      return (result as! SecKey)
    case errSecItemNotFound:
      return nil
    default:
      throw SignerError(
        .keystoreFailure, "SecItemCopyMatching failed with status \(status)")
    }
  }

  /// Whether a live key is held by the Secure Enclave.
  ///
  /// Read back from the key's own attributes rather than inferred from how it
  /// was requested, so a silent fallback inside the Security framework cannot
  /// be reported as enclave-backed.
  private func isEnclaveKey(_ key: SecKey) -> Bool {
    guard let attributes = SecKeyCopyAttributes(key) as? [String: Any] else { return false }
    guard let tokenID = attributes[kSecAttrTokenID as String] as? String else { return false }
    return tokenID == (kSecAttrTokenIDSecureEnclave as String)
  }

  /// Probe the enclave by creating and immediately discarding a non-permanent key.
  ///
  /// `LAContext.canEvaluatePolicy` is not a valid proxy: it reports biometric
  /// enrolment, not enclave presence, and the two diverge on a simulator and on
  /// a device with no passcode set.
  private func isSecureEnclaveAvailable() -> Bool {
    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        [.privateKeyUsage],
        &error)
    else { return false }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false,
        kSecAttrAccessControl as String: access,
      ],
    ]
    guard let probe = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
      return false
    }
    return isEnclaveKey(probe)
  }

  private func tagData(_ keyId: String) -> Data {
    Data((Self.tagPrefix + keyId).utf8)
  }

  private func base64Url(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private func describe(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "unknown error" }
    return CFErrorCopyDescription(error) as String? ?? "unknown error"
  }

  private func arguments(_ call: FlutterMethodCall) throws -> [String: Any] {
    guard let args = call.arguments as? [String: Any] else {
      throw SignerError(.keystoreFailure, "Expected a map of arguments")
    }
    return args
  }

  private func requireString(_ args: [String: Any], _ name: String) throws -> String {
    guard let value = args[name] as? String else {
      throw SignerError(.keystoreFailure, "Missing required argument \"\(name)\"")
    }
    return value
  }

  /// The one wire -> enum boundary for the protection tag.
  ///
  /// Missing or unrecognised is a hard failure, with no default. Guessing
  /// `ambient` would hand a caller who asked for tier-3 protection a key that
  /// signs without a human; guessing `userPresent` would make the request
  /// interceptor prompt on every background poll. Neither is a safe direction to
  /// be wrong in, so a mismatched Dart/native pairing fails at the call instead
  /// of producing a key with the wrong policy baked in permanently.
  private func requireProtection(_ args: [String: Any]) throws -> KeyProtection {
    let raw = try requireString(args, "protection")
    guard let protection = KeyProtection(rawValue: raw) else {
      throw SignerError(
        .keystoreFailure, "Unknown key protection \"\(raw)\"")
    }
    return protection
  }

}
