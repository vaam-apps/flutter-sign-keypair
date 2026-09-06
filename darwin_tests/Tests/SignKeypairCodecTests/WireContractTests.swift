import XCTest

@testable import SignKeypairCodec

/// The wire contract, pinned on the Swift side.
///
/// The same vectors are asserted in `test/wire_contract_test.dart` and
/// `android/src/test/.../WireContractTest.kt`. The mapping is necessarily
/// duplicated once per language, and duplication is what drifts — these tests
/// turn a drift into a red build on the side that moved, instead of a runtime
/// failure on one platform only.
///
/// `Wire.swift` is pure Foundation, so this runs in the standalone SwiftPM
/// package with no simulator and no Flutter engine.
final class WireContractTests: XCTestCase {

  // MARK: - Method

  func testMethodWireNamesMatchTheDartSideVerbatim() {
    let expected: [String: SignerMethod] = [
      "capabilities": .capabilities,
      "generateKey": .generateKey,
      "getKey": .getKey,
      "sign": .sign,
      "deleteKey": .deleteKey,
    ]
    for (wire, method) in expected {
      XCTAssertEqual(method.rawValue, wire)
      XCTAssertEqual(SignerMethod(rawValue: wire), method)
    }
    XCTAssertEqual(
      Set(expected.values), Set(SignerMethod.allCases),
      "a SignerMethod was added without a wire vector — update Wire.swift, Wire.kt, "
        + "models.dart and all three test suites")
  }

  func testEveryMethodRoundTrips() {
    for method in SignerMethod.allCases {
      XCTAssertEqual(SignerMethod(rawValue: method.rawValue), method)
    }
  }

  func testMethodWireNamesAreUnique() {
    XCTAssertEqual(Set(SignerMethod.allCases.map(\.rawValue)).count, SignerMethod.allCases.count)
  }

  /// An unknown method must fail to parse so `handle` answers
  /// `FlutterMethodNotImplemented` — the response Flutter expects.
  func testUnknownMethodNamesFailToParse() {
    for wire in ["", " ", "nope", "CAPABILITIES", "generate_key", "sign "] {
      XCTAssertNil(SignerMethod(rawValue: wire), "\"\(wire)\" should not parse")
    }
  }

  // MARK: - Backing

  func testBackingWireNamesMatchTheDartSideVerbatim() {
    let expected: [String: KeyBacking] = [
      "secure_enclave": .secureEnclave,
      "keychain": .keychain,
      "software": .software,
    ]
    for (wire, backing) in expected {
      XCTAssertEqual(backing.rawValue, wire)
      XCTAssertEqual(KeyBacking(rawValue: wire), backing)
    }
    XCTAssertEqual(Set(expected.values), Set(KeyBacking.allCases))
  }

  /// Apple platforms never emit these, but Dart understands them because
  /// Android does. Pinned so nobody "tidies up" the Dart enum by deleting them.
  func testAppleDoesNotEmitTheAndroidBackingTags() {
    XCTAssertNil(KeyBacking(rawValue: "strongbox"))
    XCTAssertNil(KeyBacking(rawValue: "tee"))
  }

  func testEveryBackingRoundTrips() {
    for backing in KeyBacking.allCases {
      XCTAssertEqual(KeyBacking(rawValue: backing.rawValue), backing)
    }
  }

  func testBackingWireNamesAreUnique() {
    XCTAssertEqual(Set(KeyBacking.allCases.map(\.rawValue)).count, KeyBacking.allCases.count)
  }

  func testUnknownBackingTagsFailToParseAndAreNeverHardware() {
    for wire in ["", "quantum", "SECURE_ENCLAVE", "secureEnclave", "keychain "] {
      let parsed = KeyBacking(rawValue: wire)
      XCTAssertNil(parsed, "\"\(wire)\" should not parse")
      // The fallback for a nil parse is .software — fail-safe.
      XCTAssertFalse((parsed ?? .software).isHardwareBacked)
    }
  }

  /// `keychain` is deliberately NOT hardware-backed: OS-protected, but not held
  /// by a secure element, so the scalar can in principle be exported.
  func testOnlySecureElementBackingsAreHardwareBacked() {
    XCTAssertTrue(KeyBacking.secureEnclave.isHardwareBacked)
    XCTAssertFalse(KeyBacking.keychain.isHardwareBacked)
    XCTAssertFalse(KeyBacking.software.isHardwareBacked)
  }

  // MARK: - KeyProtection

  func testProtectionWireNamesMatchTheDartSideVerbatim() {
    let expected: [String: KeyProtection] = [
      "ambient": .ambient,
      "user_present": .userPresent,
    ]
    for (wire, protection) in expected {
      XCTAssertEqual(protection.rawValue, wire)
      XCTAssertEqual(KeyProtection(rawValue: wire), protection)
    }
    XCTAssertEqual(
      Set(expected.values), Set(KeyProtection.allCases),
      "a KeyProtection was added without a wire vector — update Wire.swift, "
        + "models.dart, Wire.kt and all three test suites")
  }

  func testEveryProtectionRoundTrips() {
    for protection in KeyProtection.allCases {
      XCTAssertEqual(KeyProtection(rawValue: protection.rawValue), protection)
    }
  }

  func testProtectionWireNamesAreUnique() {
    XCTAssertEqual(
      Set(KeyProtection.allCases.map(\.rawValue)).count, KeyProtection.allCases.count)
  }

  /// Unlike `KeyBacking`, an unparseable protection tag has **no safe fallback**
  /// — the caller must fail. Defaulting to `.ambient` would hand a tier-3 caller
  /// a key that signs without a human; defaulting to `.userPresent` would make
  /// the request interceptor prompt on every background poll. The policy is
  /// baked into the key permanently at creation, so a wrong guess is not
  /// recoverable without destroying the key.
  func testUnknownProtectionTagsFailToParse() {
    for wire in ["", " ", "AMBIENT", "userPresent", "user-present", "user_present "] {
      XCTAssertNil(KeyProtection(rawValue: wire), "\"\(wire)\" should not parse")
    }
  }

  func testOnlyTheUserPresentKeyDemandsAHuman() {
    XCTAssertFalse(KeyProtection.ambient.requiresUserPresence)
    XCTAssertTrue(KeyProtection.userPresent.requiresUserPresence)
  }

  // MARK: - ErrorCode

  func testErrorCodeWireNamesMatchTheDartSideVerbatim() {
    let expected: [String: SignerErrorCode] = [
      "key_not_found": .keyNotFound,
      "key_already_exists": .keyAlreadyExists,
      "hardware_unavailable": .hardwareUnavailable,
      "keystore_failure": .keystoreFailure,
      "user_authentication_required": .userAuthenticationRequired,
      "user_authentication_cancelled": .userAuthenticationCancelled,
      "key_invalidated": .keyInvalidated,
    ]
    for (wire, code) in expected {
      XCTAssertEqual(code.rawValue, wire)
      XCTAssertEqual(SignerErrorCode(rawValue: wire), code)
    }
    XCTAssertEqual(Set(expected.values), Set(SignerErrorCode.allCases))
  }

  /// Dart has two extra members: `unsupported_platform` (from
  /// MissingPluginException) and `unknown` (the catch-all). Neither is ever
  /// emitted from here.
  func testAppleDoesNotEmitTheDartOnlyCodes() {
    XCTAssertNil(SignerErrorCode(rawValue: "unsupported_platform"))
    XCTAssertNil(SignerErrorCode(rawValue: "unknown"))
  }

  func testEveryErrorCodeRoundTrips() {
    for code in SignerErrorCode.allCases {
      XCTAssertEqual(SignerErrorCode(rawValue: code.rawValue), code)
    }
  }

  func testErrorCodeWireNamesAreUnique() {
    XCTAssertEqual(Set(SignerErrorCode.allCases.map(\.rawValue)).count, SignerErrorCode.allCases.count)
  }

  func testErrorCodesAreSnakeCaseAndMethodsAreCamelCase() {
    // The two conventions differ on purpose; mixing them is a runtime-only
    // failure on one platform.
    for code in SignerErrorCode.allCases {
      XCTAssertFalse(
        code.rawValue.contains(where: \.isUppercase), "\(code.rawValue) is not snake_case")
    }
    for method in SignerMethod.allCases {
      XCTAssertFalse(method.rawValue.contains("_"), "\(method.rawValue) is not camelCase")
    }
  }

  func testSignerErrorCarriesATypedCode() {
    let error = SignerError(.keyNotFound, "nope")
    XCTAssertEqual(error.code, .keyNotFound)
    XCTAssertEqual(error.code.rawValue, "key_not_found")
    XCTAssertEqual(error.message, "nope")
  }
}
