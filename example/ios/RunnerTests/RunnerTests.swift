import Flutter
import UIKit
import XCTest

@testable import flutter_sign_keypair

/// Tests for the plugin's Flutter-facing surface on iOS.
///
/// Scope note: the DER -> IEEE P1363 codec is NOT tested here. It lives in
/// `EcdsaSignatureCodec`, has no Flutter or Security-framework dependency, and
/// is covered by `darwin_tests/` — a plain SwiftPM package that runs in
/// milliseconds with no simulator. What is left for this target is the part that
/// genuinely needs a Flutter engine: method dispatch and argument validation.
///
/// Keychain-backed operations (generateKey/sign/getKey) are deliberately absent:
/// they need a provisioned keychain and are covered by
/// `example/integration_test/secure_signer_test.dart` on a real device.
class RunnerTests: XCTestCase {

  private func call(
    _ method: String,
    _ arguments: Any? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
  ) -> Any? {
    let plugin = FlutterSignKeypairPlugin()
    let expectation = expectation(description: "\(method) must call back")
    var captured: Any?
    plugin.handle(FlutterMethodCall(methodName: method, arguments: arguments)) { result in
      captured = result
      expectation.fulfill()
    }
    waitForExpectations(timeout: 5)
    return captured
  }

  /// An unknown method must reach Dart as notImplemented, not as a crash or a
  /// silent nil — Dart maps it to MissingPluginException.
  func testUnknownMethodIsNotImplemented() {
    let result = call("thisMethodDoesNotExist")
    XCTAssertTrue(result is NSObject)
    XCTAssertEqual(result as? NSObject, FlutterMethodNotImplemented)
  }

  /// capabilities() takes no arguments and must always answer with the two keys
  /// the Dart side decodes.
  func testCapabilitiesReturnsPlatformAndBacking() {
    guard let result = call("capabilities") as? [String: Any] else {
      return XCTFail("capabilities did not return a map")
    }
    XCTAssertEqual(result["platform"] as? String, "ios")
    let backing = result["backing"] as? String
    XCTAssertTrue(
      backing == "secure_enclave" || backing == "keychain",
      "unexpected backing tag \(backing ?? "nil") — Dart maps anything it does "
        + "not recognise to `software`, silently downgrading the report")
  }

  /// A missing required argument must produce a typed FlutterError rather than
  /// trapping on a force-unwrap.
  func testMissingKeyIdIsRejected() {
    for method in ["generateKey", "getKey", "sign", "deleteKey"] {
      let result = call(method, [String: Any]())
      guard let error = result as? FlutterError else {
        return XCTFail("\(method) with no keyId did not return a FlutterError")
      }
      XCTAssertEqual(error.code, "keystore_failure")
    }
  }

  /// Arguments of the wrong shape (not a map) must also be rejected cleanly.
  func testNonMapArgumentsAreRejected() {
    let result = call("generateKey", "not a map")
    XCTAssertTrue(result is FlutterError, "expected a FlutterError, got \(String(describing: result))")
  }

  /// sign() requires a payload as well as a keyId.
  func testMissingPayloadIsRejected() {
    let result = call("sign", ["keyId": "k"])
    guard let error = result as? FlutterError else {
      return XCTFail("sign with no payload did not return a FlutterError")
    }
    XCTAssertEqual(error.code, "keystore_failure")
    XCTAssertTrue(error.message?.contains("payload") == true)
  }
}
