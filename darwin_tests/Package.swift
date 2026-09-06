// swift-tools-version: 5.9
import PackageDescription

/// Standalone test harness for the plugin's pure-Swift code.
///
/// Why this exists as its own package rather than an Xcode test target: the
/// DER -> IEEE P1363 conversion has no Flutter and no Security-framework
/// dependency, so testing it should not require booting a simulator, building
/// the Flutter engine, or running CocoaPods. `swift test` here takes seconds.
///
/// `Sources/SignKeypairCodec/EcdsaSignatureCodec.swift` is a **symlink** to the
/// file the plugin actually ships — the tests exercise the real source, not a
/// copy that could drift.
let package = Package(
  name: "SignKeypairCodec",
  platforms: [.macOS(.v10_15)],
  targets: [
    .target(name: "SignKeypairCodec"),
    .testTarget(name: "SignKeypairCodecTests", dependencies: ["SignKeypairCodec"]),
  ]
)
