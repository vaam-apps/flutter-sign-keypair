# Testing & proof

The package makes security claims, and each one is backed by a test rather
than asserted. This page says what is tested where, and how to run it.

## What is proven, and where

| Claim                                                          | Proven by                                                                                |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| The JWS is correct ES256 and matches an independent signer     | `test/jws_compatibility_test.dart`                                                       |
| A real keystore signature verifies against the reported JWK    | `example/integration_test/secure_signer_test.dart` (on device)                           |
| The private key cannot be exported on Android                  | `SecureKeyStoreTest.privateKeyIsNeverExportable` (instrumented)                          |
| The key lives in secure hardware, where the device has it      | `SecureKeyStoreTest.keyLivesInSecureHardware` (instrumented; skipped on emulators)       |
| `generateKey()` and `capabilities()` never disagree on backing | the on-device integration test                                                           |
| `requireHardware` never degrades silently, nor destroys a key  | the integration test, the instrumented tests and `test/lifecycle_and_encoding_test.dart` |
| DER to P1363 is right in all three languages                   | `test/asn1_test.dart`, `DerToP1363Test.kt`, `EcdsaSignatureCodecTests.swift`             |
| JWK coordinates are always 32 bytes                            | `test/lifecycle_and_encoding_test.dart`, `CoordinateBytesTest.kt`                        |
| Dart, Kotlin and Swift agree on every wire string              | `test/wire_contract_test.dart`, `WireContractTest.kt`, `WireContractTests.swift`         |
| The two-key model rolls back correctly                         | `test/key_protection_test.dart`                                                          |
| The fallback never claims hardware or user presence            | `test/software_signer_test.dart`, `test/key_protection_test.dart`                        |
| Native errors map to the right `SignerErrorCode`               | `test/method_channel_signer_test.dart`                                                   |

### Hardware backing on Android

The instrumented suite drives the production `SecureKeyStore` class, not a
copy of its key spec, so a change that made the shipped spec weaker would
fail it. It asserts that `PrivateKey.getEncoded()` is `null`, which holds on
every Android device, emulator included. Where the device has real secure
hardware it also asserts that `KeyInfo.securityLevel` is
`TRUSTED_ENVIRONMENT`, `STRONGBOX` or `UNKNOWN_SECURE`. On an emulator that
assertion is **skipped, not passed**: an emulator ships a software keymaster
and cannot prove hardware residency.

### DER to IEEE P1363, in three languages

The conversion exists three times (Dart, Kotlin, Swift), and each copy has its
own unit tests driven by the **same** known-answer vectors. The vectors are
real P-256 signatures produced with `openssl dgst -sha256 -sign`, chosen to hit
the shapes that occur about once in 256 signatures. Each expected value was
computed independently, re-encoded to DER and checked with
`openssl dgst -sha256 -verify` against the real public key, so the
expectations rest on a third-party implementation rather than on the code
under test. They are known answers, not round trips: an encoder and a decoder
that share a padding bug would round-trip happily.

Covered in each language: a short `r`, a short `s`, both short, a high-bit
component carrying DER's `0x00` sign byte, the `r=1, s=2` extreme, a zero
component, long-form lengths, an always-64-bytes property check, and malformed
input (empty, truncated, wrong tag, overrunning length, zero-length INTEGER,
trailing bytes) that must fail cleanly instead of reading out of bounds.

The Swift codec lives in its own `EcdsaSignatureCodec` type with no Flutter or
Security-framework import, so `darwin_tests/` can test the shipped file (via a
symlink) without a simulator.

## Running the tests

These are the repository's commands, from its README.

```bash
# Dart unit tests (no device): correctness, ASN.1, wire contract.
flutter test
flutter analyze

# Swift codec and wire-contract tests: pure SwiftPM, no simulator.
cd darwin_tests && swift test

# Kotlin JVM unit tests (DER to P1363, BigInteger to coordinate).
cd example/android && ./gradlew :flutter_sign_keypair:testDebugUnitTest

# Kotlin instrumented tests against the real AndroidKeyStore. Needs a booted device.
cd example/android && ./gradlew :flutter_sign_keypair:connectedDebugAndroidTest

# Swift Flutter-surface tests (method dispatch, argument validation). Needs a simulator.
cd example/ios && xcodebuild test -workspace Runner.xcworkspace -scheme Runner \
  -destination 'platform=iOS Simulator,id=<sim-id>' -only-testing:RunnerTests

# On-device integration test, Android, in profile mode.
cd example
flutter drive --driver=test_driver/integration_test.dart \
  --target=integration_test/secure_signer_test.dart --profile -d <android-device>

# iOS: profile mode is not supported on the simulator, so debug only.
flutter test integration_test/secure_signer_test.dart -d <ios-simulator>
```

::: tip If the iOS build fails on a missing `listener.dart`
A previous `flutter test integration_test` run left a temporary entrypoint in
`Generated.xcconfig`. Run `flutter build ios --simulator --debug --config-only`
first.
:::

## The benchmark

The integration test also times 100 signatures through the plugin against a
hand-rolled `pointycastle` signer in the same process and prints a
`SECURE_SIGNER_BENCHMARK` line. It asserts no threshold, and the package
publishes no speed-up figure: the number depends on the device, the build mode
and whether the keystore is real hardware or an emulator's software
keymaster. Numbers are only meaningful in profile mode.
