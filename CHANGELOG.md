# Changelog

## [0.1.2](https://github.com/vaam-apps/flutter-sign-keypair/compare/v0.1.1...v0.1.2) (2026-09-19)


### Bug Fixes

* **release:** set an empty component so the merged release PR can be tagged ([aaecd0a](https://github.com/vaam-apps/flutter-sign-keypair/commit/aaecd0a41a93cd6c533905d6b3a3d1215a593345))
* **release:** use release-type simple so the merged release PR gets tagged ([b6577ab](https://github.com/vaam-apps/flutter-sign-keypair/commit/b6577ab0d0754dc59b522115aec037d53c85e4e0))
* **release:** use release-type simple so the merged release PR gets tagged ([c2487d5](https://github.com/vaam-apps/flutter-sign-keypair/commit/c2487d5a2784a9ceb0bfc8baf215a24985f4a45f))

## [0.1.1](https://github.com/vaam-apps/flutter-sign-keypair/compare/v0.1.0...v0.1.1) (2026-09-19)


### Continuous Integration

* adopt org-wide SAST, lint, Trivy and issue governance ([#1](https://github.com/vaam-apps/flutter-sign-keypair/issues/1)) ([0af5410](https://github.com/vaam-apps/flutter-sign-keypair/commit/0af5410eda97507d03a3eb49f8fc2984a1e9153d))
* adopt release-please for versioning and changelog ([#3](https://github.com/vaam-apps/flutter-sign-keypair/issues/3)) ([2d0fe59](https://github.com/vaam-apps/flutter-sign-keypair/commit/2d0fe595b23074cad5fd2aa31d0e1527b2381d1c))
* re-pin org reusable workflows for the MD024 changelog fix ([fd0fcf0](https://github.com/vaam-apps/flutter-sign-keypair/commit/fd0fcf0f3c52597842151ec473a18dfcd499a1cf))
* re-pin org reusable workflows for the MD024 changelog fix ([a344e69](https://github.com/vaam-apps/flutter-sign-keypair/commit/a344e69e9491b555487ff169b23431a262a8d152))
* re-pin org reusable workflows to current .github main ([#2](https://github.com/vaam-apps/flutter-sign-keypair/issues/2)) ([a243ce8](https://github.com/vaam-apps/flutter-sign-keypair/commit/a243ce89c249a7647a82b3c3fffda1c5b4abea7e))

## 0.1.0

Initial release of `flutter_sign_keypair` — a rebranded fork of its source
plugin's 0.2.0 release. See the README's [Origin](README.md#origin) section
for the fork relationship and license attribution.

Carried over from the source package, renamed but functionally unchanged:

- Hardware-backed ECDSA P-256 (ES256) signing via AndroidKeyStore (StrongBox
  with a graceful fallback to the TEE) and the Apple Secure Enclave (with a
  data-protection keychain fallback on iOS/macOS when the enclave is
  unavailable).
- A pure-Dart `pointycastle` software signer for web, Windows and Linux,
  which self-reports as `KeyBacking.software` rather than claiming a security
  property it cannot provide.
- The two-key model: `KeyProtection.ambient` (no user-presence binding, safe
  for a background signer) and `KeyProtection.userPresent` (biometric /
  device-credential bound, prompts every use), created together via
  `generateDeviceKeys()` with all-or-nothing rollback.
- DER → IEEE P1363 signature conversion, implemented and independently unit
  tested in Dart, Kotlin and Swift against the same known-answer vectors.
- A strict wire contract between Dart and the two native platforms —
  `KeyBacking`, `KeyProtection`, `SignerErrorCode` and `SignerMethod` each
  cross the method channel as one pinned string, asserted by matching test
  suites on both sides.
- `SoftwareSecureSigner.importKey`, for adopting an existing raw P-256 scalar
  into the software signer without putting it in a secure element (it cannot
  be — see the README's [existing keys](README.md#existing-keys) section).

Renamed from the source package as part of this fork: the default key ids, the
Android package id, the method channel name, and every source-branded class —
the public API surface is `SignKeypair`, `SignKeypairPlatform`,
`MethodChannelSignKeypair` and `FlutterSignKeypairPlugin` in this fork. See the
git history for the exact rename mapping.
