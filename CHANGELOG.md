# Changelog

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
