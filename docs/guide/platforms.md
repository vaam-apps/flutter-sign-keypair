# Platform notes & limitations

What each platform actually does, where it differs from the others, and the
gaps that are documented rather than hidden.

## Support matrix

| Platform        | Backend                             | Possible backing               | User-present keys | Tested                         |
| --------------- | ----------------------------------- | ------------------------------ | ----------------- | ------------------------------ |
| Android         | `AndroidKeyStore`                   | `strongBox`, `tee`, `software` | yes               | on device and emulator         |
| iOS             | Security framework / Secure Enclave | `secureEnclave`, `keychain`    | yes               | on the simulator               |
| macOS           | same Swift source as iOS            | `secureEnclave`, `keychain`    | yes               | shares its test suite with iOS |
| Web             | `SoftwareSecureSigner` (pure Dart)  | `software`                     | no                | unit-tested                    |
| Windows / Linux | `SoftwareSecureSigner` (pure Dart)  | `software`                     | no                | no native implementation       |

## Android

- **Minimum API 24.** The plugin is built with `compileSdk = 36` and Java 17.
- **StrongBox, then TEE.** If the device advertises
  `FEATURE_STRONGBOX_KEYSTORE`, keys are requested in StrongBox and fall back
  to the TEE when StrongBox refuses the spec.
- **Backing is read back from the keystore**, never assumed. Below API 31 the
  keystore only says "secure hardware or not", so a StrongBox key there is
  reported as `trustedExecutionEnvironment`.
- **Emulators** usually have a software keymaster. Keys there report
  `software`, even though they are still not exportable from the app process.
- **`capabilities()` is not free.** Unless StrongBox is advertised, the probe
  generates a throwaway key, reads where it landed and deletes it.
  `generateKey(requireHardware: true)` runs the same probe. Call
  `capabilities()` once at startup rather than per request.
- **User-present keys need a `FragmentActivity`.** See
  [Getting started](./getting-started#android).
- **User-present keys on API 24 to 29 are biometric-only.** Before Android 11
  the platform has no per-operation key that also accepts the device
  credential, so on those releases a device with only a PIN, pattern or
  password cannot create a user-present key; key generation fails with
  `keystoreFailure`. From API 30 the key accepts `BIOMETRIC_STRONG` or the
  device credential, and so does the prompt.
- **Per-operation authorisation.** Each user-present signature needs its own
  authentication; there is no time window during which one prompt covers
  several signatures.
- **The default prompt copy is French.** Without a `reason`, the prompt's
  title is "Authentification requise" and, when the device credential is not
  allowed (API 24 to 29), its cancel button reads "Annuler". Pass `reason` on
  every user-present call.
- **A failed `overwrite` has one narrow window.** `overwrite: true` deletes
  the old key before generating the new one, because AndroidKeyStore cannot
  rename an alias. Capability checks run first, so the common failures leave
  the old key in place; but if the keymaster advertises hardware and then
  produces a software key for a `requireHardware: true` call, the old key is
  already gone.

## iOS and macOS

- **Minimum iOS 15.0 and macOS 10.15.** One Swift source serves both; the
  macOS plugin files are symlinks to the iOS ones.
- **Secure Enclave when available, keychain otherwise.** On the iOS Simulator
  and on Macs without a Secure Enclave, keys are ordinary keychain keys and
  report `keychain`, which is **not** hardware-backed. Pass
  `requireHardware: true` to refuse them instead.
- **macOS uses the data-protection keychain** (`kSecUseDataProtectionKeychain`)
  for every key operation.
- **Keys stay on this device.** Both keys use a `ThisDeviceOnly`
  accessibility class: they are not synced to iCloud Keychain and not restored
  from backups onto another device.
- **The ambient key works while locked** (`AfterFirstUnlockThisDeviceOnly`),
  from the first unlock after a reboot, so background signing keeps working.
- **The user-present key needs the device unlocked**
  (`WhenUnlockedThisDeviceOnly`). Used from the background it fails with
  `userAuthenticationRequired` (`errSecInteractionNotAllowed`).
- **A new biometric does not destroy the user-present key.** It is created
  with `.biometryCurrentSet` **or** `.devicePasscode`. Enrolling a new
  fingerprint or face invalidates the biometric branch only; the key stays
  usable with the passcode. The Apple code never reports `keyInvalidated`.
- **The prompt is captioned with `reason`.** The plugin passes it as the
  `LAContext.localizedReason`; without it, the system shows its own generic
  text.
- **`capabilities()` probes the enclave** by creating and discarding a
  non-permanent key, so it is not free either.
- **Face ID** needs an `NSFaceIDUsageDescription` in your app's `Info.plist`
  (an Apple requirement); see [Getting started](./getting-started#ios).

## Web, Windows and Linux

These platforms have no native implementation and use `SoftwareSecureSigner`.

- **Keys are software keys.** The private scalar lives in Dart heap memory and
  is extractable by anything that can read the process. Every key reports
  `KeyBacking.software` and `isHardwareBacked == false`. Log that flag rather
  than assuming.
- **Keys do not survive a restart by default.** The default
  `InMemorySoftwareKeyStore` lives as long as the process. Inject a persistent
  `SoftwareKeyStore` if you need durable keys, and remember that what it
  stores contains the private scalar.
- **No user-present keys.** The fallback refuses `KeyProtection.userPresent`
  with `hardwareUnavailable`, so there is no silent "prompting" key that never
  prompts. As a result `generateDeviceKeys()` always fails on these platforms;
  use `generateKey()` for the ambient key.
- **`requireHardware: true` always fails** with `hardwareUnavailable`.
- **Signatures are deterministic** (RFC 6979), unlike the hardware signers.

### Windows

There is no CNG (`BCrypt*` / `NCrypt*`) implementation. Windows uses the
software fallback, and says so. If you need hardware there, the plugin's
`SignKeypairPlatform` interface is the place to plug in a native backend; see
[the API overview](./api#signkeypairplatform).

## Not supported

- **Importing a key into hardware.** A hardware key must be generated inside
  the secure element; neither AndroidKeyStore nor the Secure Enclave will take
  an existing private key. `SoftwareSecureSigner.importKey` adopts an existing
  key as a **software** key only. See [Migrating devices](./migration).
- **Curves other than P-256, and algorithms other than ES256.** The Secure
  Enclave supports P-256 only, and the API is built around ES256.
- **Key attestation.** The plugin reports where a key lives, but it does not
  return Android key attestation certificates or any Apple equivalent, so your
  backend cannot independently check that claim.
- **Exporting a private key.** There is no API for it, by design.
