# flutter_sign_keypair

Hardware-backed ECDSA P-256 (ES256) signing for device-bound authentication.

The private key is generated **inside** AndroidKeyStore or the Apple Secure
Enclave and never leaves it. Signing happens in the secure element; the raw
private scalar never enters Dart or app memory.

---

## Why this exists

A device-bound authentication scheme typically needs to sign requests with a
key that is provably tied to one device. The common naive approach — generate
an EC key pair in pure Dart (or any other in-process crypto library) and store
it in secure storage — has two weaknesses this package exists to remove:

### 1. The key stops being extractable

A pure-Dart signer has to pull the raw private scalar out of storage and into
the Dart heap on every signature, because that is the only place a pure-Dart
crypto library can compute with it. For a device-bound credential that is the
wrong posture: anything that can read the process — a debugger, a heap dump, a
memory-disclosure bug — sees the credential. With this package there is
nothing to read: the keystore hands back an opaque handle whose
`getEncoded()` is `null` on Android, and the signature is computed by the
secure element on both platforms.

This is proven, not asserted — see [Verification](#verification).

### 2. Signing can be expensive on the wrong thread

If a request-signing key is asked to sign on every authenticated call,
including from background timers and polling loops, a pure-Dart ECDSA
implementation adds real CPU cost on the UI isolate, on every one of those
calls. Moving signing into the platform's own keystore lets the secure element
(or, on a real TEE/StrongBox device, dedicated silicon) do that work instead.
This package does not ship a benchmark claiming a specific speedup — the
actual number depends heavily on the device, the build mode, and whether the
platform is running on real hardware or an emulator with a software
keymaster — but moving the arithmetic off pure Dart and onto the platform is
the right direction on any device where it matters.

### Existing devices

A hardware key **cannot be imported** — it must be generated inside the
element, which means a new public key, which means re-enrolment. This package
therefore does not and cannot silently upgrade an already-enrolled device.
[`MIGRATION.md`](MIGRATION.md) sets out the constraint and the shapes a
migration can take; no migration policy is implemented here, because the right
one depends on your backend's authentication model.

---

## Platform support

| Platform | Implementation | Backing reported | Status |
|---|---|---|---|
| **Android** | `AndroidKeyStore` + `java.security.Signature` | `strongBox` → `tee` → `software` | Implemented, tested on device/emulator |
| **iOS** | `SecKeyCreateSignature`, Secure Enclave | `secureEnclave` / `keychain` | Implemented, tested on simulator |
| **macOS** | Same Swift source as iOS (symlinked) | `secureEnclave` / `keychain` | Implemented, shares its test suite with iOS |
| **Web** | Pure-Dart `pointycastle` fallback | `software` | Implemented, unit-tested |
| **Windows / Linux** | Pure-Dart fallback | `software` | **No native implementation.** See below |

The Secure Enclave supports exactly one curve — NIST P-256 — which is also
the curve JWS ES256 requires, so there is no protocol mismatch to work around.

### Windows

There is **no CNG (`BCrypt*`/`NCrypt*`) implementation**. Windows resolves to
the pure-Dart fallback, so a Windows key is a software key and reports itself
as such. This is a documented gap, not a silent degradation: `capabilities()`
returns `KeyBacking.software` and `isHardwareBacked` is `false`. A caller that
requires hardware should pass `requireHardware: true` and handle the
`hardware_unavailable` failure.

### The fallback is deliberately loud

`SoftwareSecureSigner` exists so the app runs everywhere. It is slower than a
native keystore and its keys are extractable, so every key it produces reports
`KeyBacking.software` and `isHardwareBacked == false`. Log that flag; don't
assume.

Its default `InMemorySoftwareKeyStore` does **not** survive a restart. A web
build that needs durable keys must inject a persistent `SoftwareKeyStore`.

---

## The two-key model, and why the split exists

`generateDeviceKeys()` creates two keys, not one:

- **`KeyProtection.ambient`** — no user-presence binding. Never prompts.
  Meant to be signed with on every request, including from a background
  interceptor or a polling timer, where there is no opportunity to show a
  prompt at all.
- **`KeyProtection.userPresent`** — bound to a live biometric or the device
  credential. Prompts on every use. Meant for the operations that justify
  interrupting the user: a high-value transfer, a security-sensitive change,
  anything where you want cryptographic proof a human was present, not just
  that the app was running.

The reason for two keys instead of one is not that biometrics are hard to
wire up — it is that a single key cannot correctly serve both populations of
request. Requiring user presence on every signature would mean prompting on
every background poll, in a context where no UI is available to show a
prompt. Not requiring it at all means a compromised or automated process in
the app can sign a sensitive operation exactly as easily as a routine one. A
backend that wants to require the stronger key for a sensitive endpoint needs
that key to actually mean something — which is what the split buys: in-process
code can still *use* the ambient key (a secure element signs whatever it is
asked to), but it cannot produce a signature from the user-present key without
a human actually authenticating.

`generateDeviceKeys()` creates both as one unit and rolls the ambient key back
if the user-present one cannot be created (no biometric enrolled, no screen
lock, a keymaster that refuses the spec) — so a device is never left holding a
key your backend has never seen. A *pre-existing* ambient key is never rolled
back this way, since deleting a device's already-registered identity because a
later upgrade failed would turn a failed enrolment into a lockout.

The flag that makes a re-enrolled biometric not silently inherit the old
key's authority — `setInvalidatedByBiometricEnrollment` on Android,
`.biometryCurrentSet` on iOS/macOS — is carried by the **user-present key
alone**. Losing that flag would mean anyone who can add a new fingerprint to
the device automatically gains the authority the user-present key represents.
Carrying it only on that key also means a fresh biometric enrolment
invalidates only the prompting key, not the whole device: the ambient key is
untouched, so the device can still authenticate itself while the user-present
key is regenerated and re-registered.

Both platforms also accept the device credential (passcode / screen lock)
alongside biometrics for the user-present key, because a meaningful share of
real hardware has no working biometric sensor. That does not weaken the
biometric-invalidation property: both platforms require the *existing*
credential before they will accept a newly enrolled biometric, so an attacker
who can add a fingerprint already holds what the device-credential branch
would have asked for anyway.

## Key backing, and why unknown maps down to `software`

`KeyBacking` is ordered by decreasing assurance: `strongBox` and
`secureEnclave` and `trustedExecutionEnvironment` (all non-extractable,
hardware-isolated), then `keychain` (OS-protected but not secure-element-held,
so in principle exportable), then `software` (the scalar is reachable from
process memory).

Every place a backing tag crosses the method channel and is parsed back into
this enum, an unrecognised tag becomes `KeyBacking.software` rather than
throwing or guessing something stronger. That direction is deliberate and
load-bearing: **under-reporting strength is safe, over-reporting is a false
security claim.** If a newer native build ever reports a backing level this
Dart side has never heard of, falling back to `software` means a caller that
checks `isHardwareBacked` gets a conservative answer instead of a wrong one.

`KeyProtection` (the ambient/user-present tag) has the opposite rule on
purpose: an unrecognised protection tag has **no safe default** and fails to
parse. Guessing `ambient` for a caller that asked for the prompting key would
hand back a key that signs silently; guessing `userPresent` would make a
background signer start prompting on every poll. Neither wrong guess is safe,
so there is no default — a mismatched Dart/native pairing fails loudly at the
call instead of producing a key with the wrong policy baked in.

---

## Usage

```dart
final signer = SignKeypair();

// Once, at enrolment. Both keys or neither — if the user-present key cannot be
// created, the ambient one is rolled back rather than leaving the device
// half-enrolled.
final keys = await signer.generateDeviceKeys();
await registerDeviceWithBackend(
  ambient: keys.ambient.publicKey.toJson(),          // {kty, crv, x, y}
  userPresent: keys.userPresent.publicKey.toJson(),
);

if (!keys.isHardwareBacked) {
  logger.warning('a device key is software-backed');
}

// On every authenticated request — the ambient key, which never prompts.
final jws = await signer.signCompactJws(payload: <String, dynamic>{
  'timestamp_ms': DateTime.now().millisecondsSinceEpoch,
  'device_id': deviceId,
  'method': 'POST',
  'path': '/v1/payments/transfer',
});

// For a sensitive operation — device management, a security-relevant change, a
// high-value transfer. This one raises a biometric / passcode prompt every
// time, so pass your own localized reason string.
final sensitive = await signer.signCompactJws(
  keyId: SignKeypair.defaultUserPresentKeyId,
  reason: 'Confirm this transfer',
  payload: <String, dynamic>{...},
);
```

`SecureSignerException.code` distinguishes the three ways a user-present
signature fails, and they need different handling: `userAuthenticationCancelled`
is a person changing their mind (do nothing), `userAuthenticationRequired` is
a device with no screen lock (send them to Settings), and `keyInvalidated`
means a biometric was re-enrolled — generate a fresh user-present key and
register its thumbprint. None of the three is a reason to log the user out or
to re-run the enrolment ceremony.

The API is shaped around one specific job — build a JSON payload, wrap it in a
fixed `{"alg":"ES256","typ":"JWT"}` header, sign, emit compact JWS — rather
than a general-purpose crypto surface. If you need a raw signature over your
own signing input instead, use `signRaw`.

### The default biometric prompt copy is French — override it

The native Android prompt's default title (`"Authentification requise"`) and
cancel button (`"Annuler"`) are French strings, carried over from this
package's origin. They are used **only** when a `sign()` call for a
user-present key omits `reason` — every call site should pass its own
localized `reason`, which both the Android `BiometricPrompt` and the iOS/macOS
`LAContext.localizedReason` will show in its place. Treat seeing the default
string in production as a bug: a call that forgot to localize its prompt.

### Signatures are not stable

The Dart fallback uses RFC 6979 deterministic `k`; AndroidKeyStore and the
Secure Enclave use a random `k`. Both are valid ES256. Signing the same
payload twice will usually give two different signatures — never treat a
signature as a cache key or an idempotency token.

---

## Verification

### Signature correctness

`test/jws_compatibility_test.dart` signs payloads with this package and with
an independent reference JWS implementation (`test/support/reference_jws_signer.dart`),
then verifies **both against the same public key** and asserts byte-identical
output, which is stronger than "both verify". Several representative payload
shapes are covered, including accented French text, to exercise UTF-8 and
JSON-encoding edge cases.

On device, `example/integration_test/secure_signer_test.dart` verifies a real
keystore signature against the JWK the plugin reported, plus the negative
case, plus that `generateKey()` and `capabilities()` never disagree about
hardware backing.

### Hardware backing

Claims are checked, not assumed:

- The Android instrumented test suite asserts `PrivateKey.getEncoded() == null`
  (non-extractability — true on every Android device, including an emulator)
  and, **where the device has a real secure element**, that
  `KeyInfo.securityLevel` is `TRUSTED_ENVIRONMENT`, `STRONGBOX` or
  `UNKNOWN_SECURE`. On an emulator that assertion is *skipped*, not passed —
  an emulator ships a software keymaster and cannot prove hardware residency.
- The Dart integration test asserts `generateKey()` and `capabilities()` agree
  about hardware backing, so the plugin cannot over-promise.
- `MethodChannelSignKeypair` maps an unrecognised native backing tag to
  `software`, never optimistically to hardware.

### DER → IEEE P1363, in all three languages

Every platform ECDSA API emits ASN.1 DER; JWS ES256 requires IEEE P1363
(`r‖s`, 32 bytes each). The conversion exists three times — Dart, Kotlin,
Swift — and **each has its own isolated unit tests**, driven by the *same*
known-answer vectors, which cross-validates the implementations against one
another.

The vectors are genuine P-256 signatures produced by `openssl dgst -sha256
-sign`, selected to hit the shapes that occur only ~1 time in 256. Each
expected value was computed independently, re-encoded to DER, and confirmed
with `openssl dgst -sha256 -verify` against the real public key — so the
expectations are anchored to a third-party implementation rather than to our
own output. Known answers, not round-trips: a round-trip can be
self-consistently wrong (an encoder and decoder sharing a padding bug cancel
out).

Covered in each language: a short `r`, a short `s`, both components short, a
high-bit component carrying DER's `0x00` sign byte, the `r=1, s=2` extreme, a
zero component, long-form lengths, an always-64-bytes property check, and
several malformed inputs (empty, truncated, wrong tag, overrunning length,
zero-length INTEGER, trailing bytes) that must fail cleanly rather than read
out of bounds.

### The wire contract

Strings cross the method channel because that is all a channel can carry, but
each language maps wire↔enum in exactly one place (`models.dart`, `Wire.kt`,
`Wire.swift`) and compares on enums everywhere else. Dispatch is an exhaustive
`when`/`switch` with no `else`/`default`, so **adding a member is a compile
error in all three languages**.

An unrecognised wire value is handled deliberately, not incidentally:

| Unknown value | Result | Why |
|---|---|---|
| backing tag | `KeyBacking.software` | Fail-safe. Under-reporting strength is harmless; over-reporting is a false security claim. |
| error code | `SignerErrorCode.unknown`, raw string kept on `rawCode` | Diagnosable rather than flattened into a generic failure. |
| method name | `notImplemented()` | What Flutter expects, and it lets a newer Dart side probe this build. |

The same vectors are asserted in all three suites (`wire_contract_test.dart`,
`WireContractTest.kt`, `WireContractTests.swift`), which is what stops the
three mappings drifting apart.

### Running the tests

```bash
# Dart unit tests (no device) — correctness, ASN.1, wire contract.
flutter test
flutter analyze

# Swift codec tests — pure SwiftPM, no simulator, no Flutter, ~1 second.
cd darwin_tests && swift test

# Kotlin JVM unit tests (DER -> P1363, BigInteger -> coordinate).
cd example/android && ./gradlew :flutter_sign_keypair:testDebugUnitTest

# Swift Flutter-surface tests (method dispatch, argument validation).
# Needs a simulator. If the build fails on a missing `listener.dart`, a previous
# `flutter test integration_test` left a temp entrypoint in Generated.xcconfig —
# run `flutter build ios --simulator --debug --config-only` first.
cd example/ios && xcodebuild test -workspace Runner.xcworkspace -scheme Runner \
  -destination 'platform=iOS Simulator,id=<sim-id>' -only-testing:RunnerTests

# Kotlin instrumented tests (real AndroidKeyStore). Needs a booted device.
cd example/android && ./gradlew :flutter_sign_keypair:connectedDebugAndroidTest

# On-device integration test.
cd example
flutter drive --driver=test_driver/integration_test.dart \
  --target=integration_test/secure_signer_test.dart --profile -d <android-device>
# iOS: profile mode is unsupported on the simulator, so this is debug-only:
flutter test integration_test/secure_signer_test.dart -d <ios-simulator>
```

---

## Design notes

### Why not a fully federated package set?

The federated pattern's real payload is the platform-interface seam, and this
package has it: `SignKeypairPlatform` is a `PlatformInterface`, and an
out-of-tree implementation can register itself by assigning `.instance`.
Splitting into five separately versioned pub packages buys publishing overhead
and cross-package version skew that this package does not need yet. If a third
party ever needs to ship a Windows/Linux backend, the seam is already there.

### DER vs IEEE P1363

Getting this conversion wrong is silent *and intermittent* — the signature is
valid ECDSA and the failure surfaces as an unexplained signature rejection,
roughly 1 time in 256. See [Verification](#der--ieee-p1363-in-all-three-languages)
for how all three implementations are pinned to shared known-answer vectors.

The Swift implementation lives in its own `EcdsaSignatureCodec` type, free of
any Flutter or Security-framework import, precisely so it can be tested
without a simulator.

---

## Origin

This package is a fork of
[`webank_secure_signer`](https://github.com/ADORSYS-GIS/webank-mobile/tree/master/packages/webank_secure_signer)
from [ADORSYS-GIS/webank-mobile](https://github.com/ADORSYS-GIS/webank-mobile),
licensed MIT. It has been renamed and its documentation rewritten to describe
the package on its own terms, independent of the original application it was
built for. Fixes do not flow automatically in either direction between the two
projects.
