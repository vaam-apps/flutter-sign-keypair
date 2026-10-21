# Errors

Every failure from a backend reaches your code as a `SecureSignerException`.
Switch on its `code`:

```dart
try {
  final jws = await signer.signCompactJws(
    keyId: SignKeypair.defaultUserPresentKeyId,
    reason: 'Confirm this transfer',
    payload: payload,
  );
  await submit(jws);
} on SecureSignerException catch (e) {
  switch (e.code) {
    case SignerErrorCode.userAuthenticationCancelled:
      return; // The person changed their mind. Do nothing.
    case SignerErrorCode.userAuthenticationRequired:
      showSetUpScreenLockHint(); // Recoverable in the device's Settings.
    case SignerErrorCode.keyInvalidated:
      await reEnrolUserPresentKey(); // Not a logout, not a full re-enrolment.
    default:
      log.warning('signing failed: $e (raw code ${e.rawCode})');
  }
}
```

`showSetUpScreenLockHint`, `reEnrolUserPresentKey` and `submit` stand for your
own code.

## The exception

| Member    | Type              | Meaning                                                                                    |
| --------- | ----------------- | ------------------------------------------------------------------------------------------ |
| `code`    | `SignerErrorCode` | The reason, to switch on                                                                   |
| `rawCode` | `String`          | The code exactly as the platform sent it; the unrecognised string when `code` is `unknown` |
| `message` | `String`          | A human-readable explanation, safe to log: it never contains key material                  |
| `details` | `Object?`         | An optional platform-specific payload                                                      |

## The codes

| Code                          | Wire string                     | What it means                                                                                                |
| ----------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `keyNotFound`                 | `key_not_found`                 | Signing with a key id that has no key                                                                        |
| `keyAlreadyExists`            | `key_already_exists`            | Generating under an id that already has a key, without `overwrite: true`                                     |
| `hardwareUnavailable`         | `hardware_unavailable`          | `requireHardware: true` on a device without a secure element, or a user-present key on the software fallback |
| `keystoreFailure`             | `keystore_failure`              | The platform keystore refused, or something else went wrong natively                                         |
| `userAuthenticationRequired`  | `user_authentication_required`  | A user-present key, but nothing to authenticate the person against right now                                 |
| `userAuthenticationCancelled` | `user_authentication_cancelled` | The person dismissed the prompt, or it timed out                                                             |
| `keyInvalidated`              | `key_invalidated`               | The key was permanently destroyed by a change to biometrics or the screen lock (Android)                     |
| `unsupportedPlatform`         | `unsupported_platform`          | No native implementation is registered for this platform                                                     |
| `unknown`                     | `unknown`                       | A code this Dart side does not recognise; read `rawCode`                                                     |

`getKey` does not throw for a missing key: it returns `null`. Neither does
`deleteKey`, which is a no-op for a missing key.

## Where each code comes from

### `userAuthenticationCancelled`

A person changing their mind at a confirmation screen. Treat it as a cancelled
action, never as a reason to re-enrol or log out.

- **Android:** `BiometricPrompt` errors `ERROR_NEGATIVE_BUTTON`,
  `ERROR_USER_CANCELED`, `ERROR_CANCELED` and `ERROR_TIMEOUT`.
- **iOS / macOS:** `LAError` `userCancel`, `appCancel`, `systemCancel` and
  `userFallback`, and the keychain's `errSecUserCanceled`.

### `userAuthenticationRequired`

- **Generating a user-present key** on a device with nothing to authenticate
  against: no secure lock screen on Android (`KeyguardManager.isDeviceSecure`),
  no passcode or biometric on iOS and macOS. The check runs before anything is
  deleted, so an existing key survives it.
- **Android, while signing:** `BiometricPrompt` errors `ERROR_NO_BIOMETRICS`,
  `ERROR_NO_DEVICE_CREDENTIAL`, `ERROR_HW_NOT_PRESENT`, `ERROR_HW_UNAVAILABLE`,
  `ERROR_LOCKOUT` and `ERROR_LOCKOUT_PERMANENT`.
- **iOS / macOS, while signing:** `LAError` `passcodeNotSet`,
  `biometryNotEnrolled`, `biometryNotAvailable` and `biometryLockout`; and
  `errSecInteractionNotAllowed`, which is what a user-present key reached from
  the background produces. That last one is a bug in the calling code: sign
  with the user-present key only while the app is in front of the person.

Note that a biometric lockout lands here too, so "go to Settings" is not
always the right message: the person may only need to wait or use their
device credential.

### `keyInvalidated`

Raised on Android when starting a signature throws
`KeyPermanentlyInvalidatedException`: the keystore destroyed the key because
the device's biometric enrolment or screen lock changed. The ambient key is
not affected, so the device can still authenticate itself while it recovers.
Recovery is narrow: generate a fresh user-present key with `overwrite: true`
and register its public key. It is not a reason for a full re-enrolment or a
logout.

The iOS and macOS code has no path that produces this code; see
[Platform notes](./platforms#ios-and-macos) for what happens there instead.

### `hardwareUnavailable`

- `requireHardware: true` where the best available backing is not
  hardware-backed. On Android the plugin also deletes and refuses a key that
  came out software-backed despite the device advertising hardware.
- The software fallback asked for a user-present key, or for hardware.

### `keystoreFailure`

The catch-all for native failures. Besides keystore errors, it is what you get
for:

- a user-present signature on Android when the activity is not a
  `FragmentActivity` (see [Getting started](./getting-started#android));
- a user-present key on Android 7.0 to 10 (API 24 to 29) on a device with only
  a PIN, pattern or password, because the key is biometric-only there and key
  generation itself throws;
- a native call that returned nothing, or a native signature that is not 64
  bytes;
- an unrecognised protection tag (a mismatched Dart and native build).

### `unsupportedPlatform`

Raised by `MethodChannelSignKeypair` when no native plugin answers the channel
(Flutter's `MissingPluginException`). With the default backend selection this
should not happen, since platforms without native code get the software
signer.

### `unknown`

A code from a newer native build, or a `PlatformException` raised by something
other than this plugin. The original string is kept in `rawCode`, which is the
thing to put in a bug report.

## Errors that are not `SecureSignerException`

Argument errors in pure Dart throw the usual Dart exceptions:

| Call                                                   | Throws            | When                                             |
| ------------------------------------------------------ | ----------------- | ------------------------------------------------ |
| `EcPublicJwk.fromCoordinates`                          | `ArgumentError`   | a coordinate is not 32 bytes                     |
| `EcPublicJwk.fromJson`                                 | `FormatException` | not an EC P-256 JWK with string `x` and `y`      |
| `SoftwareSecureSigner.importKey`                       | `ArgumentError`   | the scalar is not 32 bytes, or out of range      |
| `EcdsaSignatureCodec.derToP1363` / `p1363ToDer`        | `FormatException` | malformed or wrong-length input                  |
| `SignKeypairPlatform.instance` before one is installed | `StateError`      | use the `SignKeypair` facade, which installs one |
