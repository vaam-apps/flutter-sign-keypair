# Getting started

This page takes you from an empty `pubspec.yaml` to a signed request. Read
[How it works](./how-it-works) next if you want to know why the API looks the
way it does.

## Requirements

These come straight from the plugin's own build files:

| What              | Minimum  | Where it is set                               |
| ----------------- | -------- | --------------------------------------------- |
| Dart SDK          | `3.12.0` | `pubspec.yaml` (`>=3.12.0 <4.0.0`)            |
| Flutter           | `3.3.0`  | `pubspec.yaml`                                |
| Android           | API 24   | `android/build.gradle.kts` (`minSdk = 24`)    |
| Android toolchain | Java 17  | `android/build.gradle.kts`, `compileSdk = 36` |
| iOS               | 15.0     | `ios/flutter_sign_keypair.podspec`            |
| macOS             | 10.15    | `macos/flutter_sign_keypair.podspec`          |

Web, Windows and Linux need nothing extra: they use the pure-Dart fallback
signer (see [Platform notes](./platforms#web-windows-and-linux)).

## Install

The package is not published to pub.dev (`publish_to: 'none'` in its
`pubspec.yaml`), so depend on it from Git. Releases are tagged `vX.Y.Z`;
pin a tag rather than a branch:

```yaml
dependencies:
  flutter_sign_keypair:
    git:
      url: https://github.com/vaam-apps/flutter-sign-keypair.git
      ref: v0.1.2
```

Then fetch it:

```bash
flutter pub get
```

The plugin's only runtime dependencies are `plugin_platform_interface` and
`pointycastle` (for the software fallback). On Android it adds
`androidx.biometric:biometric` to raise the authentication prompt.

## Platform setup

### Android

Nothing is needed for **ambient** keys, the ones that never prompt.

For **user-present** keys the plugin shows a `BiometricPrompt`, and that
prompt needs a `FragmentActivity` to attach to. The plugin only accepts an
activity of that type, so with Flutter's default `FlutterActivity` signing with
a user-present key fails with `SignerErrorCode.keystoreFailure` ("A
user-present key needs a foreground Activity to show the authentication
prompt, and none is attached"). Make your `MainActivity` extend
`FlutterFragmentActivity`:

```kotlin
package com.example.app

import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity : FlutterFragmentActivity()
```

::: info The example app
The repository's example app keeps the default `FlutterActivity`, because it
only uses the ambient key.
:::

A user-present key also needs a secure lock screen (a PIN, pattern or
password; the plugin checks `KeyguardManager.isDeviceSecure`). Without one,
`generateKey` refuses with `userAuthenticationRequired`. On Android 7.0 to 10 (API 24 to 29) the
user-present key is biometric-only; see
[Platform notes](./platforms#android).

### iOS

Nothing is needed for ambient keys.

User-present keys prompt through the system's biometric or passcode sheet,
which the plugin captions with the `reason` you pass to the signing call.

::: tip Face ID
Apple requires an `NSFaceIDUsageDescription` entry in the app's `Info.plist`
for any app that uses Face ID. If you sign with user-present keys on Face ID
devices, add one. The example app does not declare it, because it never uses
a user-present key.
:::

The Secure Enclave is not available on the iOS Simulator. There, keys are
created as ordinary keychain keys and report `KeyBacking.keychain`, which does
**not** count as hardware-backed.

### macOS

macOS uses the same Swift source as iOS (the macOS plugin files are symlinks to
the iOS ones). Keys are stored in the data-protection keychain, and they live
in the Secure Enclave on Macs that have one. On a Mac without one, keys report
`KeyBacking.keychain`.

### Web, Windows and Linux

There is no native code to set up. These platforms use `SoftwareSecureSigner`,
whose keys report `KeyBacking.software`. Its default key store is **in memory
and does not survive a restart**; inject a persistent `SoftwareKeyStore` if
you need durable keys there (see [the API overview](./api#software-fallback)).
User-present keys are not available on these platforms at all: the fallback
refuses to create one (`hardwareUnavailable`), and so `generateDeviceKeys()`
always fails there. Use `generateKey()` for the ambient key alone.

## First signature

```dart
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

Future<void> enrolAndSign() async {
  final signer = SignKeypair();

  // Probe once at startup and log it.
  final caps = await signer.capabilities();
  print(caps); // e.g. SignerCapabilities(platform: android, bestAvailableBacking: trustedExecutionEnvironment)

  // Enrol: create both keys of the two-key model as one unit.
  final keys = await signer.generateDeviceKeys();
  if (!keys.isHardwareBacked) {
    // Not an error: the fallback working as designed. Worth logging.
    print('a device key is software-backed');
  }

  // Send both public keys (JWKs) to your backend.
  final ambientJwk = keys.ambient.publicKey.toJson();
  final userPresentJwk = keys.userPresent.publicKey.toJson();

  // Every request: sign with the ambient key. Never prompts.
  final jws = await signer.signCompactJws(
    payload: <String, dynamic>{
      'timestamp_ms': DateTime.now().millisecondsSinceEpoch,
      'method': 'GET',
      'path': '/v1/accounts/balance',
    },
  );

  // A sensitive action: sign with the user-present key. Prompts every time,
  // so pass your own localized reason.
  final confirmed = await signer.signCompactJws(
    keyId: SignKeypair.defaultUserPresentKeyId,
    reason: 'Confirm this transfer',
    payload: <String, dynamic>{'amount': 100},
  );
}
```

::: warning Always pass `reason` for user-present keys
On Android, a user-present signature without a `reason` shows the plugin's
default prompt copy, which is French: the title "Authentification requise"
and, on Android 7 to 10, a cancel button "Annuler". On iOS and macOS the system
shows its own generic text instead. Treat seeing either in production as a
bug.
:::

If the device cannot make the user-present key (no screen lock, no biometric,
or the fallback signer), `generateDeviceKeys` throws and removes the ambient
key it has just created, so the device is not left half-enrolled. To demand
hardware and fail otherwise, pass `requireHardware: true`. Both behaviours are
described in [How it works](./how-it-works#enrolment-both-keys-or-neither).

## Next steps

- [How it works](./how-it-works): what lives where, and what the signature
  looks like.
- [Verifying signatures](./verifying): what your backend has to check.
- [Errors](./errors): which failures to expect and how to handle each.
- The [example app](https://github.com/vaam-apps/flutter-sign-keypair/tree/main/example)
  has buttons for capabilities, generate, sign and delete.
