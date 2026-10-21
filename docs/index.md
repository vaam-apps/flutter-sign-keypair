---
title: flutter_sign_keypair
layout: home

hero:
  name: flutter_sign_keypair
  text: Device-bound ES256 signing, in hardware
  tagline: A Flutter plugin that generates ECDSA P-256 keys inside AndroidKeyStore or the Apple Secure Enclave and signs there. The private key never enters Dart or app memory.
  image:
    src: /logo.svg
    alt: flutter_sign_keypair
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: How it works
      link: /guide/how-it-works
    - theme: alt
      text: GitHub
      link: https://github.com/vaam-apps/flutter-sign-keypair

features:
  - icon: 🔐
    title: Keys that cannot be extracted
    details: Generated inside StrongBox, the TEE or the Secure Enclave. Dart only ever holds an opaque key id and the public JWK.
    link: /guide/how-it-works
    linkText: What never leaves the device
  - icon: ✍️
    title: Compact JWS in one call
    details: signCompactJws() wraps a JSON payload in a fixed ES256 header and returns header.payload.signature, with the platform's DER signature already converted to the 64-byte form JWS requires.
    link: /guide/verifying
    linkText: Verify on your server
  - icon: 👆
    title: Two keys, two policies
    details: A silent ambient key for every request, and a user-present key that demands a biometric or the device credential on every use.
    link: /guide/how-it-works#the-two-key-model
    linkText: The two-key model
  - icon: 🧭
    title: Honest about its backing
    details: Every key reports where it really lives. Web, Windows and Linux fall back to a pure-Dart signer that says it is software, never hardware.
    link: /guide/platforms
    linkText: Platform notes
---

## At a glance

```dart
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

final signer = SignKeypair();

// Once, at enrolment: both keys, or neither.
final keys = await signer.generateDeviceKeys();
await registerDeviceWithBackend(
  ambient: keys.ambient.publicKey.toJson(), // {crv, kty, x, y}
  userPresent: keys.userPresent.publicKey.toJson(),
);

// On every authenticated request: the ambient key, which never prompts.
final jws = await signer.signCompactJws(payload: <String, dynamic>{
  'timestamp_ms': DateTime.now().millisecondsSinceEpoch,
  'method': 'POST',
  'path': '/v1/payments/transfer',
});
```

`registerDeviceWithBackend` stands for your own enrolment call. The plugin
creates keys and signs with them; registering, checking and revoking keys is
your backend's job.

## Why it exists

A device-bound credential is only as strong as the place its private key
lives. A pure-Dart signer has to load the raw private scalar into the Dart
heap for every signature, where a debugger, a heap dump or a memory-disclosure
bug can read it. This plugin moves both the key and the signing operation into
the platform keystore, so there is nothing in the process to read: on Android
the keystore hands back a key handle whose `getEncoded()` is `null`, and on
both platforms the secure element computes the signature.

## Where it runs

| Platform        | Implementation                                    | Backing it can report          |
| --------------- | ------------------------------------------------- | ------------------------------ |
| Android         | `AndroidKeyStore` + `java.security.Signature`     | `strongBox`, `tee`, `software` |
| iOS             | Security framework, Secure Enclave when available | `secureEnclave`, `keychain`    |
| macOS           | The same Swift source as iOS                      | `secureEnclave`, `keychain`    |
| Web             | Pure-Dart `pointycastle` fallback                 | `software`                     |
| Windows / Linux | Pure-Dart fallback; no native implementation      | `software`                     |

Only `strongBox`, `secureEnclave` and `tee` count as hardware-backed. See
[Platform notes & limitations](/guide/platforms) for the details of each.

::: tip A fork, with credit
`flutter_sign_keypair` is a renamed fork of
[`webank_secure_signer`](https://github.com/ADORSYS-GIS/webank-mobile/tree/master/packages/webank_secure_signer)
from ADORSYS-GIS/webank-mobile, released under the MIT License. See
[About](/about) for the details.
:::
