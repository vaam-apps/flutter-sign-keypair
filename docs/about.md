# About

## Origin

`flutter_sign_keypair` is a fork of
[`webank_secure_signer`](https://github.com/ADORSYS-GIS/webank-mobile/tree/master/packages/webank_secure_signer),
a package in [ADORSYS-GIS/webank-mobile](https://github.com/ADORSYS-GIS/webank-mobile),
which is licensed MIT. Version 0.1.0 of this package was a rebranded fork of
that package's 0.2.0 release.

The fork renamed the default key ids, the Android package id
(`com.vaam.flutter_sign_keypair`), the method channel
(`com.vaam/flutter_sign_keypair`) and every source-branded class; the public
classes are `SignKeypair`, `SignKeypairPlatform`, `MethodChannelSignKeypair`
and `FlutterSignKeypairPlugin`. Its documentation was rewritten to describe the
package on its own terms, independent of the application it was first built
for. The signing behaviour itself was carried over unchanged.

Fixes do not flow automatically in either direction between the two projects.

A few traces of that origin remain on purpose: the Android biometric prompt's
default copy is French ("Authentification requise", "Annuler"), and the test
suite pins the package's JWS output byte for byte against a reference signer
carried over from the original application.

## License

Released under the [MIT License](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/LICENSE):

- Copyright (c) 2026 ADORSYS GIS
- Copyright (c) 2026 Vaam

Keep both notices if you redistribute the code.

## Sibling project

[`tauri-sign-keypair`](https://github.com/vaam-apps/tauri-sign-keypair) brings
the same hardware-backed ES256 signing to Tauri v2 apps, via AndroidKeyStore
and the Apple Secure Enclave. It is a port of this plugin.

## Releases

Versions are cut by release-please from conventional commits and tagged
`vX.Y.Z`. What changed in each release is in the
[changelog](https://github.com/vaam-apps/flutter-sign-keypair/blob/main/CHANGELOG.md).

## Contributing

Issues and pull requests go to
[vaam-apps/flutter-sign-keypair](https://github.com/vaam-apps/flutter-sign-keypair).
Pull request titles must be conventional commits (`feat:`, `fix:`, `docs:` and
so on), because the repository squash-merges and release-please reads the
title to decide the next version. Run the tests on
[Testing & proof](/guide/testing) before you open one.
