#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_sign_keypair.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_sign_keypair'
  s.version          = '0.1.0'
  s.summary          = 'Hardware-backed ES256 signing for device-bound authentication.'
  s.description      = <<-DESC
Generates and uses an EC P-256 key inside the Secure Enclave (or the
data-protection keychain when the enclave is unavailable) so the private scalar
never enters app memory. Emits IEEE P1363 signatures for JWS ES256.
                       DESC
  s.homepage         = 'https://github.com/vaam-apps/flutter-sign-keypair'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Vaam' => 'oss@vaam.app' }

  s.source           = { :path => '.' }
  s.source_files = 'flutter_sign_keypair/Sources/flutter_sign_keypair/**/*'

  # If your plugin requires a privacy manifest, for example if it collects user
  # data, update the PrivacyInfo.xcprivacy file to describe your plugin's
  # privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'flutter_sign_keypair_privacy' => ['flutter_sign_keypair/Sources/flutter_sign_keypair/PrivacyInfo.xcprivacy']}

  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
