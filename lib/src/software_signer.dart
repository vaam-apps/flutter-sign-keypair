import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'models.dart';
import 'platform_interface.dart';

/// Persistence seam for [SoftwareSecureSigner].
///
/// Deliberately not tied to `flutter_secure_storage`: this package stays
/// dependency-light, and the embedding app already owns a secure store. The
/// default [InMemorySoftwareKeyStore] does **not** survive a restart — a web
/// app that needs durable keys must inject its own store.
abstract class SoftwareKeyStore {
  /// Read the stored record for [keyId], or `null`.
  Future<String?> read(String keyId);

  /// Write (or overwrite) the record for [keyId].
  Future<void> write(String keyId, String value);

  /// Delete the record for [keyId]. Deleting a missing key is a no-op.
  Future<void> delete(String keyId);
}

/// Process-lifetime key store. Fine for tests; not durable.
class InMemorySoftwareKeyStore implements SoftwareKeyStore {
  final Map<String, String> _entries = <String, String>{};

  @override
  Future<String?> read(String keyId) async => _entries[keyId];

  @override
  Future<void> write(String keyId, String value) async {
    _entries[keyId] = value;
  }

  @override
  Future<void> delete(String keyId) async {
    _entries.remove(keyId);
  }
}

/// Pure-Dart ES256 signer. The fallback, and only the fallback.
///
/// The private scalar lives in Dart heap memory, so it is extractable by
/// anything that can read the process — which is exactly why every key this
/// signer produces reports [KeyBacking.software]. That flag is the API's whole
/// point: callers can see they are on the degraded path instead of assuming
/// hardware protection they do not have.
///
/// Signing uses RFC 6979 deterministic `k` (HMAC-SHA256). That is not a
/// stylistic choice: pointycastle's default `SecureRandom()` resolves through
/// its algorithm registry and throws `RegistryFactoryException` at runtime
/// with no registered name unless the caller registers one first.
class SoftwareSecureSigner extends SignKeypairPlatform {
  SoftwareSecureSigner({SoftwareKeyStore? store, Random? random})
    : _store = store ?? InMemorySoftwareKeyStore(),
      _random = random ?? Random.secure();

  final SoftwareKeyStore _store;
  final Random _random;

  /// Cached parsed keys, so a hot signing path does not re-parse per call.
  final Map<String, _SoftwareKeyRecord> _cache = <String, _SoftwareKeyRecord>{};

  static final pc.ECDomainParameters _domain = pc.ECDomainParameters(
    'prime256v1',
  );

  @override
  Future<SignerCapabilities> capabilities() async => const SignerCapabilities(
    platform: 'dart-software',
    bestAvailableBacking: KeyBacking.software,
  );

  @override
  Future<SecureKey> generateKey({
    required String keyId,
    required bool requireHardware,
    required bool overwrite,
    required KeyProtection protection,
  }) async {
    if (requireHardware) {
      throw SecureSignerException(
        SignerErrorCode.hardwareUnavailable,
        'The pure-Dart fallback signer cannot produce a hardware-backed key',
      );
    }
    // Refuse, rather than issue a key that answers to the name.
    //
    // There is no secure element here to withhold a signature, and no platform
    // prompt to raise — the scalar sits in Dart heap memory and `sign()` would
    // return happily with no human anywhere near the device. Handing that back
    // as a user-present key would make every downstream check that compares
    // protection against key id (an audit log, a risk score, a backend that
    // requires the prompting key for a sensitive operation) assert something
    // untrue about how the signature was produced.
    //
    // The practical consequence is that a platform without a secure element
    // cannot do user-present operations at all. That is the correct outcome:
    // a degraded target, not a quietly-equivalent one.
    if (protection.requiresUserPresence) {
      throw SecureSignerException(
        SignerErrorCode.hardwareUnavailable,
        'The pure-Dart fallback signer cannot enforce user presence — '
        'user-present operations require a device with a secure element',
      );
    }
    if (!overwrite && await _store.read(keyId) != null) {
      throw SecureSignerException(
        SignerErrorCode.keyAlreadyExists,
        'A software key already exists under "$keyId"',
      );
    }

    final Uint8List seed = Uint8List.fromList(
      List<int>.generate(32, (_) => _random.nextInt(256)),
    );
    final pc.FortunaRandom secureRandom = pc.FortunaRandom()
      ..seed(pc.KeyParameter(seed));
    final pc.ECKeyGenerator generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(_domain),
          secureRandom,
        ),
      );

    final pc.AsymmetricKeyPair<pc.PublicKey, pc.PrivateKey> pair = generator
        .generateKeyPair();
    final pc.ECPrivateKey private = pair.privateKey as pc.ECPrivateKey;
    final pc.ECPublicKey public = pair.publicKey as pc.ECPublicKey;

    final _SoftwareKeyRecord record = _SoftwareKeyRecord(
      d: _bigIntTo32Bytes(private.d!),
      x: _bigIntTo32Bytes(public.Q!.x!.toBigInteger()!),
      y: _bigIntTo32Bytes(public.Q!.y!.toBigInteger()!),
    );

    await _store.write(keyId, record.encode());
    _cache[keyId] = record;
    return _toSecureKey(keyId, record);
  }

  /// Adopt an existing raw P-256 private scalar under [keyId].
  ///
  /// This exists for one reason: migrating devices that already registered a
  /// key with the app's old `KeyManager`, whose scalar sits in secure storage.
  /// An imported key is by definition already extractable, so it is stored and
  /// reported as [KeyBacking.software] — importing into StrongBox or the Secure
  /// Enclave is not possible, and pretending otherwise would be a lie.
  Future<SecureKey> importKey({
    required String keyId,
    required Uint8List privateScalar,
    bool overwrite = false,
  }) async {
    if (privateScalar.length != 32) {
      throw ArgumentError(
        'A P-256 private scalar is 32 bytes, got ${privateScalar.length}',
      );
    }
    if (!overwrite && await _store.read(keyId) != null) {
      throw SecureSignerException(
        SignerErrorCode.keyAlreadyExists,
        'A software key already exists under "$keyId"',
      );
    }

    final BigInt d = _bytesToBigInt(privateScalar);
    if (d <= BigInt.zero || d >= _domain.n) {
      throw ArgumentError('Private scalar is out of range for P-256');
    }
    final pc.ECPoint q = (_domain.G * d)!;

    final _SoftwareKeyRecord record = _SoftwareKeyRecord(
      d: privateScalar,
      x: _bigIntTo32Bytes(q.x!.toBigInteger()!),
      y: _bigIntTo32Bytes(q.y!.toBigInteger()!),
    );
    await _store.write(keyId, record.encode());
    _cache[keyId] = record;
    return _toSecureKey(keyId, record);
  }

  @override
  Future<SecureKey?> getKey(String keyId) async {
    final _SoftwareKeyRecord? record = await _load(keyId);
    if (record == null) return null;
    return _toSecureKey(keyId, record);
  }

  @override
  Future<Uint8List> sign({
    required String keyId,
    required Uint8List payload,
    // Accepted and ignored: this signer never holds a user-present key (see
    // generateKey), so there is no prompt for a reason string to caption.
    String? reason,
  }) async {
    final _SoftwareKeyRecord? record = await _load(keyId);
    if (record == null) {
      throw SecureSignerException(
        SignerErrorCode.keyNotFound,
        'No software key stored under "$keyId"',
      );
    }

    final pc.ECPrivateKey private = pc.ECPrivateKey(
      _bytesToBigInt(record.d),
      _domain,
    );
    final pc.ECDSASigner signer = pc.ECDSASigner(
      pc.SHA256Digest(),
      pc.HMac(pc.SHA256Digest(), 64),
    )..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(private));
    final pc.ECSignature signature =
        signer.generateSignature(payload) as pc.ECSignature;

    // JWS ES256 is IEEE P1363: r‖s, 32 bytes each, no ASN.1 wrapper.
    final Uint8List out = Uint8List(64)
      ..setRange(0, 32, _bigIntTo32Bytes(signature.r))
      ..setRange(32, 64, _bigIntTo32Bytes(signature.s));
    return out;
  }

  @override
  Future<void> deleteKey(String keyId) async {
    _cache.remove(keyId);
    await _store.delete(keyId);
  }

  Future<_SoftwareKeyRecord?> _load(String keyId) async {
    final _SoftwareKeyRecord? cached = _cache[keyId];
    if (cached != null) return cached;
    final String? raw = await _store.read(keyId);
    if (raw == null) return null;
    return _cache[keyId] = _SoftwareKeyRecord.decode(raw);
  }

  static SecureKey _toSecureKey(String keyId, _SoftwareKeyRecord record) =>
      SecureKey(
        keyId: keyId,
        publicKey: EcPublicJwk.fromCoordinates(x: record.x, y: record.y),
        backing: KeyBacking.software,
      );

  static Uint8List _bigIntTo32Bytes(BigInt value) {
    final Uint8List out = Uint8List(32);
    BigInt remaining = value;
    final BigInt mask = BigInt.from(0xff);
    for (int i = 31; i >= 0 && remaining > BigInt.zero; i--) {
      out[i] = (remaining & mask).toInt();
      remaining = remaining >> 8;
    }
    return out;
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (final int byte in bytes) {
      result = (result << 8) | BigInt.from(byte);
    }
    return result;
  }
}

/// The serialised form of a software key: `d`, `x`, `y` as unpadded base64url.
class _SoftwareKeyRecord {
  const _SoftwareKeyRecord({required this.d, required this.x, required this.y});

  factory _SoftwareKeyRecord.decode(String raw) {
    final Object? decoded = jsonDecode(raw);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException('Corrupt software key record');
    }
    return _SoftwareKeyRecord(
      d: _b64uDecode(decoded['d'] as String),
      x: _b64uDecode(decoded['x'] as String),
      y: _b64uDecode(decoded['y'] as String),
    );
  }

  final Uint8List d;
  final Uint8List x;
  final Uint8List y;

  String encode() =>
      jsonEncode(<String, String>{'d': _b64u(d), 'x': _b64u(x), 'y': _b64u(y)});

  static String _b64u(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static Uint8List _b64uDecode(String value) =>
      base64Url.decode(value.padRight((value.length + 3) & ~3, '='));
}
