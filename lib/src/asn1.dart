import 'dart:typed_data';

/// Conversions between the two ECDSA signature encodings that matter here.
///
/// Every platform ECDSA API in this package (`java.security.Signature`,
/// `SecKeyCreateSignature`) emits **ASN.1 DER** `SEQUENCE { INTEGER r, INTEGER s }`.
/// JWS ES256 (RFC 7515 §3.4 / RFC 7518 §3.4) requires **IEEE P1363** — the two
/// integers as fixed-width 32-byte big-endian values, concatenated, no wrapper.
///
/// Getting this wrong is silent: the signature is valid ECDSA, a JWS
/// verifier rejects it, and the failure looks like an auth bug.
class EcdsaSignatureCodec {
  const EcdsaSignatureCodec._();

  /// Byte width of each P-256 coordinate.
  static const int coordinateLength = 32;

  /// Total length of a P-256 P1363 signature.
  static const int p1363Length = coordinateLength * 2;

  /// Convert a DER-encoded ECDSA signature to IEEE P1363 `r‖s`.
  static Uint8List derToP1363(Uint8List der) {
    int offset = 0;

    int readByte() {
      if (offset >= der.length) {
        throw FormatException('Truncated DER signature at offset $offset');
      }
      return der[offset++];
    }

    if (readByte() != 0x30) {
      throw const FormatException('DER signature does not start with SEQUENCE');
    }

    // Length octet(s) of the SEQUENCE. Short form for anything P-256 emits,
    // but handle the long form so a 0x81-prefixed encoder doesn't break us.
    int seqLength = readByte();
    if (seqLength & 0x80 != 0) {
      final int lengthOctets = seqLength & 0x7f;
      if (lengthOctets == 0 || lengthOctets > 2) {
        throw FormatException(
          'Unsupported DER length form: $lengthOctets octets',
        );
      }
      seqLength = 0;
      for (int i = 0; i < lengthOctets; i++) {
        seqLength = (seqLength << 8) | readByte();
      }
    }
    if (offset + seqLength != der.length) {
      throw FormatException(
        'DER SEQUENCE length $seqLength does not match payload '
        '${der.length - offset}',
      );
    }

    Uint8List readInteger() {
      if (readByte() != 0x02) {
        throw const FormatException('Expected DER INTEGER in ECDSA signature');
      }
      final int length = readByte();
      if (length & 0x80 != 0) {
        throw const FormatException('Unsupported long-form DER INTEGER length');
      }
      if (length == 0) {
        throw const FormatException('Zero-length DER INTEGER');
      }
      if (offset + length > der.length) {
        throw const FormatException('Truncated DER INTEGER');
      }
      final Uint8List value = Uint8List.sublistView(
        der,
        offset,
        offset + length,
      );
      offset += length;
      return value;
    }

    final Uint8List r = readInteger();
    final Uint8List s = readInteger();

    // r and s must account for the entire SEQUENCE. Without this, trailing
    // bytes are silently ignored, which makes the encoding malleable: junk can
    // be appended to produce a different byte string that decodes to the same
    // signature. `openssl asn1parse` rejects such input too.
    if (offset != der.length) {
      throw FormatException(
        '${der.length - offset} trailing byte(s) after s in DER signature',
      );
    }

    final Uint8List out = Uint8List(p1363Length)
      ..setRange(0, coordinateLength, _leftPad(r))
      ..setRange(coordinateLength, p1363Length, _leftPad(s));
    return out;
  }

  /// Convert an IEEE P1363 `r‖s` signature to ASN.1 DER.
  ///
  /// Used to hand a JWS-shaped signature to a DER-only verifier (pointycastle's
  /// verifier takes BigInts, but platform verifiers want DER).
  static Uint8List p1363ToDer(Uint8List p1363) {
    if (p1363.length != p1363Length) {
      throw FormatException(
        'Expected a $p1363Length-byte P1363 signature, got ${p1363.length}',
      );
    }
    final List<int> r = _derInteger(
      Uint8List.sublistView(p1363, 0, coordinateLength),
    );
    final List<int> s = _derInteger(
      Uint8List.sublistView(p1363, coordinateLength, p1363Length),
    );
    final int bodyLength = r.length + s.length;
    if (bodyLength > 0x7f) {
      // Two P-256 integers can reach 0x48 bytes at most, so this is defensive.
      throw StateError('Unexpectedly long DER body: $bodyLength');
    }
    return Uint8List.fromList(<int>[0x30, bodyLength, ...r, ...s]);
  }

  /// Strip leading zeros then left-pad to exactly 32 bytes.
  ///
  /// DER INTEGERs are signed, so a coordinate whose top bit is set carries a
  /// leading 0x00 that must not survive into P1363; conversely a small
  /// coordinate is shorter than 32 bytes and must be zero-extended, not
  /// left-aligned. Both directions have shipped as production bugs elsewhere.
  static Uint8List _leftPad(Uint8List value) {
    int start = 0;
    while (start < value.length - 1 && value[start] == 0) {
      start++;
    }
    final int length = value.length - start;
    if (length > coordinateLength) {
      throw FormatException('ECDSA integer is $length bytes, expected <= 32');
    }
    final Uint8List out = Uint8List(coordinateLength);
    out.setRange(coordinateLength - length, coordinateLength, value, start);
    return out;
  }

  static List<int> _derInteger(Uint8List value) {
    int start = 0;
    while (start < value.length - 1 && value[start] == 0) {
      start++;
    }
    // Growable copy: Uint8List.sublist is fixed-length, so insert() throws.
    final List<int> magnitude = List<int>.of(value.sublist(start));
    // Prepend 0x00 when the high bit is set, so DER does not read it as negative.
    if (magnitude.first & 0x80 != 0) {
      magnitude.insert(0, 0x00);
    }
    return <int>[0x02, magnitude.length, ...magnitude];
  }
}
