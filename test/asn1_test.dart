import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_sign_keypair/flutter_sign_keypair.dart';

/// Known-answer tests for DER <-> IEEE P1363.
///
/// DER <-> P1363 is where "valid ECDSA signature the BFF rejects" bugs live, and
/// they are intermittent: DER encodes integers minimally, so a component whose
/// top byte happens to be zero is one byte shorter — roughly 1 signature in 256
/// per component. Code that skips the left-pad works for days, then does not.
///
/// **Provenance of the vectors.** The `real signature` cases are genuine P-256
/// signatures from `openssl dgst -sha256 -sign` over the message
/// `"flutter_sign_keypair known-answer vector"`, selected out of 1200 samples to
/// hit those rare shapes. Each expected P1363 value was computed independently
/// (not by this codec), re-encoded to DER, and confirmed with
/// `openssl dgst -sha256 -verify` against the real public key — so the
/// expectations are anchored to a third-party implementation.
///
/// These are the **same vectors** used by the Kotlin suite
/// (`android/src/test/.../DerToP1363Test.kt`) and the Swift suite
/// (`darwin_tests/.../EcdsaSignatureCodecTests.swift`), which cross-validates
/// all three implementations against one another.
void main() {
  Uint8List hex(String value) => Uint8List.fromList(<int>[
    for (int i = 0; i < value.length; i += 2)
      int.parse(value.substring(i, i + 2), radix: 16),
  ]);

  String toHex(Uint8List bytes) =>
      bytes.map((int b) => b.toRadixString(16).padLeft(2, '0')).join();

  group('derToP1363 — real signatures', () {
    test('short r is left-padded (the ~1-in-256 case)', () {
      final Uint8List der = hex(
        '3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d'
        'f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93',
      );
      const String expected =
          '002952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2df'
          '7d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93';

      final Uint8List actual = EcdsaSignatureCodec.derToP1363(der);

      expect(toHex(actual), expected);
      expect(actual, hasLength(64));
      expect(actual[0], 0x00, reason: 'the pad byte must be at the FRONT of r');
      expect(actual[1], 0x29);
    });

    test('short s is left-padded', () {
      final Uint8List der = hex(
        '3044022007cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0'
        '022000c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52',
      );
      const String expected =
          '07cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0'
          '00c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52';

      final Uint8List actual = EcdsaSignatureCodec.derToP1363(der);

      expect(toHex(actual), expected);
      expect(actual, hasLength(64));
      expect(actual[32], 0x00, reason: 's must be left-padded');
      expect(actual[33], 0xc3);
    });

    test('both components high-bit: both DER sign bytes are stripped', () {
      final Uint8List der = hex(
        '30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90'
        '022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6',
      );
      const String expected =
          '8ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90'
          'bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6';

      final Uint8List actual = EcdsaSignatureCodec.derToP1363(der);

      expect(toHex(actual), expected);
      expect(actual, hasLength(64));
      expect(actual[0], 0x8f, reason: 'sign byte must not survive into r');
      expect(actual[32], 0xbd, reason: 'sign byte must not survive into s');
    });
  });

  group('derToP1363 — synthetic extremes', () {
    test('tiny integers are padded on the left, not the right', () {
      // r = 1, s = 2 — the case where naive code emits 0x01 then 63 zeros.
      final Uint8List actual = EcdsaSignatureCodec.derToP1363(
        hex('3006020101020102'),
      );

      expect(actual, hasLength(64));
      expect(actual.sublist(0, 31), everyElement(0));
      expect(actual[31], 0x01);
      expect(actual.sublist(32, 63), everyElement(0));
      expect(actual[63], 0x02);
    });

    test('both components short at once', () {
      // ~1 in 65 000 real signatures, so an integration test will never see it.
      final List<int> r = List<int>.filled(30, 0xaa);
      final List<int> s = List<int>.filled(29, 0x0b);
      final List<int> body = <int>[0x02, r.length, ...r, 0x02, s.length, ...s];
      final Uint8List der = Uint8List.fromList(<int>[
        0x30,
        body.length,
        ...body,
      ]);

      final Uint8List actual = EcdsaSignatureCodec.derToP1363(der);

      expect(actual, hasLength(64));
      expect(actual.sublist(0, 2), everyElement(0), reason: 'r padded by 2');
      expect(actual[2], 0xaa);
      expect(actual.sublist(32, 35), everyElement(0), reason: 's padded by 3');
      expect(actual[35], 0x0b);
    });

    test('a zero component', () {
      final Uint8List actual = EcdsaSignatureCodec.derToP1363(
        hex('3006020100020101'),
      );

      expect(actual, hasLength(64));
      expect(actual.sublist(0, 32), everyElement(0));
      expect(actual[63], 0x01);
    });

    test('accepts the long-form SEQUENCE length', () {
      final List<int> r = List<int>.filled(32, 0x11);
      final List<int> s = List<int>.filled(32, 0x22);
      final List<int> body = <int>[0x02, 32, ...r, 0x02, 32, ...s];
      final Uint8List der = Uint8List.fromList(<int>[
        0x30,
        0x81,
        body.length,
        ...body,
      ]);

      expect(
        EcdsaSignatureCodec.derToP1363(der),
        Uint8List.fromList(<int>[...r, ...s]),
      );
    });

    test('output is always exactly 64 bytes', () {
      const List<String> inputs = <String>[
        '3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d'
            'f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93',
        '30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90'
            '022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6',
        '3006020101020102',
        '3006020100020100',
      ];
      for (final String input in inputs) {
        expect(
          EcdsaSignatureCodec.derToP1363(hex(input)),
          hasLength(64),
          reason: 'input $input',
        );
      }
    });
  });

  group('derToP1363 — malformed input', () {
    // Must fail cleanly rather than crash or read out of bounds. A RangeError
    // here would mean the bounds check happens after the read, not before.
    const Map<String, String> cases = <String, String>{
      '': 'empty buffer',
      '30': 'SEQUENCE tag with no length',
      '3006': 'length with no body',
      '30060201': 'SEQUENCE length disagrees with the buffer',
      '300602010102': 'truncated before s\'s length',
      '3106020101020102': 'wrong outer tag (SET, not SEQUENCE)',
      '3006030101020102': 'wrong inner tag (BIT STRING, not INTEGER)',
      '3008020101020102': 'declared length overruns the buffer',
      '3004020101020102': 'declared length undershoots the buffer',
      '3006022001020102': 'INTEGER length overruns the buffer',
      '300602810102010201': 'long-form INTEGER length',
      '3006020001020102': 'zero-length INTEGER',
      '300402000200': 'both INTEGERs zero-length (openssl: BAD INTEGER)',
      '3009020101020102aabbcc': 'trailing bytes after s',
    };

    cases.forEach((String input, String description) {
      test('rejects $description', () {
        expect(
          () => EcdsaSignatureCodec.derToP1363(hex(input)),
          throwsFormatException,
          reason: 'input $input',
        );
      });
    });

    test('rejects all-zero-length integers', () {
      // Without an explicit zero-length check this parses as r = 0, s = 0 and
      // returns 64 zero bytes — a bogus signature accepted as valid.
      expect(
        () => EcdsaSignatureCodec.derToP1363(hex('300402000200')),
        throwsFormatException,
      );
    });

    test('rejects an integer wider than 32 bytes', () {
      final List<int> r = List<int>.filled(33, 0x11);
      final List<int> body = <int>[0x02, r.length, ...r, 0x02, 1, 0x01];
      expect(
        () => EcdsaSignatureCodec.derToP1363(
          Uint8List.fromList(<int>[0x30, body.length, ...body]),
        ),
        throwsFormatException,
      );
    });

    test(
      'trailing bytes are rejected — openssl asn1parse rejects the same input',
      () {
        // Silently ignoring them would make the encoding malleable: two
        // distinct byte strings decoding to one signature.
        expect(
          () => EcdsaSignatureCodec.derToP1363(hex('3009020101020102aabbcc')),
          throwsFormatException,
        );
      },
    );
  });

  group('p1363ToDer', () {
    test('rejects a signature that is not 64 bytes', () {
      for (final int length in <int>[0, 63, 65, 128]) {
        expect(
          () => EcdsaSignatureCodec.p1363ToDer(Uint8List(length)),
          throwsFormatException,
          reason: 'length $length',
        );
      }
    });

    test('prepends a sign byte when the high bit is set', () {
      final Uint8List p1363 = Uint8List(64)
        ..setRange(0, 32, List<int>.filled(32, 0xff))
        ..setRange(32, 64, List<int>.filled(32, 0x01));

      final Uint8List der = EcdsaSignatureCodec.p1363ToDer(p1363);

      expect(der[0], 0x30);
      expect(der[2], 0x02);
      expect(der[3], 33, reason: 'r must carry a 0x00 sign byte');
      expect(der[4], 0x00);
    });

    test('round-trips the real signature vectors', () {
      const List<String> vectors = <String>[
        '3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d'
            'f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93',
        '30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90'
            '022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6',
      ];
      for (final String vector in vectors) {
        final Uint8List p1363 = EcdsaSignatureCodec.derToP1363(hex(vector));
        final Uint8List reencoded = EcdsaSignatureCodec.p1363ToDer(p1363);
        expect(EcdsaSignatureCodec.derToP1363(reencoded), p1363);
      }
    });

    test('round-trips a coordinate that is all zeros but one byte', () {
      final Uint8List p1363 = Uint8List(64)
        ..[31] = 0x07
        ..[63] = 0x80;
      expect(
        EcdsaSignatureCodec.derToP1363(EcdsaSignatureCodec.p1363ToDer(p1363)),
        p1363,
      );
    });
  });
}
