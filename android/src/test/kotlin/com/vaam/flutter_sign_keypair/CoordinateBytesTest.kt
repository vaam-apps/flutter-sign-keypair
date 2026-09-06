package com.vaam.flutter_sign_keypair

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Tests for the BigInteger -> 32-byte coordinate conversion behind the public JWK.
 *
 * Same bug class as DER -> P1363, different blast radius. `derToP1363` getting
 * padding wrong breaks one signature; `coordinateBytes` getting it wrong
 * corrupts the public key registered with the BFF, so *every* signature that
 * device ever makes is rejected — and the error points at signing, not at the
 * key. Both failure modes are intermittent for the same reason: they depend on
 * whether a randomly generated coordinate happens to have a high or low top byte.
 */
class CoordinateBytesTest {

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun `a high-bit coordinate drops BigInteger's sign byte`() {
        // toByteArray() returns 33 bytes: 0x00 followed by the 32 real ones.
        val hex = "ff" + "11".repeat(31)
        val value = BigInteger(hex, 16)
        assertEquals(33, value.toByteArray().size, "precondition: sign byte present")

        val actual = FlutterSignKeypairPlugin.coordinateBytes(value)

        assertEquals(32, actual.size)
        assertEquals(hex, actual.toHex())
        assertEquals(0xff, actual[0].toInt() and 0xff, "the sign byte must not survive")
    }

    @Test
    fun `a short coordinate is padded on the left`() {
        // A coordinate below 2^248 — ~1 in 256 keys. Its top significant byte
        // must have the high bit CLEAR, otherwise BigInteger adds a sign byte
        // and toByteArray() is 32 bytes again rather than 31.
        val value = BigInteger("2a" + "22".repeat(30), 16)
        assertEquals(31, value.toByteArray().size, "precondition: 31 significant bytes")

        val actual = FlutterSignKeypairPlugin.coordinateBytes(value)

        assertEquals(32, actual.size)
        assertEquals("002a" + "22".repeat(30), actual.toHex())
        assertEquals(0x00, actual[0].toInt(), "the pad must be at the FRONT")
        assertEquals(0x2a, actual[1].toInt())
    }

    /**
     * 30 significant bytes AND a high top bit: `toByteArray()` returns 31 bytes
     * (sign byte + 30). The sign byte is kept here, but it lands inside the pad
     * region, so the numeric value is still right — worth pinning, because the
     * "strip the sign byte" reflex would corrupt it.
     */
    @Test
    fun `a short high-bit coordinate keeps its value`() {
        val value = BigInteger("aa" + "22".repeat(29), 16)
        assertEquals(31, value.toByteArray().size, "precondition: sign byte + 30 bytes")

        val actual = FlutterSignKeypairPlugin.coordinateBytes(value)

        assertEquals(32, actual.size)
        assertEquals("0000aa" + "22".repeat(29), actual.toHex())
        assertEquals(value, BigInteger(1, actual), "round-trips to the same integer")
    }

    @Test
    fun `an exactly-32-byte coordinate is unchanged`() {
        val hex = "7f" + "33".repeat(31)
        val actual = FlutterSignKeypairPlugin.coordinateBytes(BigInteger(hex, 16))

        assertEquals(32, actual.size)
        assertEquals(hex, actual.toHex())
    }

    @Test
    fun `a tiny coordinate is padded to the full width`() {
        val actual = FlutterSignKeypairPlugin.coordinateBytes(BigInteger.ONE)

        assertEquals(32, actual.size)
        assertContentEquals(ByteArray(31), actual.copyOfRange(0, 31))
        assertEquals(1, actual[31].toInt())
    }

    @Test
    fun `zero is all zeros`() {
        val actual = FlutterSignKeypairPlugin.coordinateBytes(BigInteger.ZERO)

        assertEquals(32, actual.size)
        assertContentEquals(ByteArray(32), actual)
    }

    @Test
    fun `output is always exactly 32 bytes`() {
        val values = listOf(
            BigInteger.ZERO,
            BigInteger.ONE,
            BigInteger("00aa" + "22".repeat(30), 16),
            BigInteger("7f" + "33".repeat(31), 16),
            BigInteger("ff" + "11".repeat(31), 16),
        )
        for (value in values) {
            assertEquals(32, FlutterSignKeypairPlugin.coordinateBytes(value).size, "$value")
        }
    }
}
