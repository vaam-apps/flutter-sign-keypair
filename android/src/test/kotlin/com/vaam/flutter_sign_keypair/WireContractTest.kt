package com.vaam.flutter_sign_keypair

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The wire contract, pinned on the Kotlin side.
 *
 * The same vectors are asserted in `test/wire_contract_test.dart` and
 * `darwin_tests/.../WireContractTests.swift`. The mapping is necessarily
 * duplicated once per language, and duplication is what drifts — these tests
 * are what turn a drift into a red build on the side that moved, instead of a
 * runtime failure on one platform only.
 */
class WireContractTest {

    // --- SignerMethod -------------------------------------------------------------

    @Test
    fun `method wire names match the Dart side verbatim`() {
        val expected = mapOf(
            "capabilities" to SignerMethod.CAPABILITIES,
            "generateKey" to SignerMethod.GENERATE_KEY,
            "getKey" to SignerMethod.GET_KEY,
            "sign" to SignerMethod.SIGN,
            "deleteKey" to SignerMethod.DELETE_KEY,
        )
        for ((wire, method) in expected) {
            assertEquals(wire, method.wire, "wire name for $method")
            assertEquals(method, SignerMethod.from(wire), "parse of \"$wire\"")
        }
        assertEquals(
            expected.values.toSet(),
            SignerMethod.entries.toSet(),
            "a SignerMethod was added without a wire vector — update Wire.kt, " +
                "models.dart, Wire.swift and all three test suites",
        )
    }

    @Test
    fun `every method round-trips`() {
        for (method in SignerMethod.entries) {
            assertEquals(method, SignerMethod.from(method.wire))
        }
    }

    @Test
    fun `method wire names are unique`() {
        assertEquals(SignerMethod.entries.size, SignerMethod.entries.map { it.wire }.toSet().size)
    }

    /**
     * An unknown method must parse to null so the plugin can answer
     * `notImplemented()` — the response Flutter expects, and the one that lets a
     * newer Dart side probe for a capability this build does not have.
     */
    @Test
    fun `unknown method names parse to null`() {
        for (wire in listOf("", " ", "nope", "CAPABILITIES", "generate_key", "sign ")) {
            assertNull(SignerMethod.from(wire), "\"$wire\" should not parse")
        }
    }

    // --- KeyBacking ------------------------------------------------------------

    @Test
    fun `backing wire names match the Dart side verbatim`() {
        val expected = mapOf(
            "strongbox" to KeyBacking.STRONGBOX,
            "tee" to KeyBacking.TEE,
            "software" to KeyBacking.SOFTWARE,
        )
        for ((wire, backing) in expected) {
            assertEquals(wire, backing.wire)
            assertEquals(backing, KeyBacking.from(wire))
        }
        assertEquals(expected.values.toSet(), KeyBacking.entries.toSet())
    }

    /**
     * Android never emits these two, but Dart understands them because iOS does.
     * Pinned here so nobody "tidies up" the Dart enum by deleting them.
     */
    @Test
    fun `android does not emit the apple backing tags`() {
        assertNull(KeyBacking.from("secure_enclave"))
        assertNull(KeyBacking.from("keychain"))
    }

    @Test
    fun `every backing round-trips`() {
        for (backing in KeyBacking.entries) {
            assertEquals(backing, KeyBacking.from(backing.wire))
        }
    }

    @Test
    fun `backing wire names are unique`() {
        assertEquals(KeyBacking.entries.size, KeyBacking.entries.map { it.wire }.toSet().size)
    }

    @Test
    fun `unknown backing tags parse to null and are never treated as hardware`() {
        for (wire in listOf("", "quantum", "STRONGBOX", "strong_box", "tee ")) {
            val parsed = KeyBacking.from(wire)
            assertNull(parsed, "\"$wire\" should not parse")
            // The caller's fallback for a null parse is SOFTWARE — fail-safe.
            assertFalse((parsed ?: KeyBacking.SOFTWARE).isHardwareBacked)
        }
    }

    @Test
    fun `only secure-element backings are hardware-backed`() {
        assertTrue(KeyBacking.STRONGBOX.isHardwareBacked)
        assertTrue(KeyBacking.TEE.isHardwareBacked)
        assertFalse(KeyBacking.SOFTWARE.isHardwareBacked)
    }

    // --- KeyProtection ------------------------------------------------------------

    @Test
    fun `protection wire names match the Dart side verbatim`() {
        val expected = mapOf(
            "ambient" to KeyProtection.AMBIENT,
            "user_present" to KeyProtection.USER_PRESENT,
        )
        for ((wire, protection) in expected) {
            assertEquals(wire, protection.wire)
            assertEquals(protection, KeyProtection.from(wire))
        }
        assertEquals(
            expected.values.toSet(),
            KeyProtection.entries.toSet(),
            "a KeyProtection was added without a wire vector — update Wire.kt, " +
                "models.dart, Wire.swift and all three test suites",
        )
    }

    @Test
    fun `every protection round-trips`() {
        for (protection in KeyProtection.entries) {
            assertEquals(protection, KeyProtection.from(protection.wire))
        }
    }

    @Test
    fun `protection wire names are unique`() {
        assertEquals(
            KeyProtection.entries.size,
            KeyProtection.entries.map { it.wire }.toSet().size,
        )
    }

    /**
     * Unlike [KeyBacking], an unparseable protection tag has **no safe
     * fallback** — the caller must fail. Defaulting to AMBIENT would hand a
     * tier-3 caller a key that signs without a human; defaulting to USER_PRESENT
     * would make the request interceptor prompt on every background poll. The
     * policy is baked into the key permanently at creation, so getting it wrong
     * is not recoverable without destroying the key.
     */
    @Test
    fun `unknown protection tags parse to null`() {
        for (wire in listOf("", " ", "AMBIENT", "userPresent", "user-present", "user_present ")) {
            assertNull(KeyProtection.from(wire), "\"$wire\" should not parse")
        }
    }

    @Test
    fun `only the user-present key demands a human`() {
        assertFalse(KeyProtection.AMBIENT.requiresUserPresence)
        assertTrue(KeyProtection.USER_PRESENT.requiresUserPresence)
    }

    // --- SignerErrorCode ----------------------------------------------------------

    @Test
    fun `error code wire names match the Dart side verbatim`() {
        val expected = mapOf(
            "key_not_found" to SignerErrorCode.KEY_NOT_FOUND,
            "key_already_exists" to SignerErrorCode.KEY_ALREADY_EXISTS,
            "hardware_unavailable" to SignerErrorCode.HARDWARE_UNAVAILABLE,
            "keystore_failure" to SignerErrorCode.KEYSTORE_FAILURE,
            "user_authentication_required" to SignerErrorCode.USER_AUTHENTICATION_REQUIRED,
            "user_authentication_cancelled" to SignerErrorCode.USER_AUTHENTICATION_CANCELLED,
            "key_invalidated" to SignerErrorCode.KEY_INVALIDATED,
        )
        for ((wire, code) in expected) {
            assertEquals(wire, code.wire)
            assertEquals(code, SignerErrorCode.from(wire))
        }
        assertEquals(expected.values.toSet(), SignerErrorCode.entries.toSet())
    }

    /**
     * Dart has two extra members. `unsupported_platform` comes from
     * MissingPluginException and `unknown` is the catch-all, so neither is ever
     * emitted from here. Asserted so a future Kotlin addition of either is
     * caught as the contract change it would be.
     */
    @Test
    fun `android does not emit the dart-only codes`() {
        assertNull(SignerErrorCode.from("unsupported_platform"))
        assertNull(SignerErrorCode.from("unknown"))
    }

    @Test
    fun `every error code round-trips`() {
        for (code in SignerErrorCode.entries) {
            assertEquals(code, SignerErrorCode.from(code.wire))
        }
    }

    @Test
    fun `error code wire names are unique`() {
        assertEquals(SignerErrorCode.entries.size, SignerErrorCode.entries.map { it.wire }.toSet().size)
    }

    @Test
    fun `error codes are snake_case and methods are camelCase`() {
        // Not cosmetic: the two conventions differ on purpose, and mixing them
        // is a runtime-only failure on one platform.
        for (code in SignerErrorCode.entries) {
            assertFalse(code.wire.any { it.isUpperCase() }, "${code.wire} is not snake_case")
        }
        for (method in SignerMethod.entries) {
            assertFalse(method.wire.contains('_'), "${method.wire} is not camelCase")
        }
    }

    @Test
    fun `signer errors carry a typed code`() {
        val error = SecureKeyStore.SignerError(SignerErrorCode.KEY_NOT_FOUND, "nope")
        assertEquals(SignerErrorCode.KEY_NOT_FOUND, error.code)
        assertEquals("key_not_found", error.code.wire)
        assertNotNull(error.message)
    }
}
