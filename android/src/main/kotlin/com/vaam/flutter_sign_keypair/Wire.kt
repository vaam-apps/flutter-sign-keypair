package com.vaam.flutter_sign_keypair

/**
 * The wire vocabulary shared with the Dart side, as enums.
 *
 * A method channel can only carry primitives, so strings do cross the wire.
 * What this file buys is that each string is written in exactly **one** place
 * and parsed in exactly one place; every comparison in the rest of the module
 * is on an enum. Adding a member here is then a compile error at each
 * exhaustive `when` rather than a silent fallthrough.
 *
 * These must stay in step with `lib/src/models.dart` (KeyBacking,
 * SignerErrorCode) and `lib/src/method_channel_signer.dart` (SignerMethod).
 * `WireContractTest` pins the exact strings so a rename on one side cannot
 * drift past review.
 */

/** A method the plugin's channel understands. */
internal enum class SignerMethod(val wire: String) {
    CAPABILITIES("capabilities"),
    GENERATE_KEY("generateKey"),
    GET_KEY("getKey"),
    SIGN("sign"),
    DELETE_KEY("deleteKey"),
    ;

    companion object {
        /**
         * Parse a method name, or null when it is not one of ours.
         *
         * Null rather than a throw: the caller answers `notImplemented()`, which
         * is what Flutter expects for an unknown method and what lets a newer
         * Dart side probe for a capability this build does not have.
         */
        fun from(wire: String): SignerMethod? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * Where a private key lives, strongest first.
 *
 * [SOFTWARE] is the floor and the safe default: under-reporting strength is
 * harmless, over-reporting is a false security claim.
 */
internal enum class KeyBacking(val wire: String) {
    STRONGBOX("strongbox"),
    TEE("tee"),
    SOFTWARE("software"),
    ;

    /** True when the key cannot be read out of the device. */
    val isHardwareBacked: Boolean
        get() = when (this) {
            STRONGBOX, TEE -> true
            SOFTWARE -> false
        }

    companion object {
        fun from(wire: String): KeyBacking? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * What the keystore demands before it signs (ADR 0024).
 *
 * Unlike [KeyBacking] this has **no safe default**: answering [AMBIENT] for an
 * unrecognised tag would hand a caller who asked for tier-3 protection a key
 * that signs silently, and answering [USER_PRESENT] would make the Dio
 * interceptor prompt on every background poll. [from] therefore returns null and
 * the call fails.
 */
internal enum class KeyProtection(val wire: String) {
    AMBIENT("ambient"),
    USER_PRESENT("user_present"),
    ;

    /** Whether the keystore will demand authentication before signing. */
    val requiresUserPresence: Boolean
        get() = when (this) {
            AMBIENT -> false
            USER_PRESENT -> true
        }

    companion object {
        fun from(wire: String): KeyProtection? = entries.firstOrNull { it.wire == wire }
    }
}

/** Why an operation failed. Maps to `PlatformException.code` on the Dart side. */
internal enum class SignerErrorCode(val wire: String) {
    KEY_NOT_FOUND("key_not_found"),
    KEY_ALREADY_EXISTS("key_already_exists"),
    HARDWARE_UNAVAILABLE("hardware_unavailable"),
    KEYSTORE_FAILURE("keystore_failure"),
    USER_AUTHENTICATION_REQUIRED("user_authentication_required"),
    USER_AUTHENTICATION_CANCELLED("user_authentication_cancelled"),
    KEY_INVALIDATED("key_invalidated"),
    ;

    companion object {
        fun from(wire: String): SignerErrorCode? = entries.firstOrNull { it.wire == wire }
    }
}
