package com.vaam.flutter_sign_keypair

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.Signature
import java.util.concurrent.Executor

/**
 * Flutter adapter over [SecureKeyStore].
 *
 * Everything that touches AndroidKeyStore lives in [SecureKeyStore], which has
 * no Flutter dependency and is therefore drivable by instrumented tests. What
 * remains here is method dispatch, argument validation, error mapping — and the
 * one thing that genuinely cannot move: raising BiometricPrompt for a
 * user-present key, which needs an Activity.
 */
class FlutterSignKeypairPlugin : FlutterPlugin, ActivityAware, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private var keys: SecureKeyStore? = null
    private var appContext: Context? = null
    private var activity: FragmentActivity? = null
    private val mainExecutor: Executor = Executor { Handler(Looper.getMainLooper()).post(it) }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        val context = binding.applicationContext
        appContext = context
        keys = SecureKeyStore(
            strongBoxAvailable = hasStrongBox(context.packageManager),
            userAuthenticationAvailable = { hasUserAuthentication(context) },
        )
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        keys = null
        appContext = null
    }

    // ActivityAware — the Activity is needed only to host BiometricPrompt.
    // Every other operation works without one, so a null activity is a failure
    // of the tier-3 path alone, not of the plugin.

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
        onAttachedToActivity(binding)

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    override fun onMethodCall(call: MethodCall, result: Result) {
        val keys = this.keys
            ?: return result.error(
                SignerErrorCode.KEYSTORE_FAILURE.wire,
                "Plugin is not attached to an engine",
                null,
            )

        // The one wire -> enum boundary for method names. An unknown name is
        // rejected here, once, and everything below switches on the enum.
        val method = SignerMethod.from(call.method)
            ?: return result.notImplemented()

        try {
            // Deliberately a `when` EXPRESSION with no `else`: Kotlin then
            // requires it to be exhaustive, so adding a SignerMethod member without
            // handling it here is a compile error rather than a silent
            // notImplemented() at runtime on one platform only.
            val response: Any? = when (method) {
                SignerMethod.CAPABILITIES -> mapOf(
                    "platform" to "android",
                    "backing" to keys.bestAvailableBacking().wire,
                )
                SignerMethod.GENERATE_KEY -> keys.generateKey(
                    keyId = call.requireArgument("keyId"),
                    requireHardware = call.argument<Boolean>("requireHardware") ?: false,
                    overwrite = call.argument<Boolean>("overwrite") ?: false,
                    protection = call.requireProtection(),
                ).toMap()
                SignerMethod.GET_KEY -> keys.describeKey(call.requireArgument("keyId"))?.toMap()
                SignerMethod.SIGN -> {
                    val signed = sign(
                        keys = keys,
                        keyId = call.requireArgument("keyId"),
                        payload = call.requireArgument("payload"),
                        reason = call.argument<String>("reason"),
                        result = result,
                    )
                    // A user-present key completes from the BiometricPrompt
                    // callback, on a later turn of the main loop. Returning the
                    // sentinel here keeps the single `result.success` below for
                    // the synchronous cases without letting this one fall
                    // through and answer the channel twice — which Flutter
                    // treats as a fatal "reply already submitted".
                    signed ?: return
                }
                SignerMethod.DELETE_KEY -> {
                    keys.deleteKey(call.requireArgument("keyId"))
                    null
                }
            }
            result.success(response)
        } catch (e: SecureKeyStore.SignerError) {
            result.error(e.code.wire, e.message, null)
        } catch (e: Exception) {
            // Deliberately broad: every java.security failure mode (provider
            // missing, key invalidated by a lock-screen change, StrongBox
            // wedged) must reach Dart as a typed error rather than crashing the
            // engine. The message never contains key material.
            result.error(
                SignerErrorCode.KEYSTORE_FAILURE.wire,
                e.message ?: e.javaClass.simpleName,
                null,
            )
        }
    }

    /**
     * Sign, prompting first when the key demands it.
     *
     * Returns the signature for an ambient key, and **null** for a user-present
     * one — in that case [result] is completed later, from the BiometricPrompt
     * callback. Whether to prompt is decided by reading the key's own
     * [KeyInfo][android.security.keystore.KeyInfo] rather than by the alias it
     * was asked for, so a key created by an older build is handled correctly.
     */
    private fun sign(
        keys: SecureKeyStore,
        keyId: String,
        payload: ByteArray,
        reason: String?,
        result: Result,
    ): ByteArray? {
        // Begin first: this is what surfaces a key destroyed by a biometric
        // re-enrolment (KEY_INVALIDATED), and doing it before the prompt means
        // the customer is not asked for a fingerprint that cannot help them.
        val operation = keys.beginSign(keyId)
        if (!keys.requiresUserAuthentication(keyId)) {
            return keys.finishSign(operation, payload)
        }

        val activity = this.activity ?: throw SecureKeyStore.SignerError(
            SignerErrorCode.KEYSTORE_FAILURE,
            "A user-present key needs a foreground Activity to show the " +
                "authentication prompt, and none is attached",
        )

        activity.runOnUiThread {
            promptThenSign(activity, keys, operation, payload, reason, result)
        }
        return null
    }

    private fun promptThenSign(
        activity: FragmentActivity,
        keys: SecureKeyStore,
        operation: Signature,
        payload: ByteArray,
        reason: String?,
        result: Result,
    ) {
        // Every path below must complete `result` exactly once. Flutter treats a
        // second reply as fatal, and a dropped one hangs the Dart future for the
        // life of the process — so the guard is on the callback object, which is
        // the only thing all three outcomes pass through.
        var replied = false
        fun replyOnce(body: () -> Unit) {
            if (replied) return
            replied = true
            body()
        }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                replyOnce {
                    try {
                        // Sign with the Signature the keymaster just authorised —
                        // `auth.cryptoObject`, not the local `operation`. They are
                        // the same object today, but reading it back from the
                        // result is what makes that a fact rather than an
                        // assumption, and an unauthorised operation would throw
                        // here instead of silently producing nothing.
                        val authorised = auth.cryptoObject?.signature
                            ?: throw SecureKeyStore.SignerError(
                                SignerErrorCode.KEYSTORE_FAILURE,
                                "Authentication succeeded without an authorised signing operation",
                            )
                        result.success(keys.finishSign(authorised, payload))
                    } catch (e: SecureKeyStore.SignerError) {
                        result.error(e.code.wire, e.message, null)
                    } catch (e: Exception) {
                        result.error(
                            SignerErrorCode.KEYSTORE_FAILURE.wire,
                            e.message ?: e.javaClass.simpleName,
                            null,
                        )
                    }
                }
            }

            override fun onAuthenticationError(code: Int, message: CharSequence) {
                replyOnce { result.error(errorCodeFor(code).wire, message.toString(), null) }
            }

            // Deliberately no reply here: a rejected fingerprint is a retry
            // within the same prompt, not the end of it. BiometricPrompt calls
            // onAuthenticationError when it finally gives up.
            override fun onAuthenticationFailed() = Unit
        }

        try {
            val authenticators = allowedAuthenticators()
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(reason?.takeIf { it.isNotEmpty() } ?: DEFAULT_PROMPT_TITLE)
                .setAllowedAuthenticators(authenticators)
                .apply {
                    // A negative button is required when the credential is not an
                    // allowed authenticator, and forbidden when it is — the
                    // builder throws either way round. On pre-R the key is
                    // biometric-only (see SecureKeyStore.createKeyPair), so this
                    // branch tracks the same version split the key spec does.
                    if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
                        setNegativeButtonText(DEFAULT_PROMPT_CANCEL)
                    }
                }
                .build()
            BiometricPrompt(activity, mainExecutor, callback)
                .authenticate(info, BiometricPrompt.CryptoObject(operation))
        } catch (e: Exception) {
            replyOnce {
                result.error(
                    SignerErrorCode.KEYSTORE_FAILURE.wire,
                    e.message ?: e.javaClass.simpleName,
                    null,
                )
            }
        }
    }

    /**
     * Which authenticators the prompt will accept.
     *
     * Crypto-backed authentication with the device credential only works from
     * API 30 — below that, `authenticate(info, cryptoObject)` rejects a prompt
     * that allows DEVICE_CREDENTIAL. This mirrors the key spec exactly, and it
     * must: a prompt that allows something the key does not, or vice versa,
     * fails at the moment the customer is looking at it.
     */
    private fun allowedAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    /**
     * Map a BiometricPrompt error onto a wire code.
     *
     * The distinction that earns its keep is cancelled-versus-unavailable: a
     * dismissed prompt is a customer changing their mind at a confirmation
     * screen, and reporting it as an authentication failure would send them
     * through re-enrolment for a routine interaction.
     */
    private fun errorCodeFor(code: Int): SignerErrorCode = when (code) {
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_TIMEOUT,
        -> SignerErrorCode.USER_AUTHENTICATION_CANCELLED

        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        -> SignerErrorCode.USER_AUTHENTICATION_REQUIRED

        else -> SignerErrorCode.KEYSTORE_FAILURE
    }

    private fun hasStrongBox(packageManager: PackageManager): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Whether the device has anything the keystore would accept as proof a human
     * is present.
     *
     * `KeyguardManager.isDeviceSecure` rather than
     * `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)`: the key accepts the
     * device credential too (ADR 0024 §6), so probing for biometrics alone would
     * refuse a passcode-only device this package can serve perfectly well.
     */
    private fun hasUserAuthentication(context: Context): Boolean {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return false
        return keyguard.isDeviceSecure
    }

    private inline fun <reified T> MethodCall.requireArgument(name: String): T =
        argument<T>(name) ?: throw SecureKeyStore.SignerError(
            SignerErrorCode.KEYSTORE_FAILURE,
            "Missing required argument \"$name\"",
        )

    /**
     * The one wire -> enum boundary for the protection tag.
     *
     * Missing or unrecognised is a hard failure, with no default. Guessing
     * AMBIENT would hand a caller who asked for tier-3 protection a key that
     * signs without a human; guessing USER_PRESENT would make the request
     * interceptor prompt on every background poll. Neither is a safe direction to
     * be wrong in, and the policy is baked into the key permanently at creation
     * — so a mismatched Dart/native pairing fails at the call instead.
     */
    private fun MethodCall.requireProtection(): KeyProtection {
        val raw = requireArgument<String>("protection")
        return KeyProtection.from(raw) ?: throw SecureKeyStore.SignerError(
            SignerErrorCode.KEYSTORE_FAILURE,
            "Unknown key protection \"$raw\"",
        )
    }

    companion object {
        const val CHANNEL_NAME = "com.vaam/flutter_sign_keypair"

        /**
         * Shown only when the caller supplies no [reason]. This default is French,
         * which is deliberately generic rather than considered copy — a caller
         * that omits [reason] and ships this string to production is a bug worth
         * being able to spot in a screenshot. Pass [reason] to show the caller's
         * own localized copy instead.
         */
        private const val DEFAULT_PROMPT_TITLE = "Authentification requise"
        private const val DEFAULT_PROMPT_CANCEL = "Annuler"

        private const val COORDINATE_LENGTH = 32

        /**
         * Left-pad / trim a BigInteger to exactly 32 bytes (P-256 coordinate width).
         *
         * Same bug class as [derToP1363]: `BigInteger.toByteArray()` prepends a
         * 0x00 sign byte when the high bit is set (33 bytes), and returns FEWER
         * than 32 bytes for a coordinate with leading zeros. Getting either
         * wrong corrupts the public JWK sent at device registration, and the
         * symptom is "every signature this device makes is rejected" — with no
         * hint that the *key*, not the signing, was wrong.
         *
         * Internal (not private) so the JVM unit test can exercise it without
         * AndroidKeyStore, which does not exist off-device.
         */
        @JvmStatic
        internal fun coordinateBytes(value: java.math.BigInteger): ByteArray {
            val raw = value.toByteArray()
            val out = ByteArray(COORDINATE_LENGTH)
            if (raw.size > COORDINATE_LENGTH) {
                System.arraycopy(raw, raw.size - COORDINATE_LENGTH, out, 0, COORDINATE_LENGTH)
            } else {
                System.arraycopy(raw, 0, out, COORDINATE_LENGTH - raw.size, raw.size)
            }
            return out
        }

        /**
         * ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` -> IEEE P1363 `r‖s`.
         *
         * Internal (not private) so the JVM unit test can exercise it without
         * AndroidKeyStore, which does not exist off-device.
         */
        @JvmStatic
        internal fun derToP1363(der: ByteArray): ByteArray {
            var offset = 0
            fun readByte(): Int {
                require(offset < der.size) { "Truncated DER signature" }
                return der[offset++].toInt() and 0xff
            }

            require(readByte() == 0x30) { "DER signature does not start with SEQUENCE" }
            var sequenceLength = readByte()
            if (sequenceLength and 0x80 != 0) {
                val lengthOctets = sequenceLength and 0x7f
                require(lengthOctets in 1..2) { "Unsupported DER length form" }
                sequenceLength = 0
                repeat(lengthOctets) { sequenceLength = (sequenceLength shl 8) or readByte() }
            }
            require(offset + sequenceLength == der.size) { "DER length mismatch" }

            fun readInteger(): ByteArray {
                require(readByte() == 0x02) { "Expected DER INTEGER" }
                val length = readByte()
                require(length and 0x80 == 0) { "Unsupported long-form DER INTEGER" }
                require(length > 0) { "Zero-length DER INTEGER" }
                require(offset + length <= der.size) { "Truncated DER INTEGER" }
                val value = der.copyOfRange(offset, offset + length)
                offset += length
                return value
            }

            fun leftPad(value: ByteArray): ByteArray {
                var start = 0
                while (start < value.size - 1 && value[start].toInt() == 0) start++
                val length = value.size - start
                require(length <= COORDINATE_LENGTH) { "ECDSA integer longer than 32 bytes" }
                val out = ByteArray(COORDINATE_LENGTH)
                System.arraycopy(value, start, out, COORDINATE_LENGTH - length, length)
                return out
            }

            val r = leftPad(readInteger())
            val s = leftPad(readInteger())

            // r and s must account for the entire SEQUENCE. Without this,
            // trailing bytes are silently ignored, which makes the encoding
            // malleable: junk can be appended to produce a different byte
            // string that decodes to the same signature. `openssl asn1parse`
            // rejects such input too.
            require(offset == der.size) { "${der.size - offset} trailing byte(s) after s" }

            return r + s
        }
    }
}
