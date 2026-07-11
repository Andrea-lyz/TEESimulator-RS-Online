package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.PaddingMode
import android.hardware.security.keymint.Tag
import org.matrix.TEESimulator.attestation.KeyMintAttestation

object AuthorizeCreate {

    fun check(
        keyParams: KeyMintAttestation?,
        opParams: KeyMintAttestation,
        rawOpParams: Array<KeyParameter>? = null,
    ): Int? {
        if (keyParams == null) return null
        val purpose = opParams.purpose.firstOrNull() ?: return null
        // Algorithm-level rejection runs before purpose-list check (AOSP HAL behavior)
        return checkAlgorithmPurpose(keyParams, purpose)
            ?: checkPurpose(keyParams, purpose)
            ?: checkOperationShape(keyParams, opParams)
            ?: checkOperationAuthorizations(keyParams, opParams)
            ?: checkTemporalValidity(keyParams, purpose)
            ?: checkCallerNonce(keyParams, purpose, rawOpParams)
    }

    private fun checkAlgorithmPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val algo = keyParams.algorithm
        if ((algo == Algorithm.EC || algo == Algorithm.RSA) &&
            (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.ENCRYPT)
        ) {
            return KeystoreErrorCodes.unsupportedPurpose
        }
        if (algo == Algorithm.RSA && purpose == KeyPurpose.AGREE_KEY)
            return KeystoreErrorCodes.unsupportedPurpose
        return null
    }

    private fun checkPurpose(keyParams: KeyMintAttestation, purpose: Int): Int? {
        if (purpose == KeyPurpose.WRAP_KEY)
            return KeystoreErrorCodes.incompatiblePurpose
        if (purpose !in keyParams.purpose)
            return KeystoreErrorCodes.incompatiblePurpose
        return null
    }

    private fun checkOperationAuthorizations(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.blockMode.any { it !in keyParams.blockMode }) {
            return KeystoreErrorCodes.incompatibleBlockMode
        }
        if (opParams.padding.any { it !in keyParams.padding }) {
            return KeystoreErrorCodes.incompatiblePaddingMode
        }
        if (opParams.digest.any { it !in keyParams.digest }) {
            return KeystoreErrorCodes.incompatibleDigest
        }
        if (keyParams.rsaOaepMgfDigest.isNotEmpty() &&
            opParams.rsaOaepMgfDigest.any { it !in keyParams.rsaOaepMgfDigest }
        ) {
            return KeystoreErrorCodes.incompatibleMgfDigest
        }

        return null
    }

    private fun checkOperationShape(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? =
        when (keyParams.algorithm) {
            Algorithm.AES -> checkAesOperation(keyParams, opParams)
            Algorithm.HMAC -> checkHmacOperation(keyParams, opParams)
            Algorithm.RSA -> checkRsaOperation(keyParams, opParams)
            Algorithm.EC ->
                if (opParams.purpose.firstOrNull() == KeyPurpose.SIGN && opParams.digest.size != 1) {
                    KeystoreErrorCodes.unsupportedDigest
                } else {
                    null
                }
            else -> null
        }

    private fun checkAesOperation(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.blockMode.size != 1) return KeystoreErrorCodes.unsupportedBlockMode
        if (opParams.padding.size != 1) return KeystoreErrorCodes.unsupportedPaddingMode

        val blockMode = opParams.blockMode.single()
        val padding = opParams.padding.single()
        if ((blockMode == BlockMode.GCM || blockMode == BlockMode.CTR) && padding != PaddingMode.NONE) {
            return KeystoreErrorCodes.incompatiblePaddingMode
        }
        if ((blockMode == BlockMode.ECB || blockMode == BlockMode.CBC) &&
            padding != PaddingMode.NONE && padding != PaddingMode.PKCS7
        ) {
            return KeystoreErrorCodes.incompatiblePaddingMode
        }

        if (blockMode == BlockMode.GCM) {
            validateMacLength(opParams.macLength, keyParams.minMacLength, 128)?.let { return it }
        }

        val nonce = opParams.nonce
        val expectedNonceLength =
            when (blockMode) {
                BlockMode.GCM -> 12
                BlockMode.CBC, BlockMode.CTR -> 16
                else -> null
            }
        if (nonce != null && expectedNonceLength != null && nonce.size != expectedNonceLength) {
            return KeystoreErrorCodes.invalidNonce
        }
        if (opParams.purpose.firstOrNull() == KeyPurpose.DECRYPT &&
            expectedNonceLength != null && nonce == null
        ) {
            return KeystoreErrorCodes.missingNonce
        }
        return null
    }

    private fun checkHmacOperation(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.digest.size != 1) return KeystoreErrorCodes.unsupportedDigest
        val digestBits =
            when (opParams.digest.single()) {
                Digest.MD5 -> 128
                Digest.SHA1 -> 160
                Digest.SHA_2_224 -> 224
                Digest.SHA_2_256 -> 256
                Digest.SHA_2_384 -> 384
                Digest.SHA_2_512 -> 512
                else -> return KeystoreErrorCodes.unsupportedDigest
            }
        return validateMacLength(opParams.macLength, keyParams.minMacLength, digestBits)
    }

    private fun checkRsaOperation(
        keyParams: KeyMintAttestation,
        opParams: KeyMintAttestation,
    ): Int? {
        if (opParams.padding.size != 1) return KeystoreErrorCodes.unsupportedPaddingMode
        val purpose = opParams.purpose.firstOrNull()
        val padding = opParams.padding.single()
        val needsDigest =
            purpose == KeyPurpose.SIGN || padding == PaddingMode.RSA_OAEP
        if (needsDigest && opParams.digest.size != 1) return KeystoreErrorCodes.unsupportedDigest
        if (opParams.digest.size > 1) return KeystoreErrorCodes.unsupportedDigest
        if ((padding == PaddingMode.RSA_PSS || padding == PaddingMode.RSA_OAEP) &&
            opParams.digest.singleOrNull() == Digest.NONE
        ) {
            return KeystoreErrorCodes.incompatibleDigest
        }

        if (padding == PaddingMode.RSA_OAEP) {
            if (keyParams.rsaOaepMgfDigest.isEmpty()) {
                if (opParams.rsaOaepMgfDigest.any { it != Digest.SHA1 }) {
                    return KeystoreErrorCodes.incompatibleMgfDigest
                }
            } else {
                if (opParams.rsaOaepMgfDigest.size != 1) {
                    return KeystoreErrorCodes.incompatibleMgfDigest
                }
                if (opParams.rsaOaepMgfDigest.single() == Digest.NONE) {
                    return KeystoreErrorCodes.incompatibleMgfDigest
                }
            }
        }
        return null
    }

    private fun validateMacLength(requested: Int?, minimum: Int?, maximum: Int): Int? {
        if (requested == null) return KeystoreErrorCodes.missingMacLength
        if (requested <= 0 || requested % 8 != 0 || requested > maximum) {
            return KeystoreErrorCodes.unsupportedMacLength
        }
        if (minimum != null && requested < minimum) return KeystoreErrorCodes.invalidMacLength
        return null
    }

    private fun checkTemporalValidity(keyParams: KeyMintAttestation, purpose: Int): Int? {
        val now = System.currentTimeMillis()

        keyParams.activeDateTime?.let { activeDate ->
            if (now < activeDate.time) return KeystoreErrorCodes.keyNotYetValid
        }

        keyParams.originationExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.ENCRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        keyParams.usageExpireDateTime?.let { expireDate ->
            if (purpose == KeyPurpose.VERIFY || purpose == KeyPurpose.DECRYPT) {
                if (now > expireDate.time) return KeystoreErrorCodes.keyExpired
            }
        }

        return null
    }

    private fun checkCallerNonce(keyParams: KeyMintAttestation, purpose: Int, rawOpParams: Array<KeyParameter>?): Int? {
        if (purpose != KeyPurpose.SIGN && purpose != KeyPurpose.ENCRYPT) return null
        if (keyParams.callerNonce == true) return null
        if (rawOpParams?.any { it.tag == Tag.NONCE } == true)
            return KeystoreErrorCodes.callerNonceProhibited
        return null
    }
}
