package com.example.doorlockapp.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

object KeyManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "ksh_pi_hce_key"

    fun getOrCreateKeyPair(): KeyPair {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (existing != null) {
            return KeyPair(existing.certificate.publicKey, existing.privateKey)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()

        kpg.initialize(spec)
        return kpg.generateKeyPair()
    }

    fun getPublicKeySpkiB64Url(): String {
        val kp = getOrCreateKeyPair()
        val spki: ByteArray = kp.public.encoded // X.509 SPKI DER
        return B64.urlEncodeNoPad(spki)
    }

    fun getPublicKey(): PublicKey = getOrCreateKeyPair().public
}
