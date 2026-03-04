package com.example.doorlockapp.data.repo

import android.content.Context
import com.example.doorlockapp.crypto.KeyManager
import com.example.doorlockapp.data.model.KeyRegisterRequest
import com.example.doorlockapp.data.model.KeyItem
import com.example.doorlockapp.data.store.TokenStore
import com.example.doorlockapp.net.ApiClient

class KeyRepository(context: Context) {
    private val tokenStore = TokenStore(context.applicationContext)

    private fun bearer(): String {
        val token = tokenStore.getSessionToken() ?: error("Not logged in: session_token is missing")
        return "Bearer $token"
    }

    suspend fun registerMyPhoneKey(keyName: String): Boolean {
        val pub = KeyManager.getPublicKeySpkiB64Url()
        val res = ApiClient.api().registerKey(
            auth = bearer(),
            req = KeyRegisterRequest(key_name = keyName, pubkey_spki_b64 = pub)
        )
        return res.ok
    }

    suspend fun listKeys(): List<KeyItem> {
        return ApiClient.api().listKeys(bearer()).keys
    }
}
