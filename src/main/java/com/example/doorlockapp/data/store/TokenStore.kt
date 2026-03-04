package com.example.doorlockapp.data.store

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class TokenStore(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "secure_store",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun setSessionToken(token: String) {
        prefs.edit().putString("session_token", token).apply()
    }

    fun getSessionToken(): String? = prefs.getString("session_token", null)

    fun clear() {
        prefs.edit().remove("session_token").apply()
    }
}
