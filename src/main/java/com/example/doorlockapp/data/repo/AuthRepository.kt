package com.example.doorlockapp.data.repo

import android.content.Context
import com.example.doorlockapp.data.model.LoginRequest
import com.example.doorlockapp.data.model.SignupRequest
import com.example.doorlockapp.data.store.TokenStore
import com.example.doorlockapp.net.ApiClient

class AuthRepository(context: Context) {
    private val tokenStore = TokenStore(context.applicationContext)

    suspend fun signup(email: String, name: String, password: String): Boolean {
        val res = ApiClient.api().signup(SignupRequest(email, name, password))
        return res.ok
    }

    suspend fun login(email: String, password: String): Boolean {
        val res = ApiClient.api().login(LoginRequest(email, password))
        tokenStore.setSessionToken(res.session_token)
        return true
    }

    fun getSessionToken(): String? = tokenStore.getSessionToken()
}
