package com.example.doorlockapp.data.model

data class OkResponse(val ok: Boolean)

data class SignupRequest(
    val email: String,
    val name: String,
    val password: String
)

data class LoginRequest(
    val email: String,
    val password: String
)

data class LoginResponse(
    val session_token: String,
    val expires_in: Long
)
