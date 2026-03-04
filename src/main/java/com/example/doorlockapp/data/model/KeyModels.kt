package com.example.doorlockapp.data.model

data class KeyRegisterRequest(
    val key_name: String,
    val pubkey_spki_b64: String
)

data class KeysListResponse(
    val keys: List<KeyItem>
)

data class KeyItem(
    val id: Long,
    val name: String,
    val active: Int,
    val created_at: String
)
