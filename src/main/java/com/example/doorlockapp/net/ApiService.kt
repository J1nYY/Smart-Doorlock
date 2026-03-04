package com.example.doorlockapp.net

import com.example.doorlockapp.data.model.*
import retrofit2.http.*

interface ApiService {

    @POST("/api/signup")
    suspend fun signup(@Body req: SignupRequest): OkResponse

    @POST("/api/login")
    suspend fun login(@Body req: LoginRequest): LoginResponse

    @POST("/api/keys/register")
    suspend fun registerKey(
        @Header("Authorization") auth: String,
        @Body req: KeyRegisterRequest
    ): OkResponse

    @GET("/api/keys/list")
    suspend fun listKeys(
        @Header("Authorization") auth: String
    ): KeysListResponse
}
