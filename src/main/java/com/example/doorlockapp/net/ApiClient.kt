package com.example.doorlockapp.net

import android.content.Context
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory

object ApiClient {
    private lateinit var api: ApiService

    fun init(context: Context) {
        val moshi = Moshi.Builder()
            .add(KotlinJsonAdapterFactory())
            .build()

        val okHttp = HttpClientProvider.buildPinnedCaOkHttp(context.applicationContext)

        api = Retrofit.Builder()
            .baseUrl("https://10.10.141.69:8443/")
            .client(okHttp)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(ApiService::class.java)
    }

    fun api(): ApiService = api
}
