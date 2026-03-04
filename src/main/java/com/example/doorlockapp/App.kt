package com.example.doorlockapp

import android.app.Application
import com.example.doorlockapp.net.ApiClient

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        ApiClient.init(this)
    }
}
