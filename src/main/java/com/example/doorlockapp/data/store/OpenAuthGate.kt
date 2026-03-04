package com.example.doorlockapp.data.store

import android.content.Context

class OpenAuthGate(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("open_gate", Context.MODE_PRIVATE)

    fun allowForSeconds(sec: Int) {
        val until = System.currentTimeMillis() + sec * 1000L
        prefs.edit()
            .putLong("allow_until", until)
            .apply()
    }

    fun disable() {
        prefs.edit().putLong("allow_until", 0L).apply()
    }

    fun isAllowedNow(): Boolean {
        val until = prefs.getLong("allow_until", 0L)
        return System.currentTimeMillis() <= until
    }

    fun remainingMs(): Long {
        val until = prefs.getLong("allow_until", 0L)
        return (until - System.currentTimeMillis()).coerceAtLeast(0L)
    }
}
