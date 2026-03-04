package com.example.doorlockapp.crypto

import android.util.Base64

object B64 {
    fun urlEncodeNoPad(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}
