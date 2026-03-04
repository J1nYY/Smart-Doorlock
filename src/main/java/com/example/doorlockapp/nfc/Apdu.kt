package com.example.doorlockapp.nfc

object Apdu {
    // ISO7816-4: [CLA][INS][P1][P2][Lc][Data...]
    fun extractData(apdu: ByteArray): ByteArray? {
        if (apdu.size < 5) return null
        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return null
        return apdu.copyOfRange(5, 5 + lc)
    }

    fun getIns(apdu: ByteArray): Int? {
        if (apdu.size < 2) return null
        return apdu[1].toInt() and 0xFF
    }

    fun getP1(apdu: ByteArray): Int? {
        if (apdu.size < 3) return null
        return apdu[2].toInt() and 0xFF
    }

    fun getP2(apdu: ByteArray): Int? {
        if (apdu.size < 4) return null
        return apdu[3].toInt() and 0xFF
    }

    fun buildResponse(data: ByteArray, sw1: Int, sw2: Int): ByteArray {
        val out = ByteArray(data.size + 2)
        System.arraycopy(data, 0, out, 0, data.size)
        out[out.size - 2] = sw1.toByte()
        out[out.size - 1] = sw2.toByte()
        return out
    }
}

