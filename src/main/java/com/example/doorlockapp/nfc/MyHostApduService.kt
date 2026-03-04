package com.example.doorlockapp.nfc

import com.example.doorlockapp.crypto.KeyManager
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import java.security.Signature
import java.util.concurrent.atomic.AtomicReference
import java.nio.charset.StandardCharsets
class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "HCE"
        private const val INS_GET_EMAIL = 0x02
        private const val INS_GET_CAPS = 0x01
        private const val INS_SIGN_REQ = 0x20
        private const val INS_GET_SIG  = 0x21

        private const val SW1_OK = 0x90
        private const val SW2_OK = 0x00

        private const val CHUNK = 48// GET_SIG로 나눠서 주는 시그니처 조각 크기
    }

    // 서명 결과 저장
    private val sigRef = AtomicReference<ByteArray?>(null)
    private val uidRef = AtomicReference<Int?>(null)
    private fun loadEmail(): String? {
        return getSharedPreferences("auth", MODE_PRIVATE).getString("email", null)
    }
    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray {
        Log.d(TAG, "APDU <= " + apdu.joinToString(" ") { "%02X".format(it) })

        if (apdu.size < 2) return data9000("ERR".toByteArray())

        val ins = apdu[1].toInt() and 0xFF
        if (ins == 0xA4) return sw9000() // SELECT

        val resp = when (ins) {
            INS_GET_CAPS -> data9000WithEmail("ch".toByteArray())
            INS_SIGN_REQ -> handleSignReq(apdu)
            INS_GET_SIG  -> handleGetSig(apdu)
            else -> data9000("ERR|ins".toByteArray())
        }

        Log.d(TAG, "APDU => " + resp.joinToString(" ") { "%02X".format(it) })
        return resp
    }

    private fun handleSignReq(apdu: ByteArray): ByteArray {
        val data = extractLcData(apdu) ?: return data9000("ERR|no_data".toByteArray())
        // data = door(4) + user(4) + exp(4) + nonce_len(1) + nonce_str(nonce_len)
        if (data.size < 13) return data9000("ERR|bad_len".toByteArray())

        val doorId = readU32BE(data, 0)
        val userId = readU32BE(data, 4)
        val exp    = readU32BE(data, 8)
        val nlen   = data[12].toInt() and 0xFF
        if (data.size != 13 + nlen) return data9000("ERR|bad_nlen".toByteArray())

        val nonceStr = String(data, 13, nlen, StandardCharsets.US_ASCII)
        val nonceHashHex = sha256Hex(nonceStr.toByteArray(StandardCharsets.US_ASCII))

        val msg = "KSH|OPEN|user_id=$userId|door_id=$doorId|nonce_hash=$nonceHashHex|exp=$exp"

        Log.d(TAG, "SIGN msg=$msg")

        sigRef.set(null)
        uidRef.set(userId)

        Thread {
            try {
                val kp = KeyManager.getOrCreateKeyPair()
                val s = Signature.getInstance("SHA256withECDSA")
                val pub = kp.public.encoded // SPKI DER
                val ph = sha256Hex(pub)
                Log.d(TAG, "PUBKEY spki_len=${pub.size} sha256=$ph")
                s.initSign(kp.private)
                s.update(msg.toByteArray(StandardCharsets.UTF_8))
                val sigDer = s.sign() // DER
                sigRef.set(sigDer)
                Log.d(TAG, "SIG ready len=${sigDer.size}")
            } catch (e: Exception) {
                Log.e(TAG, "sign failed", e)
                sigRef.set(byteArrayOf()) // 실패 표시
            }
        }.start()

        return sw9000() // 즉시 ACK
    }
    private fun sha256Hex(data: ByteArray): String {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        val dig = md.digest(data)
        val sb = StringBuilder(dig.size * 2)
        for (b in dig) sb.append(String.format("%02x", b))  // 소문자 hex
        return sb.toString()
    }
    private fun handleGetSig(apdu: ByteArray): ByteArray {
        val chunkIndex = apdu.getOrNull(2)?.toInt()?.and(0xFF) ?: 0
        val sig = sigRef.get()
        val userId = uidRef.get() ?: return data9000("ERR|no_uid".toByteArray())

        if (sig == null) return data9000("PEND".toByteArray())
        if (sig.isEmpty()) return data9000("ERR|sign".toByteArray())

        val total = sig.size

        return if (chunkIndex == 0) {
            // chunk0: user_id(4) + sig_len(2) + sig_part
            val hdr = ByteArray(6)
            writeU32BE(hdr, 0, userId)
            hdr[4] = ((total ushr 8) and 0xFF).toByte()
            hdr[5] = (total and 0xFF).toByte()

            val take = minOf(CHUNK, total)
            val out = ByteArray(6 + take)
            System.arraycopy(hdr, 0, out, 0, 6)
            System.arraycopy(sig, 0, out, 6, take)
            data9000(out)
        } else {
            val offset = CHUNK + (chunkIndex - 1) * CHUNK
            if (offset >= total) return data9000("DONE".toByteArray())
            val take = minOf(CHUNK, total - offset)
            val out = sig.copyOfRange(offset, offset + take)
            data9000(out)
        }
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "Deactivated: $reason")
    }

    // ---- helpers ----
    private fun extractLcData(apdu: ByteArray): ByteArray? {
        if (apdu.size < 5) return null
        val lc = apdu[4].toInt() and 0xFF
        if (apdu.size < 5 + lc) return null
        return apdu.copyOfRange(5, 5 + lc)
    }

    private fun sw9000(): ByteArray = byteArrayOf(SW1_OK.toByte(), SW2_OK.toByte())
    private fun data9000WithEmail(prefix: ByteArray): ByteArray {
        val email = loadEmail()?.toByteArray(StandardCharsets.UTF_8) ?: byteArrayOf()
        val data = prefix + byteArrayOf(email.size.toByte()) + email
        return data9000(data)
    }
    private fun data9000(data: ByteArray): ByteArray {
        val out = ByteArray(data.size + 2)
        System.arraycopy(data, 0, out, 0, data.size)
        out[out.size - 2] = SW1_OK.toByte()
        out[out.size - 1] = SW2_OK.toByte()
        return out
    }

    private fun readU32BE(b: ByteArray, off: Int): Int {
        return ((b[off].toInt() and 0xFF) shl 24) or
                ((b[off + 1].toInt() and 0xFF) shl 16) or
                ((b[off + 2].toInt() and 0xFF) shl 8) or
                (b[off + 3].toInt() and 0xFF)
    }

    private fun writeU32BE(out: ByteArray, off: Int, v: Int) {
        out[off]     = ((v ushr 24) and 0xFF).toByte()
        out[off + 1] = ((v ushr 16) and 0xFF).toByte()
        out[off + 2] = ((v ushr 8) and 0xFF).toByte()
        out[off + 3] = (v and 0xFF).toByte()
    }
}
