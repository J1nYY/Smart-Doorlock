package com.example.doorlockapp.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import com.example.doorlockapp.R
import com.example.doorlockapp.data.repo.AuthRepository
import com.example.doorlockapp.data.repo.KeyRepository
import com.example.doorlockapp.data.store.OpenAuthGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val etEmail = findViewById<EditText>(R.id.etEmail)
        val etName = findViewById<EditText>(R.id.etName)
        val etPassword = findViewById<EditText>(R.id.etPassword)
        val etKeyName = findViewById<EditText>(R.id.etKeyName)

        val txt = findViewById<TextView>(R.id.txtResult)
        val btnSignup = findViewById<Button>(R.id.btnSignup)
        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val btnRegister = findViewById<Button>(R.id.btnRegisterKey)
        val btnList = findViewById<Button>(R.id.btnListKeys)
        val btnAllow30s = findViewById<Button>(R.id.btnAllowOpen30s)
        val btnDisable = findViewById<Button>(R.id.btnDisableOpen)

        val authRepo = AuthRepository(this)
        val keyRepo = KeyRepository(this)
        val gate = OpenAuthGate(this)

        fun show(msg: String) { txt.text = msg }

        btnSignup.setOnClickListener {
            lifecycleScope.launch {
                try {
                    val ok = withContext(Dispatchers.IO) {
                        authRepo.signup(
                            email = etEmail.text.toString(),
                            name = etName.text.toString(),
                            password = etPassword.text.toString()
                        )
                    }
                    show("signup ok=$ok")
                } catch (e: Exception) {
                    show("signup 실패: ${e.message}")
                }
            }
        }

        btnLogin.setOnClickListener {
            lifecycleScope.launch {
                try {
                    val email = etEmail.text.toString()
                    withContext(Dispatchers.IO) {
                        authRepo.login(
                            email = email,
                            password = etPassword.text.toString()
                        )
                    }

                    // ✅ email 저장 (HCE 서비스에서 읽을 용도)
                    getSharedPreferences("auth", MODE_PRIVATE)
                        .edit()
                        .putString("email", email)
                        .apply()

                    show("login 성공. token 저장됨.")
                } catch (e: Exception) {
                    show("login 실패: ${e.message}")
                }
            }
        }
        btnRegister.setOnClickListener {
            lifecycleScope.launch {
                try {
                    val ok = withContext(Dispatchers.IO) {
                        keyRepo.registerMyPhoneKey(etKeyName.text.toString().ifBlank { "my-phone" })
                    }
                    show("keys/register ok=$ok")
                } catch (e: Exception) {
                    show("keys/register 실패: ${e.message}")
                }
            }
        }

        btnList.setOnClickListener {
            lifecycleScope.launch {
                try {
                    val keys = withContext(Dispatchers.IO) { keyRepo.listKeys() }
                    show(keys.joinToString(
                        prefix = "keys:\n",
                        separator = "\n"
                    ) { "id=${it.id}, name=${it.name}, active=${it.active}, created=${it.created_at}" })
                } catch (e: Exception) {
                    show("keys/list 실패: ${e.message}")
                }
            }
        }

        // ✅ 여기: "버튼 이벤트로 30초 허용"
        btnAllow30s.setOnClickListener {
            gate.allowForSeconds(30)
            show("NFC 문열기 30초 허용됨. (남은 ${gate.remainingMs()/1000}s)")
        }

        btnDisable.setOnClickListener {
            gate.disable()
            show("NFC 문열기 허용 꺼짐")
        }
    }
}
