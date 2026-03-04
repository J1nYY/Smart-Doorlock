package com.example.doorlockapp.net

import android.content.Context
import com.example.doorlockapp.R
import okhttp3.OkHttpClient
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object HttpClientProvider {

    fun buildPinnedCaOkHttp(context: Context): OkHttpClient {
        val cf = CertificateFactory.getInstance("X.509")
        val caCert = context.resources.openRawResource(R.raw.ca).use {
            cf.generateCertificate(it) as X509Certificate
        }

        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("ca", caCert)
        }

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(keyStore)
        }
        val trustManager = tmf.trustManagers.first() as X509TrustManager

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustManager), null)
        }

        return OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .build()
    }
}
