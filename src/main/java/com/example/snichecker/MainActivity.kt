package com.example.snichecker

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
        }
        val title = TextView(this).apply {
            text = "SNI / TLS Checker"
            textSize = 22f
        }
        val input = EditText(this).apply {
            setText("google.com\ngithub.com\nwikipedia.org")
            minLines = 4
            gravity = Gravity.TOP
        }
        val button = Button(this).apply { text = "Check" }
        val output = TextView(this).apply {
            textSize = 14f
            setTextIsSelectable(true)
        }
        val scroll = ScrollView(this).apply { addView(output) }

        root.addView(title)
        root.addView(input)
        root.addView(button)
        root.addView(scroll)
        setContentView(root)

        button.setOnClickListener {
            val hosts = input.text.toString().lines().map { it.trim() }.filter { it.isNotEmpty() }
            button.isEnabled = false
            output.text = "Checking..."
            Thread {
                val sb = StringBuilder()
                for (h in hosts) {
                    sb.append(checkHost(h)).append("\n\n")
                    val text = sb.toString()
                    runOnUiThread { output.text = text }
                }
                runOnUiThread { button.isEnabled = true }
            }.start()
        }
    }

    // TCP connect to port 443, send the host name as SNI, do the TLS handshake,
    // then read details from the server certificate.
    private fun checkHost(host: String): String {
        val start = System.currentTimeMillis()
        return try {
            val raw = Socket()
            raw.connect(InetSocketAddress(host, 443), 5000)
            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(raw, host, 443, true) as SSLSocket
            val params = ssl.sslParameters
            params.serverNames = listOf(SNIHostName(host))
            ssl.sslParameters = params
            ssl.soTimeout = 5000
            ssl.startHandshake()

            val cert = ssl.session.peerCertificates[0] as X509Certificate
            val issuer = cert.issuerX500Principal.name.substringAfter("CN=").substringBefore(",")
            val ms = System.currentTimeMillis() - start
            val result = "✅ $host\nTLS: ${ssl.session.protocol}\nIssuer: $issuer\n" +
                "Expires: ${cert.notAfter}\nHandshake: $ms ms"
            ssl.close()
            result
        } catch (e: Exception) {
            "❌ $host\nError: ${e.message ?: "unknown"}"
        }
    }
}
