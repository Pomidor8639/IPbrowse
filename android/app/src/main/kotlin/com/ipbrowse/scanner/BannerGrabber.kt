package com.ipbrowse.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Аналог `grab_banner` из scanner.py — best-effort снятие баннера.
 * Двухходовка: либо порт сразу присылает баннер (SSH/FTP/SMTP/...), либо
 * шлём минимальный HEAD и читаем первую непустую строку.
 */
object BannerGrabber {

    private val BANNER_FIRST_PORTS = setOf(
        21, 22, 23, 25, 110, 143, 220, 465, 587, 993, 995, 5900, 6667,
    )

    suspend fun grab(ip: String, port: Int, timeoutMs: Int = 1500): String = withContext(Dispatchers.IO) {
        val sock = Socket()
        sock.soTimeout = timeoutMs
        try {
            try {
                sock.connect(InetSocketAddress(ip, port), timeoutMs)
            } catch (_: IOException) {
                return@withContext ""
            }

            val input = sock.getInputStream()
            val output = sock.getOutputStream()
            var data = ByteArray(0)

            if (port in BANNER_FIRST_PORTS) {
                val buf = ByteArray(2048)
                try {
                    val n = input.read(buf)
                    if (n > 0) data = buf.copyOf(n)
                } catch (_: IOException) {
                    // пусто — пробуем HEAD
                }
            }

            if (data.isEmpty()) {
                try {
                    val req = "HEAD / HTTP/1.0\r\nHost: $ip\r\nUser-Agent: IPbrowse\r\n\r\n"
                    output.write(req.toByteArray(Charsets.US_ASCII))
                    output.flush()
                    val chunks = ArrayList<ByteArray>()
                    var total = 0
                    val buf = ByteArray(2048)
                    while (true) {
                        val n = try {
                            input.read(buf)
                        } catch (_: IOException) {
                            break
                        }
                        if (n <= 0) break
                        chunks.add(buf.copyOf(n))
                        total += n
                        if (total >= 4096) break
                    }
                    if (chunks.isNotEmpty()) {
                        val all = ByteArray(total)
                        var off = 0
                        for (c in chunks) {
                            System.arraycopy(c, 0, all, off, c.size); off += c.size
                        }
                        data = all
                    }
                } catch (_: IOException) {
                    return@withContext ""
                }
            }

            if (data.isEmpty()) return@withContext ""
            val text = data.toString(Charsets.UTF_8)

            // Server: header у HTTP — приоритет.
            val server = Regex("(?im)^Server:\\s*(.+)$").find(text)?.groupValues?.get(1)
            val line = server ?: text.lineSequence().firstOrNull { it.isNotBlank() } ?: ""
            val cleaned = line.replace(Regex("[\\x00-\\x08\\x0b-\\x1f\\x7f]"), "").trim()
            return@withContext if (cleaned.length > 120) cleaned.take(117) + "..." else cleaned
        } finally {
            try { sock.close() } catch (_: IOException) { }
        }
    }
}
