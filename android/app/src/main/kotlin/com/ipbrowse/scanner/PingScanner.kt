package com.ipbrowse.scanner

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Аналог `ping()` из scanner.py для Android.
 *
 * Без root настоящий ICMP-echo недоступен (нет raw-сокетов), поэтому
 * используем двухэтапную стратегию:
 * 1) `InetAddress.isReachable()` — внутри JVM пробует ICMP (на root-устройстве)
 *    и TCP-эхо на порт 7 как fallback. Чаще всего на нерутованном Android
 *    срабатывает только TCP-fallback и большинство хостов отвечают «мёртв»;
 * 2) если первый шаг не подтвердил живость — пробуем TCP-touch на 80 / 443 /
 *    22 / 445. Если хоть одно соединение открылось или вернуло RST «быстро»,
 *    хост точно жив. На локальной сети это работает на порядки лучше ICMP.
 */
object PingScanner {

    private val FALLBACK_TOUCH_PORTS = intArrayOf(80, 443, 22, 445, 53, 8080)

    data class Result(val alive: Boolean, val responseMs: Double?, val ttl: Int?)

    fun ping(ip: String, timeoutMs: Int = 700): Result {
        val started = System.nanoTime()
        try {
            val addr = InetAddress.getByName(ip)
            if (addr.isReachable(timeoutMs)) {
                val ms = (System.nanoTime() - started) / 1_000_000.0
                return Result(true, ms, null)
            }
        } catch (_: IOException) {
            // см. ниже — фоллбэк через TCP
        } catch (_: SecurityException) {
            // INTERNET-permission будет, но на всякий случай.
        }

        // TCP-touch fallback: успешный connect (или быстрый RST) = хост живой.
        val budgetEachMs = (timeoutMs.coerceAtLeast(200) / FALLBACK_TOUCH_PORTS.size)
            .coerceAtLeast(120)
        for (p in FALLBACK_TOUCH_PORTS) {
            val (alive, ms) = touch(ip, p, budgetEachMs)
            if (alive) return Result(true, ms, null)
        }
        return Result(false, null, null)
    }

    /**
     * Простая TCP-проверка: успех `connect` — хост и порт живы;
     * быстрый `ConnectException` — хост жив, но порт закрыт (тоже считаем живым);
     * таймаут — считаем мёртвым.
     */
    private fun touch(ip: String, port: Int, timeoutMs: Int): Pair<Boolean, Double?> {
        val sock = Socket()
        val started = System.nanoTime()
        try {
            sock.connect(InetSocketAddress(ip, port), timeoutMs)
            val ms = (System.nanoTime() - started) / 1_000_000.0
            return true to ms
        } catch (_: java.net.ConnectException) {
            // RST — хост дошёл до нас, просто не слушает порт.
            val ms = (System.nanoTime() - started) / 1_000_000.0
            return true to ms
        } catch (_: java.net.SocketTimeoutException) {
            return false to null
        } catch (_: IOException) {
            return false to null
        } finally {
            try { sock.close() } catch (_: IOException) { }
        }
    }
}
