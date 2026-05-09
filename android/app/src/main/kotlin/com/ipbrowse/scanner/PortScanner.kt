package com.ipbrowse.scanner

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * TCP-connect сканер портов — порт `scan_ports` / `scan_port` из scanner.py.
 * Параллелизм через корутины + Semaphore вместо ThreadPoolExecutor.
 */
object PortScanner {

    suspend fun scanPort(ip: String, port: Int, timeoutMs: Int): Boolean = withContext(Dispatchers.IO) {
        val sock = Socket()
        try {
            sock.connect(InetSocketAddress(ip, port), timeoutMs)
            true
        } catch (_: IOException) {
            false
        } finally {
            try { sock.close() } catch (_: IOException) { }
        }
    }

    /**
     * Сканирует список портов параллельно. `progress` вызывается из произвольной
     * корутины, UI-слой обязан переключиться на main-thread сам.
     */
    suspend fun scanPorts(
        scope: CoroutineScope,
        ip: String,
        ports: List<Int>,
        timeoutMs: Int,
        workers: Int,
        progress: ((done: Int, total: Int) -> Unit)? = null,
    ): List<Int> {
        if (ports.isEmpty()) return emptyList()
        val total = ports.size
        val semaphore = Semaphore(workers.coerceIn(1, 256))
        var done = 0
        val step = (total / 100).coerceAtLeast(1)

        val deferred = ports.map { port ->
            scope.async(Dispatchers.IO) {
                if (!isActive) return@async null
                val open = semaphore.withPermit { scanPort(ip, port, timeoutMs) }
                synchronized(this) {
                    done += 1
                    if (progress != null && (done == total || done % step == 0)) {
                        progress(done, total)
                    }
                }
                if (open) port else null
            }
        }
        return deferred.awaitAll().filterNotNull().sorted()
    }
}
