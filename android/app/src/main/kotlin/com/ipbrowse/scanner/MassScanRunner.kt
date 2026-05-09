package com.ipbrowse.scanner

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Массовое сканирование одного / нескольких портов по списку IP —
 * Android-эквивалент `MassScanWorker` из app.py. На UI отдаются только
 * открытые порты, как и в десктопе: писать каждое closed / timeout /
 * error в Compose-список бессмысленно и тормозит интерфейс. Закрытые /
 * timeout / error попадают только в счётчик прогресса.
 */
data class MassScanOptions(
    val ips: List<String>,
    val ports: List<Int>,
    val workers: Int = 200,
    val timeoutMs: Int = 600,
)

data class MassScanHit(
    val ip: String,
    val port: Int,
    val rttMs: Double,
)

sealed interface MassScanEvent {
    data class Hit(val hit: MassScanHit) : MassScanEvent
    data class Progress(val done: Int, val total: Int) : MassScanEvent
    data object Done : MassScanEvent
}

object MassScanRunner {

    fun run(opts: MassScanOptions): Flow<MassScanEvent> = channelFlow {
        try {
            val jobs = ArrayList<Pair<String, Int>>(opts.ips.size * opts.ports.size)
            for (ip in opts.ips) for (p in opts.ports) jobs.add(ip to p)
            val total = jobs.size
            send(MassScanEvent.Progress(0, total))
            if (total == 0) {
                send(MassScanEvent.Done)
                return@channelFlow
            }

            val sem = Semaphore(opts.workers.coerceIn(1, 1024))
            // Те же 1% / 50 пробов, что и в десктопе — иначе UI тонет в событиях.
            val step = maxOf(50, total / 100)
            var done = 0
            val lock = Any()

            coroutineScope {
                jobs.map { (ip, port) ->
                    async(Dispatchers.IO) {
                        if (!isActive) return@async
                        sem.withPermit {
                            val (open, rtt) = probe(ip, port, opts.timeoutMs)
                            if (open) trySend(MassScanEvent.Hit(MassScanHit(ip, port, rtt)))
                            val emit: Pair<Int, Int>? = synchronized(lock) {
                                done += 1
                                if (done == total || done % step == 0) done to total else null
                            }
                            if (emit != null) trySend(MassScanEvent.Progress(emit.first, emit.second))
                        }
                    }
                }.awaitAll()
            }
            send(MassScanEvent.Done)
        } catch (_: CancellationException) {
            throw CancellationException()
        }
    }

    private fun probe(ip: String, port: Int, timeoutMs: Int): Pair<Boolean, Double> {
        val sock = Socket()
        val started = System.nanoTime()
        return try {
            sock.connect(InetSocketAddress(ip, port), timeoutMs)
            true to (System.nanoTime() - started) / 1_000_000.0
        } catch (_: SocketTimeoutException) {
            false to timeoutMs.toDouble()
        } catch (_: ConnectException) {
            false to (System.nanoTime() - started) / 1_000_000.0
        } catch (_: IOException) {
            false to (System.nanoTime() - started) / 1_000_000.0
        } finally {
            try { sock.close() } catch (_: IOException) { }
        }
    }
}
