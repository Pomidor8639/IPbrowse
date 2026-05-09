package com.ipbrowse.scanner

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * Параметры одного запуска — Android-эквивалент `ScanFlags` + аргументов
 * `scan_network` из scanner.py. То, что физически невозможно без root, в
 * настройках помечено как информационный «не работает на Android».
 */
data class ScanOptions(
    val targets: List<String>,
    val ports: List<Int> = emptyList(),
    val pingTimeoutMs: Int = 700,
    val pingRetries: Int = 1,
    val portTimeoutMs: Int = 600,
    val workers: Int = 64,
    val portWorkers: Int = 64,
    val resolveHostnames: Boolean = true,
    val skipPing: Boolean = false,        // -Pn
    val osDetect: Boolean = false,        // -O (ограниченно: TTL по ICMP недоступен без root)
    val versionDetect: Boolean = false,   // -sV
    val randomizePorts: Boolean = false,
    val randomizeHosts: Boolean = false,
)

/**
 * Поток событий: каждое событие — обновлённый `Host`. UI просто заменяет
 * запись по `ip` в общем списке. Ровно как `on_host_update` в десктопе.
 */
sealed interface ScanEvent {
    data class HostUpdate(val host: Host) : ScanEvent
    data object Done : ScanEvent
}

object ScanRunner {

    fun run(opts: ScanOptions): Flow<ScanEvent> = channelFlow {
        try {
            val targets = if (opts.randomizeHosts) opts.targets.shuffled() else opts.targets
            val ports = if (opts.randomizePorts) opts.ports.shuffled() else opts.ports

            // Фаза 1: ping sweep.
            val phase1Sem = Semaphore(opts.workers.coerceIn(1, 256))
            val aliveHosts = ArrayList<Host>()
            coroutineScope {
                val deferred = targets.map { ip ->
                    async(Dispatchers.IO) {
                        if (!isActive) return@async null
                        val host = if (opts.skipPing) {
                            Host(ip = ip, alive = true, portScanTotal = ports.size)
                        } else {
                            phase1Sem.withPermit {
                                var alive = false
                                var rtt: Double? = null
                                var ttl: Int? = null
                                repeat(opts.pingRetries.coerceAtLeast(1)) {
                                    if (alive) return@repeat
                                    val r = PingScanner.ping(ip, opts.pingTimeoutMs)
                                    if (r.alive) {
                                        alive = true; rtt = r.responseMs; ttl = r.ttl
                                    }
                                }
                                Host(
                                    ip = ip,
                                    alive = alive,
                                    responseMs = rtt,
                                    ttl = ttl,
                                    osGuess = if (opts.osDetect) guessOsFromTtl(ttl) else "",
                                    portScanTotal = ports.size,
                                    scanComplete = !alive,
                                )
                            }
                        }
                        send(ScanEvent.HostUpdate(host))
                        if (host.alive) host else null
                    }
                }
                deferred.awaitAll().filterNotNull().forEach(aliveHosts::add)
            }
            if (!isActive) return@channelFlow

            // Фаза 2: обогащение живых хостов (DNS + порты + баннеры).
            val phase2Sem = Semaphore(opts.workers.coerceIn(1, 64))
            coroutineScope {
                aliveHosts.map { initial ->
                    async(Dispatchers.IO) {
                        if (!isActive) return@async
                        phase2Sem.withPermit {
                            var host = initial
                            if (opts.resolveHostnames) {
                                val name = resolveHostname(initial.ip)
                                if (name.isNotEmpty()) {
                                    host = host.copy(hostname = name)
                                    send(ScanEvent.HostUpdate(host))
                                }
                            }
                            if (ports.isNotEmpty()) {
                                val open = PortScanner.scanPorts(
                                    scope = this@channelFlow,
                                    ip = host.ip,
                                    ports = ports,
                                    timeoutMs = opts.portTimeoutMs,
                                    workers = opts.portWorkers,
                                ) { d, t ->
                                    val snapshot = host.copy(portScanDone = d, portScanTotal = t)
                                    trySend(ScanEvent.HostUpdate(snapshot))
                                }
                                host = host.copy(openPorts = open, portScanDone = ports.size, portScanTotal = ports.size)
                                if (opts.versionDetect && open.isNotEmpty()) {
                                    val grabbed = HashMap<Int, String>()
                                    val bSem = Semaphore(opts.portWorkers.coerceIn(1, 32))
                                    coroutineScope {
                                        open.map { p ->
                                            async(Dispatchers.IO) {
                                                bSem.withPermit {
                                                    val b = BannerGrabber.grab(host.ip, p, opts.portTimeoutMs * 2)
                                                    if (b.isNotEmpty()) synchronized(grabbed) { grabbed[p] = b }
                                                }
                                            }
                                        }.awaitAll()
                                    }
                                    if (grabbed.isNotEmpty()) host = host.copy(banners = grabbed)
                                }
                            }
                            host = host.copy(scanComplete = true)
                            send(ScanEvent.HostUpdate(host))
                        }
                    }
                }.awaitAll()
            }
            send(ScanEvent.Done)
        } catch (_: CancellationException) {
            // нормальная отмена — выходим без события
            throw CancellationException()
        }
    }

    private suspend fun resolveHostname(ip: String): String = withContext(Dispatchers.IO) {
        try {
            val name = InetAddress.getByName(ip).canonicalHostName
            // canonicalHostName при невозможности резолва вернёт сам IP — это не имя.
            if (name.equals(ip, ignoreCase = true)) "" else name
        } catch (_: Throwable) {
            ""
        }
    }

    fun guessOsFromTtl(ttl: Int?): String {
        if (ttl == null || ttl <= 0) return ""
        return when {
            ttl <= 64 -> "Linux/macOS"
            ttl <= 128 -> "Windows"
            else -> "Сетевое устройство"
        }
    }
}
