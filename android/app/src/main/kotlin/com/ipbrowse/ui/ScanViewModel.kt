package com.ipbrowse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ipbrowse.scanner.Host
import com.ipbrowse.scanner.ScanEvent
import com.ipbrowse.scanner.ScanOptions
import com.ipbrowse.scanner.ScanRunner
import com.ipbrowse.scanner.Targets
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * UI-состояние одной вкладки сканирования. Один `ScanViewModel` —
 * одна вкладка (Local / External). Два экземпляра в `IPbrowseApp` нужны
 * именно потому, что у них разное состояние и независимые запуски.
 */
data class ScanUiState(
    val target: String = "",
    val ports: String = "22,80,443,3389",
    val resolveHostnames: Boolean = true,
    val skipPing: Boolean = false,
    val osDetect: Boolean = false,
    val versionDetect: Boolean = false,
    val workers: Int = 64,
    val portWorkers: Int = 64,
    val pingTimeoutMs: Int = 700,
    val portTimeoutMs: Int = 600,
    val pingRetries: Int = 1,
    val randomizePorts: Boolean = false,
    val randomizeHosts: Boolean = false,
    val showOnlyAlive: Boolean = true,
    val filter: String = "",

    val isScanning: Boolean = false,
    val progressDone: Int = 0,
    val progressTotal: Int = 0,
    val statusMessage: String = "Готов к сканированию",
    val errorMessage: String? = null,
    val hosts: List<Host> = emptyList(),
)

class ScanViewModel : ViewModel() {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    private var scanJob: Job? = null

    fun setTarget(value: String) = _state.update { it.copy(target = value) }
    fun setPorts(value: String) = _state.update { it.copy(ports = value) }
    fun setFilter(value: String) = _state.update { it.copy(filter = value) }
    fun setResolveHostnames(value: Boolean) = _state.update { it.copy(resolveHostnames = value) }
    fun setSkipPing(value: Boolean) = _state.update { it.copy(skipPing = value) }
    fun setOsDetect(value: Boolean) = _state.update { it.copy(osDetect = value) }
    fun setVersionDetect(value: Boolean) = _state.update { it.copy(versionDetect = value) }
    fun setRandomizePorts(value: Boolean) = _state.update { it.copy(randomizePorts = value) }
    fun setRandomizeHosts(value: Boolean) = _state.update { it.copy(randomizeHosts = value) }
    fun setShowOnlyAlive(value: Boolean) = _state.update { it.copy(showOnlyAlive = value) }
    fun setWorkers(value: Int) = _state.update { it.copy(workers = value.coerceIn(1, 256)) }
    fun setPortWorkers(value: Int) = _state.update { it.copy(portWorkers = value.coerceIn(1, 256)) }
    fun setPingTimeoutMs(value: Int) = _state.update { it.copy(pingTimeoutMs = value.coerceIn(50, 10_000)) }
    fun setPortTimeoutMs(value: Int) = _state.update { it.copy(portTimeoutMs = value.coerceIn(50, 10_000)) }
    fun setPingRetries(value: Int) = _state.update { it.copy(pingRetries = value.coerceIn(1, 5)) }

    fun setDefaultTarget(value: String) {
        _state.update { if (it.target.isBlank()) it.copy(target = value) else it }
    }

    /**
     * Запускает фазу1+2 сканера и склеивает события в живой список хостов.
     * Параллельные запуски той же вкладки не запускаются — старый Job
     * отменяется (хотя UI и так дизейблит кнопку «Сканировать»).
     */
    fun startScan() {
        val s = _state.value
        if (s.isScanning) return
        val targets = Targets.expand(s.target)
        if (targets.isEmpty()) {
            _state.update { it.copy(errorMessage = "Введите хотя бы один IP / диапазон / CIDR") }
            return
        }
        val ports = parsePorts(s.ports)

        _state.update {
            it.copy(
                isScanning = true,
                progressDone = 0,
                progressTotal = targets.size,
                hosts = targets.map { ip -> Host(ip = ip, portScanTotal = ports.size) },
                statusMessage = "Сканирование ${targets.size} адресов…",
                errorMessage = null,
            )
        }
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            try {
                val opts = ScanOptions(
                    targets = targets,
                    ports = ports,
                    pingTimeoutMs = s.pingTimeoutMs,
                    pingRetries = s.pingRetries,
                    portTimeoutMs = s.portTimeoutMs,
                    workers = s.workers,
                    portWorkers = s.portWorkers,
                    resolveHostnames = s.resolveHostnames,
                    skipPing = s.skipPing,
                    osDetect = s.osDetect,
                    versionDetect = s.versionDetect,
                    randomizePorts = s.randomizePorts,
                    randomizeHosts = s.randomizeHosts,
                )
                ScanRunner.run(opts).collect { ev ->
                    when (ev) {
                        is ScanEvent.HostUpdate -> applyHostUpdate(ev.host)
                        ScanEvent.Done -> _state.update {
                            it.copy(
                                isScanning = false,
                                statusMessage = "Готово · живых: ${it.hosts.count { h -> h.alive }} из ${it.hosts.size}",
                            )
                        }
                    }
                }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(
                        isScanning = false,
                        errorMessage = t.message ?: t::class.java.simpleName,
                        statusMessage = "Ошибка сканирования",
                    )
                }
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        scanJob = null
        _state.update {
            it.copy(
                isScanning = false,
                statusMessage = "Сканирование остановлено",
            )
        }
    }

    fun clearError() = _state.update { it.copy(errorMessage = null) }

    private fun applyHostUpdate(updated: Host) {
        _state.update { st ->
            val newHosts = st.hosts.map { h -> if (h.ip == updated.ip) updated else h }
            // Прогресс — сколько хостов уже завершили обе фазы (или признаны мёртвыми).
            val done = newHosts.count { it.scanComplete }
            st.copy(
                hosts = newHosts,
                progressDone = done,
                progressTotal = newHosts.size,
            )
        }
    }

    /**
     * "22,80,1000-1010" → [22, 80, 1000..1010] с дедупликацией.
     * Невалидные куски молча игнорируются (UI это и так подсветит пустым списком).
     */
    private fun parsePorts(text: String): List<Int> {
        val out = LinkedHashSet<Int>()
        for (chunk in text.split(",", " ", "\n", "\t").map { it.trim() }.filter { it.isNotEmpty() }) {
            try {
                if ("-" in chunk) {
                    val (a, b) = chunk.split("-")
                    val start = a.toInt()
                    val end = b.toInt()
                    if (start in 1..65535 && end in start..65535) {
                        for (p in start..end) out.add(p)
                    }
                } else {
                    val p = chunk.toInt()
                    if (p in 1..65535) out.add(p)
                }
            } catch (_: NumberFormatException) {
                // мусор — пропускаем
            }
        }
        return out.toList()
    }
}
