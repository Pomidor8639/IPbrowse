package com.ipbrowse.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ipbrowse.scanner.MassScanEvent
import com.ipbrowse.scanner.MassScanHit
import com.ipbrowse.scanner.MassScanOptions
import com.ipbrowse.scanner.MassScanRunner
import com.ipbrowse.scanner.Targets
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Состояние вкладки «Массовое сканирование». В отличие от десктопа,
 * на Android нет файлового пикера прямо к нативному tkinter-диалогу —
 * пользователь вводит / вставляет список IP в текстовое поле, и
 * IPs парсятся как для обычной цели (одна строка на адрес или CSV).
 */
data class MassScanUiState(
    val targets: String = "",
    val ports: String = "22,80,443",
    val workers: Int = 200,
    val timeoutMs: Int = 600,
    val isScanning: Boolean = false,
    val progressDone: Int = 0,
    val progressTotal: Int = 0,
    val hits: List<MassScanHit> = emptyList(),
    val statusMessage: String = "",
    val errorMessage: String? = null,
    val filter: String = "",
)

class MassScanViewModel : ViewModel() {

    private val _state = MutableStateFlow(MassScanUiState())
    val state: StateFlow<MassScanUiState> = _state.asStateFlow()

    private var scanJob: Job? = null

    fun setTargets(value: String) = _state.update { it.copy(targets = value) }
    fun setPorts(value: String) = _state.update { it.copy(ports = value) }
    fun setWorkers(value: Int) = _state.update { it.copy(workers = value.coerceIn(1, 1024)) }
    fun setTimeoutMs(value: Int) = _state.update { it.copy(timeoutMs = value.coerceIn(50, 10_000)) }
    fun setFilter(value: String) = _state.update { it.copy(filter = value) }
    fun clearError() = _state.update { it.copy(errorMessage = null) }

    fun startScan() {
        val s = _state.value
        if (s.isScanning) return
        val ips = parseTargets(s.targets)
        if (ips.isEmpty()) {
            _state.update { it.copy(errorMessage = "Введите список IP или CIDR") }
            return
        }
        val ports = parsePorts(s.ports)
        if (ports.isEmpty()) {
            _state.update { it.copy(errorMessage = "Введите хотя бы один порт") }
            return
        }
        val total = ips.size * ports.size
        _state.update {
            it.copy(
                isScanning = true,
                hits = emptyList(),
                progressDone = 0,
                progressTotal = total,
                statusMessage = "Запущено · цели: ${ips.size}, порты: ${ports.size}",
                errorMessage = null,
            )
        }
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            try {
                val opts = MassScanOptions(
                    ips = ips,
                    ports = ports,
                    workers = s.workers,
                    timeoutMs = s.timeoutMs,
                )
                MassScanRunner.run(opts).collect { ev ->
                    when (ev) {
                        is MassScanEvent.Hit -> _state.update {
                            it.copy(hits = it.hits + ev.hit)
                        }
                        is MassScanEvent.Progress -> _state.update {
                            it.copy(progressDone = ev.done, progressTotal = ev.total)
                        }
                        MassScanEvent.Done -> _state.update {
                            it.copy(
                                isScanning = false,
                                statusMessage = "Готово · открытых: ${it.hits.size} из ${it.progressTotal}",
                            )
                        }
                    }
                }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(
                        isScanning = false,
                        errorMessage = t.message ?: t::class.java.simpleName,
                        statusMessage = "Ошибка",
                    )
                }
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        scanJob = null
        _state.update { it.copy(isScanning = false, statusMessage = "Остановлено") }
    }

    private fun parseTargets(text: String): List<String> {
        // Поддерживаем и `,` и переносы строк — типичные источники списков (CSV / txt).
        val flat = text.replace("\r", "").split("\n", ",").map { it.trim() }.filter { it.isNotEmpty() }
        val out = LinkedHashSet<String>()
        for (line in flat) {
            // Каждый кусок может быть отдельным IP, CIDR или диапазоном — пропускаем
            // через тот же `Targets.expand`, что и обычная вкладка.
            for (ip in Targets.expand(line)) out.add(ip)
        }
        return out.toList()
    }

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
            } catch (_: NumberFormatException) { }
        }
        return out.toList()
    }
}
