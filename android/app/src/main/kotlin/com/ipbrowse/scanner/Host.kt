package com.ipbrowse.scanner

/**
 * Запись об одном хосте — Android-порт `dataclass Host` из `scanner.py`.
 *
 * Поля `mac` / `vendor` оставлены для совместимости с UI: на Android без root
 * ARP-таблица соседей недоступна, поэтому в подавляющем большинстве случаев
 * они останутся пустыми. Заполняются для шлюза по данным DHCP.
 */
data class Host(
    val ip: String,
    val alive: Boolean = false,
    val hostname: String = "",
    val mac: String = "",
    val vendor: String = "",
    val openPorts: List<Int> = emptyList(),
    val responseMs: Double? = null,
    val ttl: Int? = null,
    val osGuess: String = "",
    val banners: Map<Int, String> = emptyMap(),
    val portScanDone: Int = 0,
    val portScanTotal: Int = 0,
    val scanComplete: Boolean = false,
)
