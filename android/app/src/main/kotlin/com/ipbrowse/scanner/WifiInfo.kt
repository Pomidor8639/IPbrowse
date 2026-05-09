package com.ipbrowse.scanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import java.io.BufferedReader
import java.io.FileReader
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Информация о сети — Android-эквивалент `get_wifi_info` / `get_default_gateway`
 * / `detect_local_subnet` из scanner.py. Всё, что собрали, упаковано в один
 * `Snapshot`, чтобы UI мог отрисовать одной таблицей.
 */
object WifiInfo {

    data class Snapshot(
        val ssid: String? = null,
        val bssid: String? = null,
        val frequencyMhz: Int? = null,
        val linkSpeedMbps: Int? = null,
        val rssiDbm: Int? = null,
        val ipv4: String? = null,
        val gateway: String? = null,
        val dnsServers: List<String> = emptyList(),
        val subnetCidr: String? = null,
        val gatewayMac: String? = null,
    )

    fun read(context: Context): Snapshot {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager

        var ssid: String? = null
        var bssid: String? = null
        var freq: Int? = null
        var speed: Int? = null
        var rssi: Int? = null

        try {
            @Suppress("DEPRECATION")
            val connInfo = wm?.connectionInfo
            if (connInfo != null) {
                val rawSsid = connInfo.ssid?.removeSurrounding("\"")
                ssid = if (rawSsid.isNullOrBlank() || rawSsid == "<unknown ssid>") null else rawSsid
                bssid = connInfo.bssid?.takeIf { it != "02:00:00:00:00:00" }
                speed = connInfo.linkSpeed.takeIf { it > 0 }
                rssi = connInfo.rssi.takeIf { it != Int.MIN_VALUE }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    freq = connInfo.frequency.takeIf { it > 0 }
                }
            }
        } catch (_: SecurityException) {
            // Без ACCESS_FINE_LOCATION нам отдадут "<unknown ssid>" — нормально.
        }

        var ipv4: String? = null
        var gateway: String? = null
        var dns = emptyList<String>()

        if (cm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val active = cm.activeNetwork
            if (active != null) {
                val link: LinkProperties? = cm.getLinkProperties(active)
                val caps: NetworkCapabilities? = cm.getNetworkCapabilities(active)
                if (link != null) {
                    ipv4 = link.linkAddresses
                        .firstOrNull { it.address is Inet4Address && !it.address.isLoopbackAddress }
                        ?.address?.hostAddress
                    gateway = link.routes
                        .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
                        ?.gateway?.hostAddress
                    dns = link.dnsServers.mapNotNull { it.hostAddress }
                }
                // Если нет вай-фая — вытащим SSID хотя бы для VPN-туннелей.
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI).not() && ssid == null) {
                    ssid = ""
                }
            }
        }

        // /24 для текущего IPv4 — ровно как detect_local_subnet (это самая
        // ходовая локалка; точную маску из LinkProperties достаём при наличии).
        val subnet = ipv4?.let { ip ->
            val parts = ip.split(".")
            if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}.0/24" else null
        }

        // ARP /proc/net/arp — на Android 10+ выпилен/закрыт. Пробуем без шума.
        val gatewayMac = gateway?.let { findMacFromProcArp(it) }

        return Snapshot(
            ssid = ssid,
            bssid = bssid,
            frequencyMhz = freq,
            linkSpeedMbps = speed,
            rssiDbm = rssi,
            ipv4 = ipv4 ?: fallbackIpv4(),
            gateway = gateway,
            dnsServers = dns,
            subnetCidr = subnet,
            gatewayMac = gatewayMac,
        )
    }

    /** Резервный путь: если CONNECTIVITY_SERVICE нам ничего не сказал — берём
     *  первый non-loopback IPv4 у любого интерфейса. */
    private fun fallbackIpv4(): String? = try {
        NetworkInterface.getNetworkInterfaces().toList()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
            ?.hostAddress
    } catch (_: Throwable) { null }

    /**
     * Best-effort чтение /proc/net/arp. На Android < 10 файл часто доступен,
     * на 10+ — обычно пустой/закрыт. Если ничего не получилось — пусто, без
     * исключений.
     */
    private fun findMacFromProcArp(ip: String): String? = try {
        BufferedReader(FileReader("/proc/net/arp")).use { br ->
            br.readLine() // header
            br.lineSequence().mapNotNull { line ->
                val parts = line.split(Regex("\\s+"))
                if (parts.size >= 4 && parts[0] == ip) parts[3] else null
            }.firstOrNull()?.takeIf { it.isNotBlank() && it != "00:00:00:00:00:00" }
        }
    } catch (_: Throwable) { null }
}
