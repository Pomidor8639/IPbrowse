package com.ipbrowse.scanner

import java.net.InetAddress

/**
 * Разворачивание строки-цели в список IP — порт `expand_target` из scanner.py.
 *
 * Поддерживает: "192.168.1.0/24", "192.168.1.1-50", "192.168.1.1-192.168.2.10",
 * одиночный IP, и любые их комбинации через запятую.
 */
object Targets {

    fun expand(target: String): List<String> {
        val raw = target.trim()
        if (raw.isEmpty()) return emptyList()

        val out = LinkedHashSet<String>()
        for (chunk in raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }) {
            try {
                when {
                    "/" in chunk -> expandCidr(chunk).forEach(out::add)
                    "-" in chunk -> expandRange(chunk).forEach(out::add)
                    else -> out.add(InetAddress.getByName(chunk).hostAddress ?: chunk)
                }
            } catch (_: Throwable) {
                // Молча пропускаем невалидные куски — UI отдельно валидирует
                // ввод, но в массовом списке пользователь может вставить мусор.
            }
        }
        return out.toList()
    }

    private fun expandCidr(cidr: String): List<String> {
        val (addr, prefix) = cidr.split("/")
        val prefixLen = prefix.toInt()
        if (prefixLen !in 0..32) return emptyList()
        val base = ipv4ToLong(addr)
        // Сеть приводим к канонической форме (обнуляем хостовую часть).
        val mask = if (prefixLen == 0) 0L else (-1L shl (32 - prefixLen)) and 0xFFFFFFFFL
        val networkLong = base and mask
        val total = if (prefixLen >= 31) 1L shl (32 - prefixLen) else (1L shl (32 - prefixLen)) - 2
        val first = if (prefixLen >= 31) networkLong else networkLong + 1
        val out = ArrayList<String>(total.toInt().coerceAtMost(65536))
        var cur = first
        var left = total
        while (left > 0) {
            out.add(longToIpv4(cur))
            cur++
            left--
        }
        return out
    }

    private fun expandRange(chunk: String): List<String> {
        val dashIdx = chunk.indexOf('-')
        val left = chunk.substring(0, dashIdx)
        val right = chunk.substring(dashIdx + 1)
        // Полный диапазон вида "192.168.1.1-192.168.2.10".
        if ("." in right) {
            val a = ipv4ToLong(left)
            val b = ipv4ToLong(right)
            if (a > b) return emptyList()
            val out = ArrayList<String>((b - a + 1).toInt().coerceAtMost(65536))
            var cur = a
            while (cur <= b) {
                out.add(longToIpv4(cur))
                cur++
            }
            return out
        }
        // Сокращённый "192.168.1.1-50": правая часть — только последний октет.
        val baseDot = left.lastIndexOf('.')
        if (baseDot < 0) return emptyList()
        val base = left.substring(0, baseDot)
        val start = left.substring(baseDot + 1).toInt()
        val end = right.toInt()
        if (start > end) return emptyList()
        return (start..end).map { "$base.$it" }
    }

    private fun ipv4ToLong(ip: String): Long {
        val parts = ip.split(".")
        require(parts.size == 4)
        var v = 0L
        for (p in parts) {
            val octet = p.toInt()
            require(octet in 0..255)
            v = (v shl 8) or octet.toLong()
        }
        return v and 0xFFFFFFFFL
    }

    private fun longToIpv4(v: Long): String {
        return "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"
    }
}
