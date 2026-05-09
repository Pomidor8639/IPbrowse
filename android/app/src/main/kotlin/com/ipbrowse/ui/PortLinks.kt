package com.ipbrowse.ui

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Один-в-один с `_google_search_url_for_port` из app.py: открываем
 * google.com в русской локали с запросом «что такое порт N tcp».
 */
fun googleSearchUrlForPort(port: Int, proto: String = "tcp"): String {
    val q = "что такое порт $port $proto"
    val enc = URLEncoder.encode(q, StandardCharsets.UTF_8.name())
    return "https://www.google.com/search?hl=ru&q=$enc"
}
