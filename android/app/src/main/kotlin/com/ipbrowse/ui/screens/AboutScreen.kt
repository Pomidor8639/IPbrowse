package com.ipbrowse.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

private const val GITHUB_URL = "https://github.com/Pomidor8639/IPbrowse"

/**
 * Вкладка «О программе» — короткое описание, перечень фич, ссылки на
 * GitHub / issues / лицензию / реестр портов IANA. Один-в-один с
 * `AboutTab` десктопа, только текст «PySide6» заменён на «Jetpack
 * Compose».
 */
@Composable
fun AboutScreen() {
    val context = LocalContext.current
    val openUrl = { url: String ->
        context.startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(url))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "IPbrowse",
            style = MaterialTheme.typography.headlineLarge,
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "Сканер локальной сети с интерфейсом на Jetpack Compose",
            color = MaterialTheme.colorScheme.tertiary,
            style = MaterialTheme.typography.bodyMedium,
        )

        Text(
            text = "IPbrowse находит активные устройства в подсети, определяет имена хостов, " +
                "сканирует открытые TCP-порты, поддерживает массовое сканирование списка адресов " +
                "и подбирает баннеры сервисов. На Android из-за отсутствия root некоторые " +
                "возможности (ARP-таблица, ICMP-пинг) ограничены — используется TCP-touch как " +
                "fallback.",
            color = MaterialTheme.colorScheme.onSurface,
        )

        Text(
            text = "Возможности",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.secondary,
            fontWeight = FontWeight.Bold,
        )
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                listOf(
                    "Ping-сканирование подсетей, диапазонов и одиночных IP (CIDR / range / список)",
                    "Резолв имени хоста (reverse DNS)",
                    "TCP-connect сканирование портов с настраиваемой параллельностью",
                    "Снятие баннеров сервисов (-sV) и грубое определение ОС по TTL (-O)",
                    "Wi-Fi: текущая сеть, шлюз, IP, DNS",
                    "Массовое сканирование одного / нескольких портов по списку IP",
                    "Фильтрация и сортировка результатов в реальном времени",
                    "Реестр портов IANA в комплекте (res/raw/ports.csv)",
                    "Тёмная тема Catppuccin Mocha",
                ).forEach { line ->
                    Text(
                        text = "• $line",
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(vertical = 2.dp),
                    )
                }
            }
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(
                    text = "Совет",
                    color = MaterialTheme.colorScheme.secondary,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Тапните по строке хоста на любой вкладке сканирования — откроется список " +
                        "открытых портов с расшифровкой сервиса и кнопкой «Узнать больше», которая " +
                        "ведёт в Google на русском языке.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Text(
            text = "Ссылки",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.secondary,
            fontWeight = FontWeight.Bold,
        )
        LinkRow("GitHub", GITHUB_URL, openUrl)
        LinkRow("Сообщить о проблеме", "$GITHUB_URL/issues", openUrl)
        LinkRow("Лицензия (MIT)", "$GITHUB_URL/blob/main/LICENSE", openUrl)
        LinkRow(
            "Реестр портов IANA",
            "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml",
            openUrl,
        )

        Text(
            text = "Jetpack Compose · Material 3 · Kotlin · реестр портов IANA включён в комплект (res/raw/ports.csv)",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun LinkRow(label: String, url: String, openUrl: (String) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f),
        )
        TextButton(onClick = { openUrl(url) }) {
            Text(text = "Открыть")
        }
    }
}
