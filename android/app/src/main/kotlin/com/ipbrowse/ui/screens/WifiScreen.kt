package com.ipbrowse.ui.screens

import android.Manifest
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import com.ipbrowse.ui.WifiViewModel

/**
 * Вкладка «Wi-Fi» — отображение информации о текущей сети, шлюзе, DNS,
 * рассчитанной /24-подсети. Аналог `WifiTab` из app.py, но без сканера
 * соседей: на Android без root полноценный ARP не отдаёт MAC-таблицу,
 * клиентов сети считать честно нельзя — используем основную вкладку
 * сканера для этого.
 */
@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun WifiScreen(vm: WifiViewModel) {
    val state by vm.state.collectAsState()
    val locationPerm = rememberPermissionState(Manifest.permission.ACCESS_FINE_LOCATION)

    LaunchedEffect(locationPerm.status.isGranted) {
        if (locationPerm.status.isGranted) vm.refresh()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
    ) {
        Text(
            text = "Текущая сеть",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.secondary,
        )
        Spacer(Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface,
            ),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                val s = state.snapshot
                InfoRow("SSID", s.ssid?.takeIf { it.isNotBlank() } ?: "—")
                InfoRow("BSSID", s.bssid?.uppercase() ?: "—")
                InfoRow("Частота", s.frequencyMhz?.let { "$it МГц" } ?: "—")
                InfoRow("Скорость", s.linkSpeedMbps?.let { "$it Мбит/с" } ?: "—")
                InfoRow("Сигнал", s.rssiDbm?.let { "$it дБм" } ?: "—")
                InfoRow("IP-адрес", s.ipv4 ?: "—", mono = true)
                InfoRow("Подсеть", s.subnetCidr ?: "—", mono = true)
                InfoRow("Шлюз", s.gateway ?: "—", mono = true)
                InfoRow("MAC шлюза", s.gatewayMac?.uppercase() ?: "—", mono = true)
                InfoRow(
                    "DNS-серверы",
                    s.dnsServers.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: "—",
                    mono = true,
                )
            }
        }

        Spacer(Modifier.height(12.dp))

        if (!locationPerm.status.isGranted && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.3f),
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "Для получения SSID и BSSID нужно разрешение на доступ к местоположению (Android 8.1+).",
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = { locationPerm.launchPermissionRequest() }) {
                        Text("Дать разрешение")
                    }
                }
            }
            Spacer(Modifier.height(12.dp))
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            Button(onClick = vm::refresh, enabled = !state.isLoading) {
                Text(if (state.isLoading) "Обновление…" else "Обновить")
            }
        }
        state.errorMessage?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(
            text = label,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(120.dp),
            fontWeight = FontWeight.Medium,
        )
        Text(
            text = value,
            color = MaterialTheme.colorScheme.onSurface,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
            modifier = Modifier.weight(1f),
        )
    }
}
