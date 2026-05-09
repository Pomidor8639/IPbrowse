package com.ipbrowse.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.ipbrowse.ui.MassScanViewModel
import kotlinx.coroutines.launch

/**
 * Вкладка «Массовое сканирование» — Android-аналог `MassScanTab`.
 * Показываем только успешные коннекты (открытые порты), как в десктопе.
 * Прогресс отдельно — закрытые / timeout не пишем в список (это и
 * раньше тормозило UI на 65k-проб).
 */
@Composable
fun MassScanScreen(vm: MassScanViewModel) {
    val state by vm.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let {
            snackbar.showSnackbar(it)
            vm.clearError()
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
            OutlinedTextField(
                value = state.targets,
                onValueChange = vm::setTargets,
                label = { Text("Цели (по одной на строке или через запятую)") },
                placeholder = { Text("например, 192.168.1.0/24\n10.0.0.1-50\n8.8.8.8") },
                modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp),
                maxLines = 6,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.ports,
                onValueChange = vm::setPorts,
                label = { Text("Порты") },
                placeholder = { Text("например, 22 или 22,80,443") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = state.workers.toString(),
                    onValueChange = { v -> v.toIntOrNull()?.let(vm::setWorkers) },
                    label = { Text("Потоков") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                OutlinedTextField(
                    value = state.timeoutMs.toString(),
                    onValueChange = { v -> v.toIntOrNull()?.let(vm::setTimeoutMs) },
                    label = { Text("Таймаут, мс") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(
                    onClick = vm::startScan,
                    enabled = !state.isScanning,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                ) { Text("Сканировать") }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = vm::stopScan,
                    enabled = state.isScanning,
                ) { Text("Остановить") }
            }
            Spacer(Modifier.height(8.dp))
            if (state.progressTotal > 0) {
                LinearProgressIndicator(
                    progress = { state.progressDone.toFloat() / state.progressTotal.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.tertiary,
                )
                Spacer(Modifier.height(2.dp))
            }
            Text(
                text = state.statusMessage.ifBlank {
                    if (state.progressTotal > 0) "${state.progressDone} / ${state.progressTotal}" else ""
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.filter,
                onValueChange = vm::setFilter,
                label = { Text("Фильтр (IP / порт)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(6.dp))

            val visibleHits = remember(state.hits, state.filter) {
                val q = state.filter.trim().lowercase()
                if (q.isEmpty()) state.hits else state.hits.filter {
                    it.ip.contains(q, true) || it.port.toString().contains(q)
                }
            }

            // ---- Заголовок ----
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(vertical = 6.dp, horizontal = 8.dp),
            ) {
                Text("IP", modifier = Modifier.weight(1.6f),
                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                Text("Порт", modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                Text("RTT, мс", modifier = Modifier.weight(1f),
                    color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
            }

            LazyColumn(modifier = Modifier.fillMaxSize().padding(top = 4.dp)) {
                items(visibleHits, key = { "${it.ip}:${it.port}" }) { hit ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surface)
                            .padding(vertical = 8.dp, horizontal = 8.dp),
                    ) {
                        Text(
                            text = hit.ip,
                            modifier = Modifier.weight(1.6f),
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.tertiary,
                        )
                        Text(
                            text = hit.port.toString(),
                            modifier = Modifier.weight(1f),
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            text = String.format("%.1f", hit.rttMs),
                            modifier = Modifier.weight(1f),
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
                    )
                }
            }
        }

        SnackbarHost(
            hostState = snackbar,
            modifier = Modifier.align(Alignment.BottomCenter),
            snackbar = { Snackbar(it) },
        )
    }
}
