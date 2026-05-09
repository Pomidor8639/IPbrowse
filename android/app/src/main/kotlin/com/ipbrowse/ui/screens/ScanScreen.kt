package com.ipbrowse.ui.screens

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.ipbrowse.scanner.Host
import com.ipbrowse.scanner.WifiInfo
import com.ipbrowse.ui.ScanViewModel
import kotlinx.coroutines.launch

/**
 * Универсальная вкладка сканирования — используется и для «Локальной сети»,
 * и для «Внешних сетей». Различия: `showAutoDetect` (кнопка «Моя подсеть»)
 * и опциональный `warningText` (баннер про правила/легальность).
 *
 * Раскладка: настройки сверху, потом прогресс / статус, потом таблица
 * хостов как `LazyColumn`. Таблица заменяет десктопную QTableView,
 * фильтр и «только живые» работают как там.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    vm: ScanViewModel,
    showAutoDetect: Boolean,
    warningText: String?,
) {
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    var selectedHost by remember { mutableStateOf<Host?>(null) }
    var settingsExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let {
            snackbar.showSnackbar(it)
            vm.clearError()
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
            if (warningText != null) {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.4f),
                    ),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = warningText,
                        modifier = Modifier.padding(12.dp),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(8.dp))
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = state.target,
                    onValueChange = vm::setTarget,
                    label = { Text("Цель") },
                    placeholder = { Text("например, 192.168.1.0/24 или 192.168.1.1-50") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                if (showAutoDetect) {
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = {
                        WifiInfo.read(context).subnetCidr?.let { vm.setTarget(it) }
                    }) {
                        Text("Моя подсеть")
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            OutlinedTextField(
                value = state.ports,
                onValueChange = vm::setPorts,
                label = { Text("Порты") },
                placeholder = { Text("например, 22,80,443,3389 или 1-65535") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

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
                Spacer(Modifier.weight(1f))
                Box {
                    IconButton(onClick = { settingsExpanded = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Настройки")
                    }
                    DropdownMenu(
                        expanded = settingsExpanded,
                        onDismissRequest = { settingsExpanded = false },
                    ) {
                        DropdownMenuItem(
                            text = { ScanCheckbox("Резолв имён", state.resolveHostnames, vm::setResolveHostnames) },
                            onClick = { vm.setResolveHostnames(!state.resolveHostnames) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("Не пинговать (-Pn)", state.skipPing, vm::setSkipPing) },
                            onClick = { vm.setSkipPing(!state.skipPing) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("ОС по TTL (-O)", state.osDetect, vm::setOsDetect) },
                            onClick = { vm.setOsDetect(!state.osDetect) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("Баннеры (-sV)", state.versionDetect, vm::setVersionDetect) },
                            onClick = { vm.setVersionDetect(!state.versionDetect) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("Перемешать порты", state.randomizePorts, vm::setRandomizePorts) },
                            onClick = { vm.setRandomizePorts(!state.randomizePorts) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("Перемешать хосты", state.randomizeHosts, vm::setRandomizeHosts) },
                            onClick = { vm.setRandomizeHosts(!state.randomizeHosts) },
                        )
                        DropdownMenuItem(
                            text = { ScanCheckbox("Только живые", state.showOnlyAlive, vm::setShowOnlyAlive) },
                            onClick = { vm.setShowOnlyAlive(!state.showOnlyAlive) },
                        )
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("Параллельность хостов: ${state.workers}") },
                            onClick = { vm.setWorkers((state.workers % 256) + 16) },
                        )
                        DropdownMenuItem(
                            text = { Text("Параллельность портов: ${state.portWorkers}") },
                            onClick = { vm.setPortWorkers((state.portWorkers % 256) + 16) },
                        )
                        DropdownMenuItem(
                            text = { Text("Таймаут пинга: ${state.pingTimeoutMs} мс") },
                            onClick = { vm.setPingTimeoutMs((state.pingTimeoutMs + 200).coerceAtMost(5000)) },
                        )
                        DropdownMenuItem(
                            text = { Text("Таймаут портов: ${state.portTimeoutMs} мс") },
                            onClick = { vm.setPortTimeoutMs((state.portTimeoutMs + 200).coerceAtMost(5000)) },
                        )
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            val total = state.progressTotal
            if (total > 0) {
                LinearProgressIndicator(
                    progress = { state.progressDone.toFloat() / total.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                    color = MaterialTheme.colorScheme.tertiary,
                )
                Spacer(Modifier.height(2.dp))
            }

            Text(
                text = state.statusMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(6.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = state.filter,
                    onValueChange = vm::setFilter,
                    label = { Text("Фильтр") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                ScanCheckbox(
                    label = "Только живые",
                    checked = state.showOnlyAlive,
                    onChange = vm::setShowOnlyAlive,
                )
            }

            Spacer(Modifier.height(6.dp))

            val visibleHosts = remember(state.hosts, state.filter, state.showOnlyAlive) {
                val q = state.filter.trim().lowercase()
                state.hosts.asSequence()
                    .filter { !state.showOnlyAlive || it.alive }
                    .filter {
                        q.isEmpty() ||
                            it.ip.contains(q, true) ||
                            it.hostname.contains(q, true) ||
                            it.mac.contains(q, true) ||
                            it.vendor.contains(q, true) ||
                            it.osGuess.contains(q, true) ||
                            it.openPorts.any { p -> p.toString().contains(q) }
                    }.toList()
            }

            HostsTableHeader()
            LazyColumn(modifier = Modifier.fillMaxSize().padding(top = 4.dp)) {
                items(visibleHosts, key = { it.ip }) { host ->
                    HostsRow(
                        host = host,
                        onClick = { selectedHost = host },
                        onLongClick = {
                            clipboard.setText(AnnotatedString(host.ip))
                            scope.launch { snackbar.showSnackbar("Скопировано: ${host.ip}") }
                        },
                    )
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f))
                }
            }
        }

        SnackbarHost(
            hostState = snackbar,
            modifier = Modifier.align(Alignment.BottomCenter),
            snackbar = { Snackbar(it) },
        )

        selectedHost?.let { h ->
            HostPortsDialog(
                host = h,
                onDismiss = { selectedHost = null },
            )
        }
    }
}

@Composable
private fun ScanCheckbox(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = checked,
            onCheckedChange = onChange,
            colors = CheckboxDefaults.colors(
                checkedColor = MaterialTheme.colorScheme.primary,
                checkmarkColor = MaterialTheme.colorScheme.onPrimary,
            ),
        )
        Text(label)
    }
}

@Composable
private fun HostsTableHeader() {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(vertical = 6.dp, horizontal = 8.dp),
    ) {
        Text(
            text = "IP",
            modifier = Modifier.weight(1.4f),
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "Имя / MAC",
            modifier = Modifier.weight(2f),
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "Порты",
            modifier = Modifier.weight(2.2f),
            color = MaterialTheme.colorScheme.primary,
            fontWeight = FontWeight.Bold,
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HostsRow(host: Host, onClick: () -> Unit, onLongClick: () -> Unit) {
    val color = if (host.alive) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.outline
    val portsLabel = when {
        host.openPorts.isNotEmpty() -> host.openPorts.joinToString(", ")
        host.portScanTotal > 0 && host.portScanDone in 1 until host.portScanTotal ->
            "сканируется ${host.portScanDone}/${host.portScanTotal}"
        host.alive && host.scanComplete -> "—"
        else -> ""
    }
    val nameOrMac = host.hostname.takeIf { it.isNotBlank() } ?: host.mac.takeIf { it.isNotBlank() } ?: ""

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp)
            .background(MaterialTheme.colorScheme.surface)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
            .padding(vertical = 6.dp, horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1.4f)) {
            Text(
                text = host.ip,
                fontFamily = FontFamily.Monospace,
                color = color,
            )
            if (host.osGuess.isNotEmpty()) {
                Text(
                    text = host.osGuess,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Column(modifier = Modifier.weight(2f)) {
            Text(
                text = nameOrMac.ifEmpty { "—" },
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (host.vendor.isNotBlank()) {
                Text(
                    text = host.vendor,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            text = portsLabel,
            modifier = Modifier.weight(2.2f),
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
