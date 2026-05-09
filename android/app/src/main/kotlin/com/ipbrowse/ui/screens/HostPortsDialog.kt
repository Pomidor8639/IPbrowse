package com.ipbrowse.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.ipbrowse.scanner.Host
import com.ipbrowse.scanner.Ports
import com.ipbrowse.ui.googleSearchUrlForPort

/**
 * Диалог открытых портов одного хоста — Android-аналог `HostPortsDialog`
 * из app.py. Для каждого открытого порта показываем имя сервиса (IANA +
 * COMMON_PORTS), типичный софт, баннер (если есть, -sV) и кнопку
 * «Узнать больше», которая через Intent открывает поиск Google в локали
 * `hl=ru` ровно как в десктопе.
 */
@Composable
fun HostPortsDialog(host: Host, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val ports = host.openPorts

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Card(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface,
            ),
        ) {
            Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                Text(
                    text = "Порты: ${host.ip}",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                )
                if (host.hostname.isNotBlank()) {
                    Text(
                        text = host.hostname,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                Spacer(Modifier.height(12.dp))

                if (ports.isEmpty()) {
                    Box(
                        modifier = Modifier.fillMaxSize().padding(top = 24.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = "Открытых портов не найдено",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                } else {
                    LazyColumn(modifier = Modifier.weight(1f)) {
                        items(ports) { p ->
                            PortRow(host = host, port = p, openLink = { uri ->
                                context.startActivity(
                                    Intent(Intent.ACTION_VIEW, Uri.parse(uri))
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                )
                            })
                            HorizontalDivider(
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
                            )
                        }
                    }
                    if (ports.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                // «Узнать больше обо всех» из десктопа: открываем по
                                // одной вкладке на порт. На Android это превращается
                                // в N последовательных Intent — но их обработает
                                // браузер: в Chrome это N вкладок, а в Firefox —
                                // тоже несколько вкладок (вмешиваться не надо).
                                for (p in ports) {
                                    context.startActivity(
                                        Intent(Intent.ACTION_VIEW, Uri.parse(googleSearchUrlForPort(p)))
                                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Узнать больше обо всех") }
                    }
                }

                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End) {
                    TextButton(onClick = onDismiss) { Text("Закрыть") }
                }
            }
        }
    }
}

@Composable
private fun PortRow(host: Host, port: Int, openLink: (String) -> Unit) {
    val context = LocalContext.current
    val service = remember(port) { Ports.serviceForPort(context, port) }
    val software = remember(port) { Ports.PORT_SOFTWARE[port].orEmpty() }
    val banner = host.banners[port].orEmpty()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(vertical = 10.dp, horizontal = 4.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = port.toString(),
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.tertiary,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.width(64.dp),
            )
            Text(
                text = service.ifBlank { "—" },
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { openLink(googleSearchUrlForPort(port)) }) {
                Text("Узнать больше")
            }
        }
        if (software.isNotEmpty()) {
            Text(
                text = software,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(start = 64.dp),
            )
        }
        if (banner.isNotEmpty()) {
            Text(
                text = "Баннер: $banner",
                color = MaterialTheme.colorScheme.secondary,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(start = 64.dp, top = 2.dp),
            )
        }
    }
}
