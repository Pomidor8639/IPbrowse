package com.ipbrowse.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ipbrowse.R
import com.ipbrowse.ui.screens.AboutScreen
import com.ipbrowse.ui.screens.MassScanScreen
import com.ipbrowse.ui.screens.ScanScreen
import com.ipbrowse.ui.screens.WifiScreen

/**
 * Корневая Compose-обёртка: верхний `ScrollableTabRow` с пятью вкладками +
 * контент текущей вкладки. Состояние каждой вкладки живёт в своём
 * ViewModel'е, которые `viewModel(key=...)` отделяет — иначе Local и
 * External получили бы один и тот же `ScanViewModel` и тёрли друг другу
 * запуск.
 *
 * `ScrollableTabRow` (а не `TabRow` с ручным horizontalScroll) важен:
 * у обычного `TabRow` под scrollable-обёрткой нет конечной ширины и он
 * падает при измерении — экран остаётся пустым, видим только цвет фона.
 * `ScrollableTabRow` сам разруливает прокрутку, индикатор и edgePadding.
 */
@Composable
fun IPbrowseApp() {
    val tabs = listOf(
        stringResource(R.string.tab_local),
        stringResource(R.string.tab_external),
        stringResource(R.string.tab_wifi),
        stringResource(R.string.tab_mass),
        stringResource(R.string.tab_about),
    )
    var selected by rememberSaveable { mutableIntStateOf(0) }

    val localVm: ScanViewModel = viewModel(key = "scan-local")
    val externalVm: ScanViewModel = viewModel(key = "scan-external")
    val massVm: MassScanViewModel = viewModel()
    val wifiVm: WifiViewModel = viewModel()

    // WifiInfo.read блокирует главный поток (NetworkInterface, ConnectivityManager),
    // поэтому используем тот же ViewModel, что и Wi-Fi-вкладка — он уже
    // вызывает read() через Dispatchers.IO. Реактивно подсовываем результат
    // в дефолтную цель локальной вкладки.
    val wifiState by wifiVm.state.collectAsState()
    LaunchedEffect(wifiState.snapshot.subnetCidr) {
        wifiState.snapshot.subnetCidr?.let { localVm.setDefaultTarget(it) }
    }

    Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
        ScrollableTabRow(
            selectedTabIndex = selected,
            modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            edgePadding = 0.dp,
        ) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selected == index,
                    onClick = { selected = index },
                    text = {
                        Text(
                            text = title,
                            fontWeight = if (selected == index) FontWeight.Bold else FontWeight.Normal,
                        )
                    },
                )
            }
        }

        Box(modifier = Modifier.fillMaxSize().padding(horizontal = 0.dp)) {
            when (selected) {
                0 -> ScanScreen(
                    vm = localVm,
                    showAutoDetect = true,
                    warningText = null,
                )
                1 -> ScanScreen(
                    vm = externalVm,
                    showAutoDetect = false,
                    warningText = "Внимание: сканирование внешних сетей может нарушать правила " +
                        "провайдера и действующее законодательство. Сканируйте только то, на что " +
                        "у вас есть явное разрешение.",
                )
                2 -> WifiScreen(vm = wifiVm)
                3 -> MassScanScreen(vm = massVm)
                4 -> AboutScreen()
            }
        }
    }
}
