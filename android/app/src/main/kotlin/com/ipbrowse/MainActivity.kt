package com.ipbrowse

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.ipbrowse.ui.IPbrowseApp
import com.ipbrowse.ui.theme.IPbrowseTheme

/**
 * Точка входа Android-приложения. Активность одна — внутри Compose-роутер
 * с пятью вкладками (`IPbrowseApp`). edge-to-edge включён, чтобы навбар и
 * статусбар сливались с фоном Catppuccin (см. `IPbrowseTheme`).
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { IPbrowseRoot() }
    }
}

@Composable
private fun IPbrowseRoot() {
    IPbrowseTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            IPbrowseApp()
        }
    }
}
