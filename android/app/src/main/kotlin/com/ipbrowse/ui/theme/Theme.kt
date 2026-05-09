package com.ipbrowse.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

/**
 * Тема в стиле Catppuccin Mocha — палитра подобрана так, чтобы Material 3
 * выглядел один-в-один с десктопной версией: фон `Base`, поверхности `Mantle`
 * / `Surface0`, акцент `Blue`, успех `Green`, ошибка `Red`. Светлой темы нет —
 * приложение всегда тёмное, как и десктоп.
 */
private val IPbrowseColors = darkColorScheme(
    primary = Catppuccin.Blue,
    onPrimary = Catppuccin.Base,
    primaryContainer = Catppuccin.Surface0,
    onPrimaryContainer = Catppuccin.Text,

    secondary = Catppuccin.Lavender,
    onSecondary = Catppuccin.Base,
    secondaryContainer = Catppuccin.Surface1,
    onSecondaryContainer = Catppuccin.Text,

    tertiary = Catppuccin.Green,
    onTertiary = Catppuccin.Base,
    tertiaryContainer = Catppuccin.Surface1,
    onTertiaryContainer = Catppuccin.Text,

    error = Catppuccin.Red,
    onError = Catppuccin.Base,
    errorContainer = Catppuccin.Surface1,
    onErrorContainer = Catppuccin.Red,

    background = Catppuccin.Base,
    onBackground = Catppuccin.Text,
    surface = Catppuccin.Mantle,
    onSurface = Catppuccin.Text,
    surfaceVariant = Catppuccin.Surface0,
    onSurfaceVariant = Catppuccin.Subtext0,
    surfaceTint = Catppuccin.Blue,

    outline = Catppuccin.Surface2,
    outlineVariant = Catppuccin.Surface1,
    inverseSurface = Catppuccin.Text,
    inverseOnSurface = Catppuccin.Base,
    inversePrimary = Catppuccin.Blue,
    scrim = Color(0x99000000),
)

private val IPbrowseTypography = Typography(
    bodyLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 16.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 12.sp),
    labelLarge = TextStyle(fontFamily = FontFamily.SansSerif, fontSize = 14.sp),
)

@Composable
@Suppress("UNUSED_PARAMETER")
fun IPbrowseTheme(
    // darkTheme игнорируется — у IPbrowse тема одна, тёмная. Параметр оставлен,
    // чтобы превью под isSystemInDarkTheme=false тоже работало (Compose-превью
    // обычно дёргает функцию с дефолтами).
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = Catppuccin.Mantle.toArgb()
            window.navigationBarColor = Catppuccin.Mantle.toArgb()
            val controller = WindowCompat.getInsetsController(window, view)
            controller.isAppearanceLightStatusBars = false
            controller.isAppearanceLightNavigationBars = false
        }
    }
    MaterialTheme(
        colorScheme = IPbrowseColors,
        typography = IPbrowseTypography,
        content = content,
    )
}
