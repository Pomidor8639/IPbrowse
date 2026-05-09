package com.ipbrowse.ui.theme

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
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

/**
 * View.context может быть как Activity, так и ContextWrapper (например, под
 * ComponentActivity Compose оборачивает контекст). Прямой cast к Activity
 * валится с ClassCastException и убивает onCreate ещё до отрисовки —
 * именно по этому экран был тёмно-синим без UI поверх. Аккуратно
 * разворачиваем обёртки до настоящей Activity.
 */
private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

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
            val activity = view.context.findActivity()
            if (activity != null) {
                val window = activity.window
                @Suppress("DEPRECATION")
                window.statusBarColor = Catppuccin.Mantle.toArgb()
                @Suppress("DEPRECATION")
                window.navigationBarColor = Catppuccin.Mantle.toArgb()
                val controller = WindowCompat.getInsetsController(window, view)
                controller.isAppearanceLightStatusBars = false
                controller.isAppearanceLightNavigationBars = false
            }
        }
    }
    MaterialTheme(
        colorScheme = IPbrowseColors,
        typography = IPbrowseTypography,
        content = content,
    )
}
