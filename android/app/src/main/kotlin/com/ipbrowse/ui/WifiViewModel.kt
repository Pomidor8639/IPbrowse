package com.ipbrowse.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.ipbrowse.scanner.WifiInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Состояние вкладки Wi-Fi. Снапшот считаем в IO-потоке, чтобы возможные
 * IPC-ожидания CONNECTIVITY_SERVICE / NetworkInterface не дёргали main.
 */
data class WifiUiState(
    val snapshot: WifiInfo.Snapshot = WifiInfo.Snapshot(),
    val isLoading: Boolean = false,
    val errorMessage: String? = null,
    val refreshedAtMs: Long = 0L,
)

class WifiViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow(WifiUiState())
    val state: StateFlow<WifiUiState> = _state.asStateFlow()

    fun refresh() {
        if (_state.value.isLoading) return
        _state.value = _state.value.copy(isLoading = true, errorMessage = null)
        viewModelScope.launch {
            try {
                val snap = withContext(Dispatchers.IO) { WifiInfo.read(getApplication()) }
                _state.value = WifiUiState(
                    snapshot = snap,
                    isLoading = false,
                    refreshedAtMs = System.currentTimeMillis(),
                )
            } catch (t: Throwable) {
                _state.value = _state.value.copy(
                    isLoading = false,
                    errorMessage = t.message ?: t::class.java.simpleName,
                )
            }
        }
    }

    init { refresh() }
}
