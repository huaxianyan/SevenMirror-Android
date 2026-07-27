package dev.notificationmirroring.android

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object DebugActionState {
    private val mutableLastResult = MutableStateFlow("No debug action received")
    val lastResult: StateFlow<String> = mutableLastResult.asStateFlow()

    fun update(value: String) {
        mutableLastResult.value = value
    }
}
