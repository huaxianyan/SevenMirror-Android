package dev.notificationmirroring.android

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object DebugActionState {
    private val mutableLastResult = MutableStateFlow("No debug action received")
    private val mutableRegularActionCount = MutableStateFlow(0)
    val lastResult: StateFlow<String> = mutableLastResult.asStateFlow()
    val regularActionCount: StateFlow<Int> = mutableRegularActionCount.asStateFlow()

    @Synchronized
    fun restore(context: Context) {
        mutableRegularActionCount.value = preferences(context).getInt(REGULAR_ACTION_COUNT, 0)
    }

    @Synchronized
    fun recordRegularAction(context: Context) {
        val count = Math.addExact(preferences(context).getInt(REGULAR_ACTION_COUNT, 0), 1)
        check(preferences(context).edit().putInt(REGULAR_ACTION_COUNT, count).commit()) {
            "Unable to persist synthetic side-effect count"
        }
        mutableRegularActionCount.value = count
        mutableLastResult.value = "Regular PendingIntent action received"
    }

    fun update(value: String) {
        mutableLastResult.value = value
    }

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    private const val PREFERENCES = "synthetic-action-evidence-v1"
    private const val REGULAR_ACTION_COUNT = "regular-action-count"
}
