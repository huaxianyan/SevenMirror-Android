package dev.notificationmirroring.android

import android.content.Context

internal object ProductDebugActions {
    const val available: Boolean = false

    fun restore(context: Context) = Unit

    fun postNotification(context: Context) = Unit
}
