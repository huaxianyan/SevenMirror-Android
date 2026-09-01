package dev.notificationmirroring.android

import android.content.Context

internal object ProductDebugActions {
    const val available: Boolean = true

    fun restore(context: Context) {
        DebugActionState.restore(context)
    }

    fun postNotification(context: Context) {
        DebugNotificationPublisher.post(context)
    }
}
