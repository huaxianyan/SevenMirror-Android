package dev.notificationmirroring.android

import android.content.Context
import dev.notificationmirroring.notification.NotificationSnapshot

internal object ProductDebugActions {
    const val available: Boolean = false

    fun restore(context: Context) = Unit

    fun postNotification(context: Context) = Unit

    fun isFixtureNotification(snapshot: NotificationSnapshot): Boolean = false
}
