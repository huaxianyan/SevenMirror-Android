package dev.notificationmirroring.android

import android.content.Context
import dev.notificationmirroring.notification.NotificationSnapshot

internal object ProductDebugActions {
    const val available: Boolean = true

    fun restore(context: Context) {
        DebugActionState.restore(context)
    }

    fun postNotification(context: Context) {
        DebugNotificationPublisher.post(context)
    }

    fun isFixtureNotification(snapshot: NotificationSnapshot): Boolean =
        snapshot.packageName == BuildConfig.APPLICATION_ID &&
            snapshot.title in setOf("Avatar test", "App icon fallback test")
}
