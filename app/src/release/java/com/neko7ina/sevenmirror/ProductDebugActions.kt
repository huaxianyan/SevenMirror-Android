package com.neko7ina.sevenmirror

import android.content.Context
import com.neko7ina.sevenmirror.notification.NotificationSnapshot

internal object ProductDebugActions {
    const val available: Boolean = false

    fun restore(context: Context) = Unit

    fun postNotification(context: Context) = Unit

    fun isFixtureNotification(snapshot: NotificationSnapshot): Boolean = false
}
