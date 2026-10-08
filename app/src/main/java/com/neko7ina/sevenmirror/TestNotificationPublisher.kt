package com.neko7ina.sevenmirror

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.neko7ina.sevenmirror.notification.NotificationSnapshot
import java.text.DateFormat
import java.util.Date

internal enum class TestNotificationResult(val message: Int) {
    POSTED(R.string.test_notification_posted),
    PERMISSION_REQUIRED(R.string.test_notification_permission_required),
    BLOCKED(R.string.test_notification_blocked),
}

/** User-requested notifications use a dedicated channel, never the background status channel. */
internal object TestNotificationPublisher {
    const val CHANNEL_ID = "sevenmirror-test-notifications"
    private const val NOTIFICATION_ID = 73001

    fun isTestNotification(snapshot: NotificationSnapshot): Boolean =
        snapshot.packageName == BuildConfig.APPLICATION_ID &&
            snapshot.channelId == CHANNEL_ID && !snapshot.isOngoing

    fun post(context: Context): TestNotificationResult {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.test_notification),
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
        if (!canShowForegroundStatus(context) ||
            manager.getNotificationChannel(CHANNEL_ID).importance == NotificationManager.IMPORTANCE_NONE
        ) return TestNotificationResult.BLOCKED

        val openApp = PendingIntent.getActivity(
            context, NOTIFICATION_ID,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_status)
            .setContentTitle(context.getString(R.string.test_notification_title))
            .setContentText(context.getString(R.string.test_notification_body))
            .setStyle(Notification.BigTextStyle().bigText(
                context.getString(R.string.test_notification_expanded,
                    DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date())),
            ))
            .setContentIntent(openApp)
            .setAutoCancel(true)
            .setTimeoutAfter(5 * 60 * 1_000L)
            .build()
        return try {
            manager.notify(NOTIFICATION_ID, notification)
            TestNotificationResult.POSTED
        } catch (_: SecurityException) {
            TestNotificationResult.BLOCKED
        }
    }
}
