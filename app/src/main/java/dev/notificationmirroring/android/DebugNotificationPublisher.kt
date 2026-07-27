package dev.notificationmirroring.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent

object DebugNotificationPublisher {
    const val ACTION_MARK_HANDLED = "dev.notificationmirroring.android.action.MARK_HANDLED"
    const val ACTION_REPLY = "dev.notificationmirroring.android.action.REPLY"
    const val REMOTE_INPUT_KEY = "debug_reply"
    const val NOTIFICATION_ID = 10_001
    private const val CHANNEL_ID = "phase0_notification_actions"

    fun post(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Phase 0 notification actions",
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )

        val handledIntent = Intent(context, DebugActionReceiver::class.java).setAction(ACTION_MARK_HANDLED)
        val handledPendingIntent = PendingIntent.getBroadcast(
            context,
            1,
            handledIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val replyIntent = Intent(context, DebugActionReceiver::class.java).setAction(ACTION_REPLY)
        val replyPendingIntent = PendingIntent.getBroadcast(
            context,
            2,
            replyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        val remoteInput = RemoteInput.Builder(REMOTE_INPUT_KEY)
            .setLabel("Reply text")
            .setAllowFreeFormInput(true)
            .build()

        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Phase 0 capability test")
            .setContentText("Use the local mirror below to invoke an action or reply")
            .setAutoCancel(false)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Mark handled",
                    handledPendingIntent,
                ).build(),
            )
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Reply",
                    replyPendingIntent,
                ).addRemoteInput(remoteInput).build(),
            )
            .build()

        manager.notify(NOTIFICATION_ID, notification)
        DebugActionState.update("Debug notification posted")
    }
}
