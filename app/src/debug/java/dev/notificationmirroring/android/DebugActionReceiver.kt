package dev.notificationmirroring.android

import android.app.NotificationManager
import android.app.RemoteInput
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class DebugActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            DebugNotificationPublisher.ACTION_MARK_HANDLED -> {
                DebugActionState.recordRegularAction(context)
            }

            DebugNotificationPublisher.ACTION_REPLY -> {
                val reply = RemoteInput.getResultsFromIntent(intent)
                    ?.getCharSequence(DebugNotificationPublisher.REMOTE_INPUT_KEY)
                    ?.toString()
                DebugActionState.update("RemoteInput received: ${reply.orEmpty()}")
            }

            else -> return
        }

        context.getSystemService(NotificationManager::class.java)
            .cancel(DebugNotificationPublisher.NOTIFICATION_ID)
    }
}
