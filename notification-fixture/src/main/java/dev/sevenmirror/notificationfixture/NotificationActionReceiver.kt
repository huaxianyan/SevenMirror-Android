package dev.sevenmirror.notificationfixture

import android.app.RemoteInput
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            FixtureNotifications.ACTION_COMPLETE -> FixtureNotifications.recordAction(
                context,
                intent.getIntExtra(FixtureNotifications.EXTRA_ACTION_GENERATION, -1),
            )

            FixtureNotifications.ACTION_REPLY -> {
                val reply = RemoteInput.getResultsFromIntent(intent)
                    ?.getCharSequence(FixtureNotifications.REMOTE_INPUT_KEY)
                    ?.toString()
                    .orEmpty()
                FixtureNotifications.recordReply(context, reply)
            }
        }
    }
}
