package dev.notificationmirroring.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Person
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.Icon

object DebugNotificationPublisher {
    const val ACTION_MARK_HANDLED = "dev.notificationmirroring.android.action.MARK_HANDLED"
    const val ACTION_REPLY = "dev.notificationmirroring.android.action.REPLY"
    const val REMOTE_INPUT_KEY = "debug_reply"
    const val NOTIFICATION_ID = 10_001
    private const val CHANNEL_ID = "phase0_notification_actions"
    private var postCount = 0

    /** Debug-only synthetic fixture: first post has an avatar; later posts exercise app-icon fallback. */
    fun post(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "SevenMirror test notifications",
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

        val includeAvatar = postCount++ == 0
        val avatar = acceptanceAvatar()
        val sender = Person.Builder()
            .setName("Media sender")
            .setIcon(Icon.createWithBitmap(avatar))
            .build()
        val style = Notification.MessagingStyle(Person.Builder().setName("SevenMirror").build())
            .addMessage(
                Notification.MessagingStyle.Message(
                    if (includeAvatar) "Avatar test" else "App icon fallback test",
                    System.currentTimeMillis(),
                    if (includeAvatar) sender else null,
                ),
            )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(if (includeAvatar) "Avatar test" else "App icon fallback test")
            .setContentText("This notification includes picture content")
            .setStyle(style)
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
        notification.extras.putParcelable(Notification.EXTRA_PICTURE, acceptanceContentPicture())

        manager.notify(NOTIFICATION_ID, notification)
        DebugActionState.update(if (includeAvatar) "Avatar test posted" else "App icon fallback test posted")
    }

    private fun acceptanceAvatar(): Bitmap = Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888).also { bitmap ->
        val canvas = Canvas(bitmap)
        canvas.drawColor(Color.rgb(0, 121, 107))
        canvas.drawCircle(48f, 38f, 20f, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE })
        canvas.drawCircle(48f, 92f, 34f, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE })
    }

    private fun acceptanceContentPicture(): Bitmap =
        Bitmap.createBitmap(320, 180, Bitmap.Config.ARGB_8888).also { bitmap ->
            val canvas = Canvas(bitmap)
            canvas.drawColor(Color.rgb(81, 45, 168))
            canvas.drawRect(40f, 40f, 280f, 140f, Paint().apply { color = Color.rgb(255, 193, 7) })
        }
}
