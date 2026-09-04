package dev.sevenmirror.notificationfixture

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

object FixtureNotifications {
    const val ACTION_COMPLETE = "dev.sevenmirror.notificationfixture.action.COMPLETE"
    const val ACTION_REPLY = "dev.sevenmirror.notificationfixture.action.REPLY"
    const val EXTRA_ACTION_GENERATION = "action_generation"
    const val REMOTE_INPUT_KEY = "fixture_reply"

    private const val DEFAULT_CHANNEL = "controlled_default"
    private const val SILENT_CHANNEL = "controlled_silent"
    private const val ONGOING_CHANNEL = "controlled_ongoing"
    private const val NORMAL_ID = 100
    private const val GROUP_SUMMARY_ID = 200
    private const val GROUP_CHILD_ONE_ID = 201
    private const val GROUP_CHILD_TWO_ID = 202
    private const val SILENT_ID = 300
    private const val ONGOING_ID = 400
    private const val GROUP_KEY = "controlled_group"
    private const val PREFS = "notification_fixture"
    private const val KEY_ACTION_GENERATION = "action_generation"
    private const val KEY_UPDATE_VERSION = "update_version"
    private const val KEY_LAST_RESULT = "last_result"

    fun post(context: Context) {
        postNormal(context, updatedVersion = null)
        recordResult(context, context.getString(R.string.result_posted))
    }

    fun repeatWithoutVisibleChanges(context: Context) {
        postNormal(context, updatedVersion = null)
        recordResult(context, context.getString(R.string.result_repeated))
    }

    fun update(context: Context) {
        val preferences = preferences(context)
        val version = preferences.getInt(KEY_UPDATE_VERSION, 0) + 1
        preferences.edit().putInt(KEY_UPDATE_VERSION, version).apply()
        postNormal(context, updatedVersion = version)
        recordResult(context, context.getString(R.string.result_updated, version))
    }

    fun remove(context: Context) {
        manager(context).cancel(NORMAL_ID)
        recordResult(context, context.getString(R.string.result_removed))
    }

    fun postGroup(context: Context) {
        ensureChannels(context)
        val notificationManager = manager(context)
        notificationManager.notify(
            GROUP_SUMMARY_ID,
            Notification.Builder(context, DEFAULT_CHANNEL)
                .setSmallIcon(R.drawable.ic_fixture)
                .setContentTitle(context.getString(R.string.group_summary))
                .setContentText(context.getString(R.string.notification_body))
                .setGroup(GROUP_KEY)
                .setGroupSummary(true)
                .build(),
        )
        notificationManager.notify(
            GROUP_CHILD_ONE_ID,
            basicNotification(context, context.getString(R.string.group_child_one))
                .setGroup(GROUP_KEY)
                .build(),
        )
        notificationManager.notify(
            GROUP_CHILD_TWO_ID,
            basicNotification(context, context.getString(R.string.group_child_two))
                .setGroup(GROUP_KEY)
                .build(),
        )
        recordResult(context, context.getString(R.string.result_group_posted))
    }

    fun removeGroupChildren(context: Context) {
        val notificationManager = manager(context)
        notificationManager.cancel(GROUP_CHILD_ONE_ID)
        notificationManager.cancel(GROUP_CHILD_TWO_ID)
        notificationManager.notify(
            GROUP_SUMMARY_ID,
            basicNotification(context, context.getString(R.string.group_summary)).build(),
        )
        recordResult(context, context.getString(R.string.result_group_children_removed))
    }

    fun postSilent(context: Context) {
        ensureChannels(context)
        manager(context).notify(
            SILENT_ID,
            Notification.Builder(context, SILENT_CHANNEL)
                .setSmallIcon(R.drawable.ic_fixture)
                .setContentTitle(context.getString(R.string.silent_title))
                .setContentText(context.getString(R.string.notification_body))
                .build(),
        )
        recordResult(context, context.getString(R.string.result_silent_posted))
    }

    fun postOngoing(context: Context) {
        ensureChannels(context)
        manager(context).notify(
            ONGOING_ID,
            Notification.Builder(context, ONGOING_CHANNEL)
                .setSmallIcon(R.drawable.ic_fixture)
                .setContentTitle(context.getString(R.string.ongoing_title))
                .setContentText(context.getString(R.string.notification_body))
                .setOngoing(true)
                .build(),
        )
        recordResult(context, context.getString(R.string.result_ongoing_posted))
    }

    fun clearAll(context: Context) {
        manager(context).cancelAll()
        recordResult(context, context.getString(R.string.result_cleared))
    }

    fun recordAction(context: Context, generation: Int) {
        recordResult(context, context.getString(R.string.result_action, generation))
    }

    fun recordReply(context: Context, reply: String) {
        recordResult(context, context.getString(R.string.result_reply, reply))
    }

    fun lastResult(context: Context): String = preferences(context)
        .getString(KEY_LAST_RESULT, null)
        ?: context.getString(R.string.result_none)

    private fun postNormal(context: Context, updatedVersion: Int?) {
        ensureChannels(context)
        val preferences = preferences(context)
        val actionGeneration = preferences.getInt(KEY_ACTION_GENERATION, 0) + 1
        preferences.edit().putInt(KEY_ACTION_GENERATION, actionGeneration).apply()

        val completeIntent = Intent(context, NotificationActionReceiver::class.java)
            .setAction(ACTION_COMPLETE)
            .putExtra(EXTRA_ACTION_GENERATION, actionGeneration)
        val completeAction = PendingIntent.getBroadcast(
            context,
            1,
            completeIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val replyIntent = Intent(context, NotificationActionReceiver::class.java)
            .setAction(ACTION_REPLY)
            .putExtra(EXTRA_ACTION_GENERATION, actionGeneration)
        val replyAction = PendingIntent.getBroadcast(
            context,
            2,
            replyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        val remoteInput = RemoteInput.Builder(REMOTE_INPUT_KEY)
            .setLabel(context.getString(R.string.reply_label))
            .setAllowFreeFormInput(true)
            .build()
        val title = updatedVersion?.let {
            context.getString(R.string.notification_title_updated, it)
        } ?: context.getString(R.string.notification_title)
        val body = updatedVersion?.let {
            context.getString(R.string.notification_body_updated, it)
        } ?: context.getString(R.string.notification_body)
        val sender = Person.Builder()
            .setName(context.getString(R.string.app_name))
            .setIcon(Icon.createWithBitmap(avatar()))
            .build()
        val style = Notification.MessagingStyle(sender)
            .addMessage(Notification.MessagingStyle.Message(body, System.currentTimeMillis(), sender))
        val notification = Notification.Builder(context, DEFAULT_CHANNEL)
            .setSmallIcon(R.drawable.ic_fixture)
            .setLargeIcon(avatar())
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(style)
            .addAction(Notification.Action.Builder(null, context.getString(R.string.action_complete), completeAction).build())
            .addAction(
                Notification.Action.Builder(null, context.getString(R.string.action_reply), replyAction)
                    .addRemoteInput(remoteInput)
                    .build(),
            )
            .build()
        notification.extras.putParcelable(Notification.EXTRA_PICTURE, contentPicture())
        manager(context).notify(NORMAL_ID, notification)
    }

    private fun basicNotification(context: Context, title: String): Notification.Builder =
        Notification.Builder(context, DEFAULT_CHANNEL)
            .setSmallIcon(R.drawable.ic_fixture)
            .setContentTitle(title)
            .setContentText(context.getString(R.string.notification_body))

    private fun ensureChannels(context: Context) {
        manager(context).createNotificationChannels(
            listOf(
                NotificationChannel(
                    DEFAULT_CHANNEL,
                    context.getString(R.string.channel_default),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
                NotificationChannel(
                    SILENT_CHANNEL,
                    context.getString(R.string.channel_silent),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { setSound(null, null) },
                NotificationChannel(
                    ONGOING_CHANNEL,
                    context.getString(R.string.channel_ongoing),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { setSound(null, null) },
            ),
        )
    }

    private fun recordResult(context: Context, result: String) {
        preferences(context).edit().putString(KEY_LAST_RESULT, result).apply()
    }

    private fun manager(context: Context): NotificationManager =
        context.getSystemService(NotificationManager::class.java)

    private fun preferences(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun avatar(): Bitmap = Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888).also { bitmap ->
        val canvas = Canvas(bitmap)
        canvas.drawColor(Color.rgb(0, 106, 96))
        canvas.drawCircle(48f, 37f, 19f, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE })
        canvas.drawCircle(48f, 92f, 34f, Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.WHITE })
    }

    private fun contentPicture(): Bitmap =
        Bitmap.createBitmap(320, 180, Bitmap.Config.ARGB_8888).also { bitmap ->
            val canvas = Canvas(bitmap)
            canvas.drawColor(Color.rgb(45, 70, 140))
            canvas.drawRect(36f, 36f, 284f, 144f, Paint().apply { color = Color.rgb(255, 196, 0) })
        }
}
