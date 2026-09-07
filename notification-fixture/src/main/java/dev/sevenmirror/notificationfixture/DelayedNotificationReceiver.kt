package dev.sevenmirror.notificationfixture

import android.app.AlarmManager
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.os.SystemClock
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

/** Development-only, inexact wakeup alarms; no claim of exact delivery during Doze. */
class DelayedNotificationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val preferences = preferences(context)
        val index = preferences.getInt(KEY_NEXT_STEP, -1)
        val step = Step.entries.getOrNull(index) ?: return
        if (!context.getSystemService(NotificationManager::class.java).areNotificationsEnabled()) {
            record(context, R.string.delayed_permission_lost)
            preferences.edit().putInt(KEY_NEXT_STEP, -1).apply()
            return
        }
        try {
            step.execute(context)
        } catch (_: SecurityException) {
            record(context, R.string.delayed_permission_lost)
            preferences.edit().putInt(KEY_NEXT_STEP, -1).apply()
            return
        }
        record(context, step.result)
        val next = index + 1
        preferences.edit().putInt(KEY_NEXT_STEP, if (next < Step.entries.size) next else -1).apply()
        if (next < Step.entries.size) schedule(context)
    }

    private enum class Step(val result: Int, val execute: (Context) -> Unit) {
        POST(R.string.result_posted, FixtureNotifications::post),
        UPDATE(R.string.delayed_updated, FixtureNotifications::update),
        REMOVE(R.string.result_removed, FixtureNotifications::remove),
    }

    companion object {
        private const val PREFS = "delayed_notification_fixture"
        private const val KEY_NEXT_STEP = "next_step"
        private const val KEY_EVENTS = "events"
        const val STEP_DELAY_SECONDS = 30L

        fun start(context: Context) {
            cancel(context)
            preferences(context).edit().putInt(KEY_NEXT_STEP, 0).putString(KEY_EVENTS, "[]").apply()
            record(context, R.string.delayed_started)
            schedule(context)
        }

        fun cancel(context: Context) {
            context.getSystemService(AlarmManager::class.java).cancel(operation(context))
            if (preferences(context).getInt(KEY_NEXT_STEP, -1) >= 0) {
                record(context, R.string.delayed_cancelled)
            }
            preferences(context).edit().putInt(KEY_NEXT_STEP, -1).apply()
        }

        fun history(context: Context): String {
            val events = JSONArray(preferences(context).getString(KEY_EVENTS, "[]"))
            if (events.length() == 0) return context.getString(R.string.delayed_none)
            return (0 until events.length()).joinToString("\n") { index ->
                val event = events.getJSONObject(index)
                context.getString(
                    R.string.delayed_event,
                    DateFormat.getTimeInstance().format(Date(event.getLong("timeMs"))),
                    event.getString("message"),
                    context.getString(if (event.getBoolean("interactive")) R.string.delayed_awake else R.string.delayed_asleep),
                )
            }
        }

        private fun schedule(context: Context) {
            context.getSystemService(AlarmManager::class.java).setAndAllowWhileIdle(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + STEP_DELAY_SECONDS * 1_000,
                operation(context),
            )
        }

        private fun operation(context: Context): PendingIntent = PendingIntent.getBroadcast(
            context,
            0,
            Intent(context, DelayedNotificationReceiver::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        private fun record(context: Context, message: Int) {
            val preferences = preferences(context)
            val events = JSONArray(preferences.getString(KEY_EVENTS, "[]"))
            val power = context.getSystemService(PowerManager::class.java)
            events.put(JSONObject().apply {
                put("message", context.getString(message))
                put("timeMs", System.currentTimeMillis())
                put("elapsedRealtimeMs", SystemClock.elapsedRealtime())
                put("interactive", power.isInteractive)
                put("deviceIdle", power.isDeviceIdleMode)
            })
            preferences.edit().putString(KEY_EVENTS, events.toString()).apply()
        }

        private fun preferences(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    }
}
