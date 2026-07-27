package dev.notificationmirroring.notification

import android.app.Notification
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.notification.StatusBarNotification
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-local registry used only by SPIKE-001. It never logs, persists, or
 * transmits notification content or PendingIntents.
 */
object LocalNotificationController {
    private data class RegisteredNotification(
        val revision: Long,
        val actions: List<Notification.Action>,
    )

    private val nextRevision = AtomicLong(0)
    private val registered = mutableMapOf<String, RegisteredNotification>()
    private val mutableNotifications = MutableStateFlow<List<NotificationSnapshot>>(emptyList())

    val notifications: StateFlow<List<NotificationSnapshot>> = mutableNotifications.asStateFlow()

    @Synchronized
    fun onPosted(
        context: Context,
        sbn: StatusBarNotification,
        isSilent: Boolean,
    ) {
        val revision = nextRevision.incrementAndGet()
        val snapshot = NotificationExtractor.extract(context, sbn, revision, isSilent)
        registered[sbn.key] = RegisteredNotification(
            revision,
            sbn.notification.actions.orEmpty().toList(),
        )
        mutableNotifications.value = (mutableNotifications.value.filterNot { it.key == sbn.key } + snapshot)
            .sortedByDescending(NotificationSnapshot::postedAtMillis)
    }

    @Synchronized
    fun onRemoved(key: String) {
        registered.remove(key)
        mutableNotifications.value = mutableNotifications.value.filterNot { it.key == key }
    }

    @Synchronized
    fun clear() {
        registered.clear()
        mutableNotifications.value = emptyList()
    }

    @Synchronized
    fun invoke(
        context: Context,
        token: NotificationActionToken,
        replyText: String? = null,
    ): ActionExecutionResult {
        val notification = registered[token.notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (notification.revision != token.notificationRevision) {
            return ActionExecutionResult(ActionExecutionStatus.STALE_NOTIFICATION_VERSION)
        }
        val action = notification.actions.getOrNull(token.actionIndex)
            ?: return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        val remoteInputs = action.remoteInputs.orEmpty()

        return try {
            when {
                remoteInputs.isEmpty() && replyText != null ->
                    ActionExecutionResult(ActionExecutionStatus.TEXT_NOT_SUPPORTED)

                remoteInputs.isNotEmpty() && replyText.isNullOrBlank() ->
                    ActionExecutionResult(ActionExecutionStatus.TEXT_REQUIRED)

                remoteInputs.isNotEmpty() -> {
                    val freeFormInputs = remoteInputs.filter { it.allowFreeFormInput }
                    if (freeFormInputs.isEmpty()) {
                        return ActionExecutionResult(ActionExecutionStatus.TEXT_NOT_SUPPORTED)
                    }
                    val text = requireNotNull(replyText)
                    val results = Bundle().apply {
                        freeFormInputs.forEach { putCharSequence(it.resultKey, text) }
                    }
                    val fillInIntent = Intent().addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                    RemoteInput.addResultsToIntent(remoteInputs, fillInIntent, results)
                    action.actionIntent.send(context, 0, fillInIntent)
                    ActionExecutionResult(ActionExecutionStatus.SUCCEEDED)
                }

                else -> {
                    action.actionIntent.send()
                    ActionExecutionResult(ActionExecutionStatus.SUCCEEDED)
                }
            }
        } catch (_: PendingIntent.CanceledException) {
            ActionExecutionResult(ActionExecutionStatus.PENDING_INTENT_CANCELLED)
        } catch (error: RuntimeException) {
            ActionExecutionResult(
                ActionExecutionStatus.INTERNAL_ERROR,
                error::class.java.simpleName,
            )
        }
    }
}
