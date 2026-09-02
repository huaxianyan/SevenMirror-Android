package dev.notificationmirroring.notification

import android.app.Notification
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.notification.StatusBarNotification
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ActiveNotificationSnapshot(
    val highWaterRevision: Long,
    val notifications: List<NotificationSnapshot>,
)

fun interface NotificationMirroringPolicy {
    fun isEligible(context: Context, packageName: String): Boolean
}

interface NotificationMirrorSink {
    fun onUpsert(snapshot: NotificationSnapshot)
    fun onRemoved(notificationId: String, revision: Long)
    fun onSnapshot(snapshot: ActiveNotificationSnapshot)
}

/**
 * Process-local notification-content and PendingIntent registry. Only the opaque global
 * notification revision high-water mark is persisted across process recreation.
 */
object LocalNotificationController {
    private data class RegisteredAction(
        val id: NotificationActionId,
        val action: Notification.Action,
    )

    private data class RegisteredNotification(
        val packageName: String,
        val revision: Long,
        val actions: List<RegisteredAction>,
        val mirrorEligible: Boolean,
        val isClearable: Boolean,
    )

    private val secureRandom = SecureRandom()
    @Volatile
    private var revisionStore: AndroidNotificationRevisionStore? = null
    private val registered = mutableMapOf<String, RegisteredNotification>()
    private val mutableNotifications = MutableStateFlow<List<NotificationSnapshot>>(emptyList())
    @Volatile
    private var mirroringPolicy = NotificationMirroringPolicy { _, _ -> false }
    @Volatile
    private var mirrorSink: NotificationMirrorSink? = null
    @Volatile
    private var dismissSink: ((String) -> Unit)? = null
    private var activeSetReady = false

    val notifications: StateFlow<List<NotificationSnapshot>> = mutableNotifications.asStateFlow()

    fun installMirroringPolicy(policy: NotificationMirroringPolicy) {
        mirroringPolicy = policy
    }

    fun installNotificationMirrorSink(sink: NotificationMirrorSink?) {
        mirrorSink = sink
    }

    fun installDismissSink(sink: ((String) -> Unit)?) {
        dismissSink = sink
    }

    @Synchronized
    fun onPosted(
        context: Context,
        sbn: StatusBarNotification,
        isSilent: Boolean,
    ) {
        val revision = revisionStore(context).allocate()
        val actions = sbn.notification.actions.orEmpty().map { action ->
            RegisteredAction(randomActionId(), action)
        }
        val snapshot = NotificationExtractor.extract(
            context,
            sbn,
            revision,
            isSilent,
            actions.map(RegisteredAction::id),
        )
        val wasMirrorEligible = registered[sbn.key]?.mirrorEligible == true
        val mirrorEligible = mirroringPolicy.isEligible(context, sbn.packageName)
        registered[sbn.key] = RegisteredNotification(
            packageName = sbn.packageName,
            revision = revision,
            actions = actions,
            mirrorEligible = mirrorEligible,
            isClearable = snapshot.isClearable,
        )
        mutableNotifications.value = (mutableNotifications.value.filterNot { it.key == sbn.key } + snapshot)
            .sortedByDescending(NotificationSnapshot::postedAtMillis)
        when {
            mirrorEligible -> mirrorSink?.onUpsert(snapshot)
            wasMirrorEligible -> mirrorSink?.onRemoved(sbn.key, revision)
        }
    }

    @Synchronized
    fun onActiveSetReady(context: Context) {
        // Reserve a fresh barrier even when the active set is empty, so a notification removed
        // while the listener was disconnected can be closed below this snapshot high-water mark.
        revisionStore(context).allocate()
        activeSetReady = true
        mirrorSink?.onSnapshot(requireNotNull(currentActiveSnapshot(context)))
    }

    @Synchronized
    fun refreshMirroringEligibility(context: Context) {
        var changed = false
        val revisedSnapshots = mutableNotifications.value.associateBy(NotificationSnapshot::key).toMutableMap()
        for ((key, notification) in registered.toMap()) {
            val eligible = mirroringPolicy.isEligible(context, notification.packageName)
            if (eligible == notification.mirrorEligible) continue

            val revision = revisionStore(context).allocate()
            val snapshot = revisedSnapshots[key]
            registered[key] = notification.copy(revision = revision, mirrorEligible = eligible)
            changed = true
            if (eligible && snapshot != null) {
                val revised = snapshot.withRevision(revision)
                revisedSnapshots[key] = revised
                mirrorSink?.onUpsert(revised)
            } else if (notification.mirrorEligible) {
                mirrorSink?.onRemoved(key, revision)
            }
        }
        if (!changed) return

        mutableNotifications.value = revisedSnapshots.values
            .sortedByDescending(NotificationSnapshot::postedAtMillis)
        if (activeSetReady) {
            revisionStore(context).allocate()
            mirrorSink?.onSnapshot(requireNotNull(currentActiveSnapshot(context)))
        }
    }

    @Synchronized
    fun currentActiveSnapshot(context: Context): ActiveNotificationSnapshot? {
        if (!activeSetReady) return null
        return ActiveNotificationSnapshot(
            highWaterRevision = revisionStore(context).current(),
            notifications = mutableNotifications.value.filter { snapshot ->
                registered[snapshot.key]?.mirrorEligible == true
            },
        )
    }

    @Synchronized
    fun onRemoved(context: Context, key: String) {
        val removed = registered.remove(key)
        mutableNotifications.value = mutableNotifications.value.filterNot { it.key == key }
        if (removed?.mirrorEligible == true) {
            mirrorSink?.onRemoved(key, revisionStore(context).allocate())
        }
    }

    @Synchronized
    fun clear() {
        activeSetReady = false
        registered.clear()
        mutableNotifications.value = emptyList()
    }

    @Synchronized
    fun dismiss(
        notificationKey: String,
        notificationRevision: Long,
        operationAuthorizer: RemoteOperationAuthorizer,
    ): ActionExecutionResult {
        val notification = registered[notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (!notification.mirrorEligible) {
            return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        }
        if (notification.revision != notificationRevision) {
            return ActionExecutionResult(ActionExecutionStatus.STALE_NOTIFICATION_VERSION)
        }
        if (!operationAuthorizer.isAllowed(notification.packageName, RemoteOperationType.CLEAR)) {
            return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        }
        if (!notification.isClearable) {
            return ActionExecutionResult(ActionExecutionStatus.INTERNAL_ERROR, "NOTIFICATION_NOT_CLEARABLE")
        }
        val sink = dismissSink
            ?: return ActionExecutionResult(ActionExecutionStatus.INTERNAL_ERROR, "LISTENER_NOT_CONNECTED")
        return try {
            sink(notificationKey)
            ActionExecutionResult(ActionExecutionStatus.SUCCEEDED)
        } catch (error: RuntimeException) {
            ActionExecutionResult(ActionExecutionStatus.INTERNAL_ERROR, error::class.java.simpleName)
        }
    }

    @Synchronized
    fun invoke(
        context: Context,
        token: NotificationActionToken,
        replyText: String? = null,
        operationAuthorizer: RemoteOperationAuthorizer,
    ): ActionExecutionResult {
        val notification = registered[token.notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (!notification.mirrorEligible) {
            return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        }
        if (notification.revision != token.notificationRevision) {
            return ActionExecutionResult(ActionExecutionStatus.STALE_NOTIFICATION_VERSION)
        }
        val action = notification.actions
            .firstOrNull { it.id == token.actionId }
            ?.action
            ?: return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        val operationType = if (replyText == null) {
            RemoteOperationType.ACTION
        } else {
            RemoteOperationType.REPLY
        }
        if (!operationAuthorizer.isAllowed(notification.packageName, operationType)) {
            return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        }
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

    private fun NotificationSnapshot.withRevision(revision: Long): NotificationSnapshot = copy(
        revision = revision,
        actions = actions.map { descriptor ->
            descriptor.copy(token = descriptor.token.copy(notificationRevision = revision))
        },
    )

    private fun revisionStore(context: Context): AndroidNotificationRevisionStore =
        revisionStore ?: synchronized(this) {
            revisionStore ?: AndroidNotificationRevisionStore(context).also { revisionStore = it }
        }

    private fun randomActionId(): NotificationActionId = ByteArray(16)
        .also(secureRandom::nextBytes)
        .let(NotificationActionId::fromBytes)
}
