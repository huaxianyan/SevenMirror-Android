package dev.notificationmirroring.notification

import android.app.Notification
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.notification.StatusBarNotification
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ActiveNotificationSnapshot(
    val highWaterRevision: Long,
    val notifications: List<NotificationSnapshot>,
)

fun interface NotificationMirroringPolicy {
    fun prepare(context: Context, snapshot: NotificationSnapshot): NotificationSnapshot?
}

interface NotificationMirrorSink {
    fun onUpsert(snapshot: NotificationSnapshot)
    fun onRemoved(notificationId: String, revision: Long)
    fun onSnapshot(snapshot: ActiveNotificationSnapshot)
}

internal data class NotificationMirrorSelection(
    val snapshots: List<NotificationSnapshot>,
    val omittedByLimit: Int,
)

internal fun selectNotificationMirrorSet(
    candidates: Collection<NotificationSnapshot>,
    limit: Int = EncryptedPayloadCodecV1.MAX_SNAPSHOT_ENTRIES,
): NotificationMirrorSelection {
    require(limit >= 0) { "Notification mirror limit must not be negative" }
    val childGroups = candidates.asSequence()
        .filterNot(NotificationSnapshot::isGroupSummary)
        .mapNotNull { snapshot ->
            snapshot.groupKey?.takeIf(String::isNotBlank)?.let { snapshot.packageName to it }
        }
        .toSet()
    val deduplicated = candidates.filterNot { snapshot ->
        snapshot.isGroupSummary && snapshot.groupKey?.let {
            (snapshot.packageName to it) in childGroups
        } == true
    }.sortedWith(mirroredNotificationOrder)
    return NotificationMirrorSelection(
        snapshots = deduplicated.take(limit),
        omittedByLimit = (deduplicated.size - limit).coerceAtLeast(0),
    )
}

private val mirroredNotificationOrder =
    compareByDescending<NotificationSnapshot>(NotificationSnapshot::postedAtMillis)
        .thenBy(NotificationSnapshot::key)

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
        val sourceSnapshot: NotificationSnapshot,
        val actions: List<RegisteredAction>,
        val mirroredSnapshot: NotificationSnapshot?,
    )

    private val secureRandom = SecureRandom()
    @Volatile
    private var revisionStore: AndroidNotificationRevisionStore? = null
    private val registered = mutableMapOf<String, RegisteredNotification>()
    private val mutableNotifications = MutableStateFlow<List<NotificationSnapshot>>(emptyList())
    private val mutableOmittedNotificationCount = MutableStateFlow(0)
    @Volatile
    private var mirroringPolicy = NotificationMirroringPolicy { _, _ -> null }
    @Volatile
    private var mirrorSink: NotificationMirrorSink? = null
    @Volatile
    private var dismissSink: ((String) -> Unit)? = null
    private var activeSetReady = false

    val notifications: StateFlow<List<NotificationSnapshot>> = mutableNotifications.asStateFlow()
    val omittedNotificationCount: StateFlow<Int> = mutableOmittedNotificationCount.asStateFlow()

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
        registered[sbn.key] = RegisteredNotification(
            sourceSnapshot = snapshot,
            actions = actions,
            mirroredSnapshot = registered[sbn.key]?.mirroredSnapshot,
        )
        reconcileMirroredSelection(context, freshRevisionKeys = setOf(sbn.key))
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
    fun refreshMirroringPolicy(context: Context) {
        if (!reconcileMirroredSelection(context)) return
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
            notifications = registered.values.mapNotNull(RegisteredNotification::mirroredSnapshot)
                .sortedWith(mirroredNotificationOrder),
        )
    }

    @Synchronized
    fun onRemoved(context: Context, key: String) {
        val removed = registered.remove(key)
        if (removed?.mirroredSnapshot != null) {
            mirrorSink?.onRemoved(key, revisionStore(context).allocate())
        }
        reconcileMirroredSelection(context)
    }

    @Synchronized
    fun onActiveSetUnavailable(context: Context) {
        if (activeSetReady) {
            val highWaterRevision = revisionStore(context).allocate()
            mirrorSink?.onSnapshot(
                ActiveNotificationSnapshot(
                    highWaterRevision = highWaterRevision,
                    notifications = emptyList(),
                ),
            )
        }
        clear()
    }

    @Synchronized
    fun clear() {
        activeSetReady = false
        registered.clear()
        mutableNotifications.value = emptyList()
        mutableOmittedNotificationCount.value = 0
    }

    @Synchronized
    fun dismiss(
        notificationKey: String,
        notificationRevision: Long,
        operationAuthorizer: RemoteOperationAuthorizer,
    ): ActionExecutionResult {
        val notification = registered[notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (notification.mirroredSnapshot == null) {
            return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        }
        if (notification.sourceSnapshot.revision != notificationRevision) {
            return ActionExecutionResult(ActionExecutionStatus.STALE_NOTIFICATION_VERSION)
        }
        if (!operationAuthorizer.isAllowed(
                notification.sourceSnapshot.packageName,
                RemoteOperationType.CLEAR,
            )
        ) {
            return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        }
        if (!notification.sourceSnapshot.isClearable) {
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
        if (notification.mirroredSnapshot == null) {
            return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        }
        if (notification.sourceSnapshot.revision != token.notificationRevision) {
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
        if (!operationAuthorizer.isAllowed(notification.sourceSnapshot.packageName, operationType)) {
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

    private fun reconcileMirroredSelection(
        context: Context,
        freshRevisionKeys: Set<String> = emptySet(),
    ): Boolean {
        val prepared = registered.values.mapNotNull { notification ->
            mirroringPolicy.prepare(context, notification.sourceSnapshot)
        }
        val selection = selectNotificationMirrorSet(prepared)
        val desiredByKey = selection.snapshots.associateBy(NotificationSnapshot::key)
        mutableOmittedNotificationCount.value = selection.omittedByLimit
        var changed = false

        for (key in registered.keys.sorted()) {
            val current = requireNotNull(registered[key])
            val desired = desiredByKey[key]
            if (desired == current.mirroredSnapshot) continue

            val revision = if (key in freshRevisionKeys) {
                current.sourceSnapshot.revision
            } else {
                revisionStore(context).allocate()
            }
            val revisedSource = current.sourceSnapshot.withRevision(revision)
            val revisedMirrored = desired?.withRevision(revision)
            registered[key] = current.copy(
                sourceSnapshot = revisedSource,
                mirroredSnapshot = revisedMirrored,
            )
            changed = true
            if (revisedMirrored != null) {
                mirrorSink?.onUpsert(revisedMirrored)
            } else if (current.mirroredSnapshot != null) {
                mirrorSink?.onRemoved(key, revision)
            }
        }

        mutableNotifications.value = registered.values.map(RegisteredNotification::sourceSnapshot)
            .sortedWith(mirroredNotificationOrder)
        return changed
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
