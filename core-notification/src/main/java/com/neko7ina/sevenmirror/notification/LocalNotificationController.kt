package com.neko7ina.sevenmirror.notification

import android.app.Notification
import android.app.PendingIntent
import android.app.RemoteInput
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.service.notification.StatusBarNotification
import com.neko7ina.sevenmirror.protocol.EncryptedPayloadCodecV1
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
        val eligibleForMirroring: Boolean,
    )

    private data class PendingMirrorChange(
        val snapshot: NotificationSnapshot?,
        val callback: Runnable,
    )

    private const val STABILITY_DELAY_MS = 1_000L
    private const val REMOVAL_DELAY_MS = 300L
    private val changeHandler = Handler(Looper.getMainLooper())
    private var stabilityWakeLock: PowerManager.WakeLock? = null
    private val mirrored = mutableMapOf<String, NotificationSnapshot>()
    private val pendingChanges = mutableMapOf<String, PendingMirrorChange>()
    private var initialSnapshotPending = false
    private var notificationStabilityEnabled = false

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
    fun setNotificationStabilityEnabled(context: Context, enabled: Boolean) {
        if (notificationStabilityEnabled == enabled) return
        notificationStabilityEnabled = enabled
        if (!enabled) refreshMirroringPolicy(context)
    }

    @Synchronized
    fun onPosted(
        context: Context,
        sbn: StatusBarNotification,
        isSilent: Boolean,
    ) {
        val previous = registered[sbn.key]
        val platformActions = sbn.notification.actions.orEmpty()
        val actionIds = if (
            previous != null && sameActionPresentation(previous.sourceSnapshot.actions, platformActions)
        ) {
            previous.actions.map(RegisteredAction::id)
        } else {
            platformActions.map { randomActionId() }
        }
        val actions = platformActions.mapIndexed { index, action ->
            RegisteredAction(actionIds[index], action)
        }
        val candidate = NotificationExtractor.extract(
            context,
            sbn,
            previous?.sourceSnapshot?.revision ?: revisionStore(context).allocate(),
            isSilent,
            actionIds,
        )
        if (previous != null && previous.sourceSnapshot.sameMirroredContent(candidate)) {
            // Keep the externally visible revision and action IDs, but execute the application's
            // latest PendingIntent if Chrome later invokes the existing token.
            registered[sbn.key] = previous.copy(actions = actions)
            return
        }
        val snapshot = if (previous == null) {
            candidate
        } else {
            candidate.withRevision(revisionStore(context).allocate())
        }
        registered[sbn.key] = RegisteredNotification(
            sourceSnapshot = snapshot,
            actions = actions,
            eligibleForMirroring = false,
        )
        reconcileMirroredSelection(context)
        finishPendingChanges(context)
    }

    @Synchronized
    fun onActiveSetReady(context: Context) {
        activeSetReady = true
        initialSnapshotPending = pendingChanges.isNotEmpty()
        if (!initialSnapshotPending) publishCurrentSnapshot(context)
    }

    @Synchronized
    fun refreshMirroringPolicy(context: Context) {
        val changed = reconcileMirroredSelection(context, immediate = true)
        releaseWakeLockIfIdle()
        if (activeSetReady && (changed || initialSnapshotPending)) {
            initialSnapshotPending = false
            publishCurrentSnapshot(context)
        }
    }

    @Synchronized
    fun currentActiveSnapshot(context: Context): ActiveNotificationSnapshot? {
        if (!activeSetReady || initialSnapshotPending) return null
        return ActiveNotificationSnapshot(
            highWaterRevision = revisionStore(context).current(),
            notifications = mirrored.values.sortedWith(mirroredNotificationOrder),
        )
    }

    @Synchronized
    fun onRemoved(context: Context, key: String) {
        registered.remove(key)
        reconcileMirroredSelection(context)
        finishPendingChanges(context)
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
        initialSnapshotPending = false
        pendingChanges.values.forEach { changeHandler.removeCallbacks(it.callback) }
        pendingChanges.clear()
        releaseWakeLockIfIdle()
        mirrored.clear()
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
        if (!notification.eligibleForMirroring) return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        val published = mirrored[notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (notification.sourceSnapshot.revision != notificationRevision || published.revision != notificationRevision) {
            return ActionExecutionResult(ActionExecutionStatus.STALE_NOTIFICATION_VERSION)
        }
        if (!operationAuthorizer.isAllowed(
                notification.sourceSnapshot.packageName,
                RemoteOperationType.CLEAR,
            )
        ) {
            return ActionExecutionResult(ActionExecutionStatus.ACTION_NOT_FOUND)
        }
        // The platform refuses a listener-initiated single cancellation only for ongoing
        // notifications (NotificationManagerService.cancelNotificationFromListenerLocked uses
        // FLAG_ONGOING_EVENT as its mustNotHaveFlags). isClearable is the wrong gate for this
        // call: it also covers FLAG_NO_CLEAR, which only opts a notification out of "Clear all"
        // and still lets the user dismiss it by hand. Gating on it made notifications the user
        // can remove on the phone impossible to clear remotely.
        if (notification.sourceSnapshot.isOngoing) {
            return ActionExecutionResult(ActionExecutionStatus.INTERNAL_ERROR, "NOTIFICATION_STILL_ONGOING")
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
        if (!notification.eligibleForMirroring) return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        val published = mirrored[token.notificationKey]
            ?: return ActionExecutionResult(ActionExecutionStatus.NOTIFICATION_NOT_FOUND)
        if (notification.sourceSnapshot.revision != token.notificationRevision || published.revision != token.notificationRevision) {
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

    private fun sameActionPresentation(
        previous: List<NotificationActionDescriptor>,
        current: Array<out Notification.Action>,
    ): Boolean = previous.size == current.size && current.indices.all { index ->
        val currentAction = current[index]
        val remoteInputs = currentAction.remoteInputs.orEmpty()
        previous[index].title ==
            (currentAction.title?.toString()?.takeIf(String::isNotBlank) ?: "Action ${index + 1}") &&
            previous[index].semanticAction == currentAction.semanticAction &&
            previous[index].requiresTextInput == remoteInputs.isNotEmpty() &&
            previous[index].allowsFreeFormInput == remoteInputs.any { it.allowFreeFormInput }
    }

    private fun NotificationSnapshot.sameMirroredContent(other: NotificationSnapshot): Boolean =
        key == other.key &&
            packageName == other.packageName &&
            channelId == other.channelId &&
            appName == other.appName &&
            title == other.title &&
            text == other.text &&
            expandedText == other.expandedText &&
            appIcon.sameMedia(other.appIcon) &&
            avatar.sameMedia(other.avatar) &&
            containsContentImage == other.containsContentImage &&
            postedAtMillis == other.postedAtMillis &&
            isClearable == other.isClearable &&
            isOngoing == other.isOngoing &&
            isSilent == other.isSilent &&
            groupKey == other.groupKey &&
            isGroupSummary == other.isGroupSummary &&
            actions.size == other.actions.size &&
            actions.indices.all { index -> actions[index].samePresentation(other.actions[index]) }

    private fun NotificationActionDescriptor.samePresentation(
        other: NotificationActionDescriptor,
    ): Boolean = token.notificationKey == other.token.notificationKey &&
        token.actionId == other.token.actionId &&
        title == other.title &&
        semanticAction == other.semanticAction &&
        requiresTextInput == other.requiresTextInput &&
        allowsFreeFormInput == other.allowsFreeFormInput

    private fun NotificationMedia?.sameMedia(other: NotificationMedia?): Boolean = when {
        this == null || other == null -> this == null && other == null
        else -> mimeType == other.mimeType &&
            width == other.width &&
            height == other.height &&
            contentSha256.contentEquals(other.contentSha256) &&
            bytes.contentEquals(other.bytes)
    }

    private fun reconcileMirroredSelection(
        context: Context,
        immediate: Boolean = false,
        readyKey: String? = null,
    ): Boolean {
        val prepared = registered.values.mapNotNull { notification ->
            mirroringPolicy.prepare(context, notification.sourceSnapshot)
        }
        val selection = selectNotificationMirrorSet(prepared)
        val desiredByKey = selection.snapshots.associateBy(NotificationSnapshot::key)
        // Eligibility follows the phone immediately; presentation can remain during the short buffer.
        registered.entries.forEach { (key, current) ->
            registered[key] = current.copy(eligibleForMirroring = key in desiredByKey)
        }
        mutableOmittedNotificationCount.value = selection.omittedByLimit
        var changed = false

        for (key in (registered.keys + mirrored.keys + pendingChanges.keys).sorted()) {
            val desired = desiredByKey[key]
            if (desired == mirrored[key]) {
                cancelPendingChange(key)
                continue
            }
            if (immediate || !notificationStabilityEnabled || key == readyKey) {
                cancelPendingChange(key)
                // A recovery snapshot may have advanced the barrier while this item waited.
                // Allocate at publication, not at scheduling, so this version stays above it.
                val revision = revisionStore(context).allocate()
                registered[key]?.let { current ->
                    registered[key] = current.copy(sourceSnapshot = current.sourceSnapshot.withRevision(revision))
                }
                changed = true
                if (desired != null) {
                    val published = desired.withRevision(revision)
                    mirrored[key] = published
                    mirrorSink?.onUpsert(published)
                } else {
                    mirrored.remove(key)
                    mirrorSink?.onRemoved(key, revision)
                }
                continue
            }
            val pending = pendingChanges[key]
            if (pending != null && pending.snapshot == desired) continue
            cancelPendingChange(key)
            scheduleMirrorChange(context.applicationContext, key, desired)
        }

        mutableNotifications.value = registered.values.map(RegisteredNotification::sourceSnapshot)
            .sortedWith(mirroredNotificationOrder)
        return changed
    }

    private fun scheduleMirrorChange(context: Context, key: String, desired: NotificationSnapshot?) {
        val callback = object : Runnable {
            override fun run() {
                synchronized(LocalNotificationController) {
                    if (pendingChanges[key]?.callback !== this) return
                    pendingChanges.remove(key)
                    try {
                        reconcileMirroredSelection(context, readyKey = key)
                    } finally {
                        finishPendingChanges(context)
                    }
                }
            }
        }
        pendingChanges[key] = PendingMirrorChange(desired, callback)
        val wakeLock = stabilityWakeLock ?: requireNotNull(context.getSystemService(PowerManager::class.java))
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SevenMirror:NotificationStability")
            .apply { setReferenceCounted(false) }
            .also { stabilityWakeLock = it }
        wakeLock.acquire(STABILITY_DELAY_MS + 1_000L)
        changeHandler.postDelayed(callback, if (desired == null) REMOVAL_DELAY_MS else STABILITY_DELAY_MS)
    }

    private fun cancelPendingChange(key: String) {
        pendingChanges.remove(key)?.let { changeHandler.removeCallbacks(it.callback) }
    }

    private fun releaseWakeLockIfIdle() {
        if (pendingChanges.isEmpty()) {
            stabilityWakeLock?.let { if (it.isHeld) it.release() }
        }
    }

    private fun finishPendingChanges(context: Context) {
        releaseWakeLockIfIdle()
        if (pendingChanges.isEmpty() && initialSnapshotPending) {
            initialSnapshotPending = false
            publishCurrentSnapshot(context)
        }
    }

    private fun publishCurrentSnapshot(context: Context) {
        // Even an empty active set must close removed items below a fresh recovery barrier.
        revisionStore(context).allocate()
        mirrorSink?.onSnapshot(requireNotNull(currentActiveSnapshot(context)))
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
