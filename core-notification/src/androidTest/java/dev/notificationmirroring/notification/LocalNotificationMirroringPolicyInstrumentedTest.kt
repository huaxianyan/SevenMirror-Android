package dev.notificationmirroring.notification

import android.annotation.SuppressLint
import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Process
import android.os.UserHandle
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class LocalNotificationMirroringPolicyInstrumentedTest {
    @Test
    fun selectionChangesEmitFreshUpsertRemovalAndSnapshotRevisions() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val selectedPackages = mutableSetOf<String>()
        var hideContent = false
        val events = mutableListOf<MirrorEvent>()
        LocalNotificationController.clear()
        LocalNotificationController.installMirroringPolicy(
            NotificationMirroringPolicy { _, snapshot ->
                snapshot.takeIf { it.packageName in selectedPackages }?.let {
                    if (hideContent) it.copy(title = null, text = null, expandedText = null) else it
                }
            },
        )
        LocalNotificationController.installNotificationMirrorSink(
            object : NotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) {
                    events += MirrorEvent.Upsert(snapshot)
                }

                override fun onRemoved(notificationId: String, revision: Long) {
                    events += MirrorEvent.Removed(notificationId, revision)
                }

                override fun onSnapshot(snapshot: ActiveNotificationSnapshot) {
                    events += MirrorEvent.Snapshot(snapshot)
                }
            },
        )

        try {
            val packageName = "com.example.selected"
            val notification = testNotification(context, packageName)
            LocalNotificationController.onPosted(context, notification, isSilent = false)
            LocalNotificationController.onActiveSetReady(context)
            assertEquals(1, events.size)
            assertTrue((events.single() as MirrorEvent.Snapshot).value.notifications.isEmpty())

            events.clear()
            selectedPackages += packageName
            LocalNotificationController.refreshMirroringPolicy(context)

            val upsert = (events[0] as MirrorEvent.Upsert).value
            val selectedSnapshot = (events[1] as MirrorEvent.Snapshot).value
            assertEquals(notification.key, upsert.key)
            assertEquals(upsert.revision, upsert.actions.single().token.notificationRevision)
            assertEquals(listOf(upsert), selectedSnapshot.notifications)
            assertTrue(selectedSnapshot.highWaterRevision > upsert.revision)

            events.clear()
            hideContent = true
            LocalNotificationController.refreshMirroringPolicy(context)

            val hiddenUpsert = (events[0] as MirrorEvent.Upsert).value
            val hiddenSnapshot = (events[1] as MirrorEvent.Snapshot).value
            assertEquals(null, hiddenUpsert.title)
            assertTrue(hiddenUpsert.revision > upsert.revision)
            assertEquals(listOf(hiddenUpsert), hiddenSnapshot.notifications)

            events.clear()
            selectedPackages.clear()
            LocalNotificationController.refreshMirroringPolicy(context)

            val removed = events[0] as MirrorEvent.Removed
            val deselectedSnapshot = (events[1] as MirrorEvent.Snapshot).value
            assertEquals(notification.key, removed.notificationId)
            assertTrue(removed.revision > hiddenUpsert.revision)
            assertTrue(deselectedSnapshot.notifications.isEmpty())
            assertTrue(deselectedSnapshot.highWaterRevision > removed.revision)
            assertEquals(
                ActionExecutionStatus.NOTIFICATION_NOT_FOUND,
                LocalNotificationController.invoke(
                    context = context,
                    token = upsert.actions.single().token,
                    operationAuthorizer = RemoteOperationAuthorizer { _, _ -> true },
                ).status,
            )
        } finally {
            LocalNotificationController.installNotificationMirrorSink(null)
            LocalNotificationController.installMirroringPolicy(
                NotificationMirroringPolicy { _, _ -> null },
            )
            LocalNotificationController.clear()
        }
    }

    @Test
    fun repeatedCallbackKeepsChromeRevisionAndExecutesLatestAppAction() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val events = mutableListOf<MirrorEvent>()
        val received = CountDownLatch(1)
        val secondAction = "dev.notificationmirroring.TEST_UPDATED_ACTION"
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == secondAction) received.countDown()
            }
        }
        registerTestReceiver(context, receiver, IntentFilter(secondAction))
        LocalNotificationController.clear()
        LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, snapshot -> snapshot })
        LocalNotificationController.installNotificationMirrorSink(
            object : NotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) {
                    events += MirrorEvent.Upsert(snapshot)
                }

                override fun onRemoved(notificationId: String, revision: Long) = Unit
                override fun onSnapshot(snapshot: ActiveNotificationSnapshot) = Unit
            },
        )

        try {
            val postedAt = 123_456L
            val first = testNotification(
                context,
                "com.example.selected",
                postTime = postedAt,
                actionRequestCode = 101,
            )
            LocalNotificationController.onPosted(context, first, isSilent = false)
            val firstUpsert = (events.single() as MirrorEvent.Upsert).value

            val updatedAction = testNotification(
                context,
                "com.example.selected",
                postTime = postedAt,
                actionRequestCode = 102,
                actionIntentAction = secondAction,
            )
            LocalNotificationController.onPosted(context, updatedAction, isSilent = false)

            assertEquals(1, events.size)
            assertEquals(
                ActionExecutionStatus.SUCCEEDED,
                LocalNotificationController.invoke(
                    context,
                    firstUpsert.actions.single().token,
                    operationAuthorizer = RemoteOperationAuthorizer { _, _ -> true },
                ).status,
            )
            assertTrue(received.await(5, TimeUnit.SECONDS))
        } finally {
            context.unregisterReceiver(receiver)
            LocalNotificationController.installNotificationMirrorSink(null)
            LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, _ -> null })
            LocalNotificationController.clear()
        }
    }

    @Test
    fun groupChildReplacesSummaryAndSummaryReturnsAfterChildRemoval() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val events = mutableListOf<MirrorEvent>()
        LocalNotificationController.clear()
        LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, snapshot -> snapshot })
        LocalNotificationController.installNotificationMirrorSink(
            object : NotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) {
                    events += MirrorEvent.Upsert(snapshot)
                }

                override fun onRemoved(notificationId: String, revision: Long) {
                    events += MirrorEvent.Removed(notificationId, revision)
                }

                override fun onSnapshot(snapshot: ActiveNotificationSnapshot) {
                    events += MirrorEvent.Snapshot(snapshot)
                }
            },
        )

        try {
            val summary = testNotification(
                context,
                "com.example.selected",
                id = 92,
                tag = "summary",
                groupKey = "messages",
                isGroupSummary = true,
            )
            val child = testNotification(
                context,
                "com.example.selected",
                id = 93,
                tag = "child",
                groupKey = "messages",
            )
            LocalNotificationController.onPosted(context, summary, isSilent = false)
            val firstSummary = (events.single() as MirrorEvent.Upsert).value

            events.clear()
            LocalNotificationController.onPosted(context, child, isSilent = false)
            val childUpsert = events.filterIsInstance<MirrorEvent.Upsert>().single().value
            val summaryRemoval = events.filterIsInstance<MirrorEvent.Removed>().single()
            assertEquals(child.key, childUpsert.key)
            assertEquals(summary.key, summaryRemoval.notificationId)
            assertTrue(summaryRemoval.revision > firstSummary.revision)

            events.clear()
            LocalNotificationController.onRemoved(context, child.key)
            val childRemoval = events.filterIsInstance<MirrorEvent.Removed>().single()
            val restoredSummary = events.filterIsInstance<MirrorEvent.Upsert>().single().value
            assertEquals(child.key, childRemoval.notificationId)
            assertEquals(summary.key, restoredSummary.key)
            assertTrue(restoredSummary.revision > summaryRemoval.revision)
        } finally {
            LocalNotificationController.installNotificationMirrorSink(null)
            LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, _ -> null })
            LocalNotificationController.clear()
        }
    }

    @Test
    fun unavailableListenerPublishesEmptySnapshotAbovePreviousNotification() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val snapshots = mutableListOf<ActiveNotificationSnapshot>()
        LocalNotificationController.clear()
        LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, snapshot -> snapshot })
        LocalNotificationController.installNotificationMirrorSink(
            object : NotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) = Unit
                override fun onRemoved(notificationId: String, revision: Long) = Unit
                override fun onSnapshot(snapshot: ActiveNotificationSnapshot) {
                    snapshots += snapshot
                }
            },
        )

        try {
            LocalNotificationController.onPosted(
                context,
                testNotification(context, "com.example.selected"),
                isSilent = false,
            )
            LocalNotificationController.onActiveSetReady(context)
            val active = snapshots.single()
            assertEquals(1, active.notifications.size)

            LocalNotificationController.onActiveSetUnavailable(context)

            val unavailable = snapshots.last()
            assertTrue(unavailable.notifications.isEmpty())
            assertTrue(unavailable.highWaterRevision > active.notifications.single().revision)
            assertEquals(null, LocalNotificationController.currentActiveSnapshot(context))
        } finally {
            LocalNotificationController.installNotificationMirrorSink(null)
            LocalNotificationController.installMirroringPolicy(NotificationMirroringPolicy { _, _ -> null })
            LocalNotificationController.clear()
        }
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    @Suppress("DEPRECATION")
    private fun registerTestReceiver(
        context: Context,
        receiver: BroadcastReceiver,
        filter: IntentFilter,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
    }

    private fun testNotification(
        context: Context,
        packageName: String,
        id: Int = 91,
        tag: String = "selected",
        groupKey: String? = null,
        isGroupSummary: Boolean = false,
        postTime: Long = System.currentTimeMillis(),
        actionRequestCode: Int = id,
        actionIntentAction: String = "dev.notificationmirroring.TEST_SELECTED_ACTION",
    ): StatusBarNotification {
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            actionRequestCode,
            Intent(actionIntentAction).setPackage(context.packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, "test")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Selected notification")
            .addAction(Notification.Action.Builder(0, "Open", pendingIntent).build())
            .also { builder -> groupKey?.let(builder::setGroup) }
            .setGroupSummary(isGroupSummary)
            .build()
        val constructor = StatusBarNotification::class.java.constructors
            .first { it.parameterTypes.size == 10 }
        val arguments: Array<Any?> =
            if (constructor.parameterTypes[6] == Int::class.javaPrimitiveType) {
                arrayOf(
                    packageName,
                    packageName,
                    id,
                    tag,
                    Process.myUid(),
                    Process.myPid(),
                    0,
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    postTime,
                )
            } else {
                arrayOf(
                    packageName,
                    packageName,
                    id,
                    tag,
                    Process.myUid(),
                    Process.myPid(),
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    null,
                    postTime,
                )
            }
        return constructor.newInstance(*arguments) as StatusBarNotification
    }

    private sealed interface MirrorEvent {
        data class Upsert(val value: NotificationSnapshot) : MirrorEvent
        data class Removed(val notificationId: String, val revision: Long) : MirrorEvent
        data class Snapshot(val value: ActiveNotificationSnapshot) : MirrorEvent
    }
}
