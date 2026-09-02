package dev.notificationmirroring.notification

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Process
import android.os.UserHandle
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LocalNotificationMirroringPolicyInstrumentedTest {
    @Test
    fun selectionChangesEmitFreshUpsertRemovalAndSnapshotRevisions() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val selectedPackages = mutableSetOf<String>()
        val events = mutableListOf<MirrorEvent>()
        LocalNotificationController.clear()
        LocalNotificationController.installMirroringPolicy(
            NotificationMirroringPolicy { _, packageName -> packageName in selectedPackages },
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
            LocalNotificationController.refreshMirroringEligibility(context)

            val upsert = (events[0] as MirrorEvent.Upsert).value
            val selectedSnapshot = (events[1] as MirrorEvent.Snapshot).value
            assertEquals(notification.key, upsert.key)
            assertEquals(upsert.revision, upsert.actions.single().token.notificationRevision)
            assertEquals(listOf(upsert), selectedSnapshot.notifications)
            assertTrue(selectedSnapshot.highWaterRevision > upsert.revision)

            events.clear()
            selectedPackages.clear()
            LocalNotificationController.refreshMirroringEligibility(context)

            val removed = events[0] as MirrorEvent.Removed
            val deselectedSnapshot = (events[1] as MirrorEvent.Snapshot).value
            assertEquals(notification.key, removed.notificationId)
            assertTrue(removed.revision > upsert.revision)
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
                NotificationMirroringPolicy { _, _ -> false },
            )
            LocalNotificationController.clear()
        }
    }

    private fun testNotification(context: Context, packageName: String): StatusBarNotification {
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            91,
            Intent("dev.notificationmirroring.TEST_SELECTED_ACTION").setPackage(context.packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, "test")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Selected notification")
            .addAction(Notification.Action.Builder(0, "Open", pendingIntent).build())
            .build()
        val constructor = StatusBarNotification::class.java.constructors
            .first { it.parameterTypes.size == 10 }
        val arguments: Array<Any?> =
            if (constructor.parameterTypes[6] == Int::class.javaPrimitiveType) {
                arrayOf(
                    packageName,
                    packageName,
                    91,
                    "selected",
                    Process.myUid(),
                    Process.myPid(),
                    0,
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    System.currentTimeMillis(),
                )
            } else {
                arrayOf(
                    packageName,
                    packageName,
                    91,
                    "selected",
                    Process.myUid(),
                    Process.myPid(),
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    null,
                    System.currentTimeMillis(),
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
