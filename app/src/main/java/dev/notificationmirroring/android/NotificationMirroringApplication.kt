package dev.notificationmirroring.android

import android.app.Application
import dev.notificationmirroring.notification.ActiveNotificationSnapshot
import dev.notificationmirroring.notification.LocalNotificationController
import dev.notificationmirroring.notification.NotificationMirrorSink
import dev.notificationmirroring.notification.NotificationMirroringPolicy
import dev.notificationmirroring.notification.NotificationSnapshot

class NotificationMirroringApplication : Application() {
    lateinit var transportCoordinator: AndroidTransportCoordinator
        private set

    override fun onCreate() {
        super.onCreate()
        ProductDebugActions.restore(this)
        val productPreferences = AndroidProductPreferences(this)
        LocalNotificationController.installMirroringPolicy(
            NotificationMirroringPolicy { context, snapshot ->
                prepareNotificationForMirroring(
                    snapshot = snapshot,
                    ownPackageName = context.packageName,
                    debugFixtureEnabled = ProductDebugActions.available,
                    applicationSelectionConfirmed =
                        productPreferences.isApplicationSelectionConfirmed(),
                    selectedPackages = productPreferences.selectedPackages(),
                    sharingSettings = productPreferences.notificationSharingSettings(),
                )
            },
        )
        transportCoordinator = AndroidTransportCoordinator(this)
        LocalNotificationController.installNotificationMirrorSink(
            object : NotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) {
                    transportCoordinator.mirrorNotification(snapshot)
                }

                override fun onRemoved(notificationId: String, revision: Long) {
                    transportCoordinator.removeNotification(notificationId, revision)
                }

                override fun onSnapshot(snapshot: ActiveNotificationSnapshot) {
                    transportCoordinator.mirrorSnapshot(snapshot)
                }
            },
        )
        transportCoordinator.connect()
    }
}
