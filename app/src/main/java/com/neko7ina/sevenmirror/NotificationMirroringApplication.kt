package com.neko7ina.sevenmirror

import android.app.Application
import com.neko7ina.sevenmirror.notification.ActiveNotificationSnapshot
import com.neko7ina.sevenmirror.notification.LocalNotificationController
import com.neko7ina.sevenmirror.notification.NotificationMirrorSink
import com.neko7ina.sevenmirror.notification.NotificationMirroringPolicy
import com.neko7ina.sevenmirror.notification.NotificationSnapshot

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
                    debugFixtureEnabled = ProductDebugActions.isFixtureNotification(snapshot),
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
    }
}
