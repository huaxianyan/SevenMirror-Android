package dev.notificationmirroring.android

import android.app.Application
import dev.notificationmirroring.notification.LocalNotificationController
import dev.notificationmirroring.notification.NotificationSnapshot
import dev.notificationmirroring.notification.SyntheticNotificationMirrorSink

class NotificationMirroringApplication : Application() {
    lateinit var transportCoordinator: AndroidTransportCoordinator
        private set
    lateinit var trustPairingController: AndroidTrustPairingController
        private set

    override fun onCreate() {
        super.onCreate()
        DebugActionState.restore(this)
        transportCoordinator = AndroidTransportCoordinator(this)
        LocalNotificationController.installSyntheticMirrorSink(
            object : SyntheticNotificationMirrorSink {
                override fun onUpsert(snapshot: NotificationSnapshot) {
                    transportCoordinator.mirrorSyntheticNotification(snapshot)
                }

                override fun onRemoved(notificationId: String, revision: Long) {
                    transportCoordinator.removeSyntheticNotification(notificationId, revision)
                }
            },
        )
        trustPairingController = AndroidTrustPairingController(this)
        transportCoordinator.connect()
    }
}
