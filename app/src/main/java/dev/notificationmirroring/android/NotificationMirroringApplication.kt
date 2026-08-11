package dev.notificationmirroring.android

import android.app.Application

class NotificationMirroringApplication : Application() {
    lateinit var transportCoordinator: AndroidTransportCoordinator
        private set
    lateinit var trustPairingController: AndroidTrustPairingController
        private set

    override fun onCreate() {
        super.onCreate()
        transportCoordinator = AndroidTransportCoordinator(this)
        trustPairingController = AndroidTrustPairingController(this)
        transportCoordinator.connect()
    }
}
