package dev.notificationmirroring.android

import android.app.Application

class NotificationMirroringApplication : Application() {
    lateinit var transportCoordinator: AndroidTransportCoordinator
        private set

    override fun onCreate() {
        super.onCreate()
        transportCoordinator = AndroidTransportCoordinator(this)
        transportCoordinator.connect()
    }
}
