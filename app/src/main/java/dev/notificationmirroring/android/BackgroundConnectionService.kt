package dev.notificationmirroring.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/** User-controlled foreground owner for the persistent encrypted relay connection. */
class BackgroundConnectionService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var coordinator: AndroidTransportCoordinator
    private var stateJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        coordinator = (application as NotificationMirroringApplication).transportCoordinator
        createNotificationChannel()
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            statusNotification(AndroidTransportState.INITIALIZING),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
        stateJob = scope.launch {
            coordinator.state.collectLatest { state ->
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, statusNotification(state))
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            AndroidProductPreferences(this).saveBackgroundConnectionEnabled(false)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!AndroidProductPreferences(this).isBackgroundConnectionEnabled() ||
            !canShowForegroundStatus(this)
        ) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (coordinator.state.value.shouldStartConnection()) {
            coordinator.connect()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stateJob?.cancel()
        scope.cancel()
        coordinator.disconnect()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.background_connection_channel),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.background_connection_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun statusNotification(state: AndroidTransportState): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, BackgroundConnectionService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_status)
            .setContentTitle(getString(R.string.background_connection_notification_title))
            .setContentText(getString(state.notificationMessage()))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .addAction(0, getString(R.string.stop_background_connection), stopIntent)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "sevenmirror_background_connection"
        private const val NOTIFICATION_ID = 20_001
        private const val ACTION_STOP = "dev.notificationmirroring.android.action.STOP_BACKGROUND_CONNECTION"

        fun reconcile(context: Context, canShowStatusNotification: Boolean) {
            val appContext = context.applicationContext
            if (AndroidProductPreferences(appContext).isBackgroundConnectionEnabled() &&
                canShowStatusNotification
            ) {
                ContextCompat.startForegroundService(
                    appContext,
                    Intent(appContext, BackgroundConnectionService::class.java),
                )
            } else {
                appContext.stopService(Intent(appContext, BackgroundConnectionService::class.java))
            }
        }
    }
}

private fun canShowForegroundStatus(context: Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        ContextCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED

private fun AndroidTransportState.shouldStartConnection(): Boolean = when (this) {
    AndroidTransportState.INITIALIZING,
    AndroidTransportState.NOT_CONFIGURED,
    AndroidTransportState.OFFLINE,
    -> true
    AndroidTransportState.SUBMITTING_REGISTRATION,
    AndroidTransportState.REGISTERING,
    AndroidTransportState.ROTATING,
    AndroidTransportState.CONNECTING,
    AndroidTransportState.ONLINE,
    AndroidTransportState.SECURITY_ERROR,
    -> false
}

private fun AndroidTransportState.notificationMessage(): Int = when (this) {
    AndroidTransportState.ONLINE -> R.string.background_connection_online
    AndroidTransportState.SECURITY_ERROR -> R.string.background_connection_security_error
    AndroidTransportState.OFFLINE -> R.string.background_connection_offline
    AndroidTransportState.NOT_CONFIGURED -> R.string.background_connection_not_configured
    AndroidTransportState.INITIALIZING,
    AndroidTransportState.SUBMITTING_REGISTRATION,
    AndroidTransportState.REGISTERING,
    AndroidTransportState.ROTATING,
    AndroidTransportState.CONNECTING,
    -> R.string.background_connection_connecting
}
