package dev.notificationmirroring.notification

import android.app.NotificationManager
import android.service.notification.NotificationListenerService
import android.service.notification.NotificationListenerService.Ranking
import android.service.notification.StatusBarNotification

/**
 * Notification listener whose process-level controller applies the user's application
 * selection before any notification enters the encrypted mirror sink.
 */
class MirroringNotificationListenerService : NotificationListenerService() {
    override fun onListenerConnected() {
        super.onListenerConnected()
        LocalNotificationController.installDismissSink(::cancelNotification)
        activeNotifications.orEmpty().forEach {
            LocalNotificationController.onPosted(this, it, isSilent(it.key))
        }
        LocalNotificationController.onActiveSetReady(this)
    }

    override fun onListenerDisconnected() {
        LocalNotificationController.installDismissSink(null)
        LocalNotificationController.clear()
        super.onListenerDisconnected()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn?.let { LocalNotificationController.onPosted(this, it, isSilent(it.key)) }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        sbn?.key?.let { LocalNotificationController.onRemoved(this, it) }
    }

    override fun onDestroy() {
        LocalNotificationController.installDismissSink(null)
        super.onDestroy()
    }

    private fun isSilent(notificationKey: String): Boolean {
        val ranking = Ranking()
        return currentRanking.getRanking(notificationKey, ranking) &&
            ranking.importance <= NotificationManager.IMPORTANCE_LOW
    }
}
