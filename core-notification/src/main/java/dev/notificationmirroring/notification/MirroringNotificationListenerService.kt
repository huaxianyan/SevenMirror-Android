package dev.notificationmirroring.notification

import android.app.NotificationManager
import android.service.notification.NotificationListenerService
import android.service.notification.NotificationListenerService.Ranking
import android.service.notification.StatusBarNotification

/**
 * SPIKE-001 listener. Notification data remains process-local and is never
 * logged, persisted, or transmitted while mandatory E2EE is unavailable.
 */
class MirroringNotificationListenerService : NotificationListenerService() {
    override fun onListenerConnected() {
        super.onListenerConnected()
        activeNotifications.orEmpty().forEach {
            LocalNotificationController.onPosted(this, it, isSilent(it.key))
        }
    }

    override fun onListenerDisconnected() {
        LocalNotificationController.clear()
        super.onListenerDisconnected()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn?.let { LocalNotificationController.onPosted(this, it, isSilent(it.key)) }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        sbn?.key?.let(LocalNotificationController::onRemoved)
    }

    private fun isSilent(notificationKey: String): Boolean {
        val ranking = Ranking()
        return currentRanking.getRanking(notificationKey, ranking) &&
            ranking.importance <= NotificationManager.IMPORTANCE_LOW
    }
}
