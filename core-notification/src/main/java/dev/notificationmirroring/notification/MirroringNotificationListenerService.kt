package dev.notificationmirroring.notification

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

/**
 * Foundation-only listener. Real notification data must not leave the device
 * until the mandatory E2EE channel has been implemented and verified.
 */
class MirroringNotificationListenerService : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        // SPIKE-001 will extract notification metadata locally without networking.
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
        // SPIKE-001 will model local removal events without networking.
    }
}
