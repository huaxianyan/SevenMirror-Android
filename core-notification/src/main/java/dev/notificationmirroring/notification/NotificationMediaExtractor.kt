package dev.notificationmirroring.notification

import android.app.Notification
import android.app.Person
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Build

internal data class ExtractedNotificationMedia(
    val appIcon: NotificationMedia?,
    val avatar: NotificationMedia?,
    val containsContentImage: Boolean,
)

internal object NotificationMediaExtractor {
    fun extract(context: Context, packageName: String, notification: Notification): ExtractedNotificationMedia {
        val messages = messagingStyleMessages(notification)
        val appIcon = loadDrawable {
            context.packageManager.getApplicationIcon(packageName)
        }
        val avatar = messages.asReversed()
            .firstNotNullOfOrNull { message -> message.senderPerson?.icon?.loadDrawableSafely(context) }
            ?: notification.getLargeIcon()?.loadDrawableSafely(context)
            ?: notification.extras.people().asReversed()
                .firstNotNullOfOrNull { person -> person.icon?.loadDrawableSafely(context) }
        val containsContentImage = notification.extras.containsKey(Notification.EXTRA_PICTURE) ||
            messages.any { message -> message.dataMimeType?.startsWith("image/", ignoreCase = true) == true }
        return ExtractedNotificationMedia(
            appIcon = NotificationMediaNormalizer.normalize(appIcon),
            avatar = NotificationMediaNormalizer.normalize(avatar),
            containsContentImage = containsContentImage,
        )
    }

    private fun messagingStyleMessages(notification: Notification): List<Notification.MessagingStyle.Message> {
        if (Build.VERSION.SDK_INT < 30) return emptyList()
        return runCatching {
            @Suppress("DEPRECATION")
            Notification.MessagingStyle.Message.getMessagesFromBundleArray(
                notification.extras.getParcelableArray(Notification.EXTRA_MESSAGES),
            )
        }.getOrDefault(emptyList())
    }

    private fun android.os.Bundle.people(): List<Person> =
        runCatching {
            @Suppress("DEPRECATION")
            getParcelableArrayList<Person>(Notification.EXTRA_PEOPLE_LIST).orEmpty()
        }.getOrDefault(emptyList())

    private fun android.graphics.drawable.Icon.loadDrawableSafely(context: Context): Drawable? =
        loadDrawable { loadDrawable(context) }

    private inline fun loadDrawable(loader: () -> Drawable?): Drawable? =
        try {
            loader()
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: RuntimeException) {
            null
        } catch (_: OutOfMemoryError) {
            null
        }
}
