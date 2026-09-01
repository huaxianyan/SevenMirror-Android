package dev.notificationmirroring.notification

import android.app.Notification
import android.content.Context
import android.service.notification.StatusBarNotification

internal object NotificationExtractor {
    fun extract(
        context: Context,
        sbn: StatusBarNotification,
        revision: Long,
        isSilent: Boolean,
        actionIds: List<NotificationActionId>,
    ): NotificationSnapshot {
        val notification = sbn.notification
        val media = NotificationMediaExtractor.extract(context, sbn.packageName, notification)
        val text = notification.extras.text(Notification.EXTRA_TEXT)
        val expandedText = notification.extras.text(Notification.EXTRA_BIG_TEXT)
        val normalizedText = if (media.containsContentImage && expandedText == null) {
            text.withContentImagePlaceholder()
        } else {
            text
        }
        val normalizedExpandedText = if (media.containsContentImage && expandedText != null) {
            expandedText.withContentImagePlaceholder()
        } else {
            expandedText
        }
        val platformActions = notification.actions.orEmpty()
        require(platformActions.size == actionIds.size) { "action ID count mismatch" }
        val actions = platformActions.mapIndexed { index, action ->
            val remoteInputs = action.remoteInputs.orEmpty()
            NotificationActionDescriptor(
                token = NotificationActionToken(sbn.key, revision, actionIds[index]),
                title = action.title?.toString()?.takeIf(String::isNotBlank) ?: "Action ${index + 1}",
                semanticAction = action.semanticAction,
                requiresTextInput = remoteInputs.isNotEmpty(),
                allowsFreeFormInput = remoteInputs.any { it.allowFreeFormInput },
            )
        }

        return NotificationSnapshot(
            key = sbn.key,
            revision = revision,
            packageName = sbn.packageName,
            appName = applicationLabel(context, sbn.packageName),
            title = notification.extras.text(Notification.EXTRA_TITLE),
            text = normalizedText,
            expandedText = normalizedExpandedText,
            appIcon = media.appIcon,
            avatar = media.avatar,
            containsContentImage = media.containsContentImage,
            postedAtMillis = sbn.postTime,
            isClearable = sbn.isClearable,
            isOngoing = sbn.isOngoing,
            isSilent = isSilent,
            groupKey = sbn.groupKey,
            isGroupSummary = notification.flags and Notification.FLAG_GROUP_SUMMARY != 0,
            actions = actions,
        )
    }

    private fun applicationLabel(context: Context, packageName: String): String =
        runCatching {
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            context.packageManager.getApplicationLabel(info).toString()
        }.getOrDefault(packageName)

    private fun android.os.Bundle.text(key: String): String? =
        getCharSequence(key)?.toString()?.takeIf(String::isNotBlank)

    private fun String?.withContentImagePlaceholder(): String = when {
        this == null -> CONTENT_IMAGE_PLACEHOLDER
        lineSequence().any { it.trim() == CONTENT_IMAGE_PLACEHOLDER } -> this
        else -> "$this\n$CONTENT_IMAGE_PLACEHOLDER"
    }

    private const val CONTENT_IMAGE_PLACEHOLDER = "[图片]"
}
