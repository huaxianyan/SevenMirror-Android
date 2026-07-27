package dev.notificationmirroring.notification

import android.app.Notification
import android.content.Context
import android.service.notification.StatusBarNotification

internal object NotificationExtractor {
    fun extract(
        context: Context,
        sbn: StatusBarNotification,
        revision: Long,
    ): NotificationSnapshot {
        val notification = sbn.notification
        val actions = notification.actions.orEmpty().mapIndexed { index, action ->
            val remoteInputs = action.remoteInputs.orEmpty()
            NotificationActionDescriptor(
                token = NotificationActionToken(sbn.key, revision, index),
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
            text = notification.extras.text(Notification.EXTRA_TEXT),
            expandedText = notification.extras.text(Notification.EXTRA_BIG_TEXT),
            postedAtMillis = sbn.postTime,
            isClearable = sbn.isClearable,
            isOngoing = sbn.isOngoing,
            isSilent = notification.silent,
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
}
