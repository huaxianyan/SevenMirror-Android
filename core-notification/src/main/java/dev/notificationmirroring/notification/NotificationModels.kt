package dev.notificationmirroring.notification

data class NotificationSnapshot(
    val key: String,
    val revision: Long,
    val packageName: String,
    val appName: String,
    val title: String?,
    val text: String?,
    val expandedText: String?,
    val postedAtMillis: Long,
    val isClearable: Boolean,
    val isOngoing: Boolean,
    val isSilent: Boolean,
    val groupKey: String?,
    val isGroupSummary: Boolean,
    val actions: List<NotificationActionDescriptor>,
)

data class NotificationActionDescriptor(
    val token: NotificationActionToken,
    val title: String,
    val semanticAction: Int,
    val requiresTextInput: Boolean,
    val allowsFreeFormInput: Boolean,
)

data class NotificationActionToken(
    val notificationKey: String,
    val notificationRevision: Long,
    val actionIndex: Int,
)

enum class ActionExecutionStatus {
    SUCCEEDED,
    NOTIFICATION_NOT_FOUND,
    STALE_NOTIFICATION_VERSION,
    ACTION_NOT_FOUND,
    TEXT_REQUIRED,
    TEXT_NOT_SUPPORTED,
    PENDING_INTENT_CANCELLED,
    INTERNAL_ERROR,
}

data class ActionExecutionResult(
    val status: ActionExecutionStatus,
    val detail: String? = null,
)
