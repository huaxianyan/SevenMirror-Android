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

@JvmInline
value class NotificationActionId(val hex: String) {
    init {
        require(hex.matches(Regex("[0-9a-f]{32}"))) { "action id must be 16-byte lowercase hex" }
    }

    fun toByteArray(): ByteArray = hex.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    companion object {
        fun fromBytes(value: ByteArray): NotificationActionId {
            require(value.size == 16) { "action id must be 16 bytes" }
            return NotificationActionId(
                value.joinToString("") { "%02x".format(it.toInt() and 0xff) },
            )
        }
    }
}

data class NotificationActionToken(
    val notificationKey: String,
    val notificationRevision: Long,
    val actionId: NotificationActionId,
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
