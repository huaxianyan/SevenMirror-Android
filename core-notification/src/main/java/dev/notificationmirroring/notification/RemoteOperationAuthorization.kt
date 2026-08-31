package dev.notificationmirroring.notification

enum class RemoteOperationType {
    ACTION,
    REPLY,
    CLEAR,
}

fun interface RemoteOperationAuthorizer {
    fun isAllowed(packageName: String, operation: RemoteOperationType): Boolean
}
