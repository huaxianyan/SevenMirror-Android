package com.neko7ina.sevenmirror.notification

enum class RemoteOperationType {
    ACTION,
    REPLY,
    CLEAR,
}

fun interface RemoteOperationAuthorizer {
    fun isAllowed(packageName: String, operation: RemoteOperationType): Boolean
}
