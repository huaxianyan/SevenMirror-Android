package dev.notificationmirroring.android

import android.content.Context
import dev.notificationmirroring.notification.NotificationActionDescriptor
import dev.notificationmirroring.notification.NotificationSnapshot
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import org.json.JSONObject

/** Debug-only public capability reference for the app-owned synthetic notification. */
object SyntheticActionTargetExporter {
    fun export(
        context: Context,
        snapshot: NotificationSnapshot,
        action: NotificationActionDescriptor,
    ): String {
        require(snapshot.packageName == context.packageName) {
            "Only the app-owned synthetic notification can be exported"
        }
        require(action.token.notificationKey == snapshot.key &&
            action.token.notificationRevision == snapshot.revision &&
            !action.requiresTextInput
        ) { "Synthetic action target is inconsistent" }
        val credential = AndroidTransportCredentialStore(context).load()
            ?: error("Transport registration is required")
        return try {
            JSONObject()
                .put("version", 1)
                .put("targetDeviceId", credential.deviceId.toHex())
                .put("targetKeyId", credential.identityKeyId.toHex())
                .put("notificationId", action.token.notificationKey)
                .put("notificationRevision", action.token.notificationRevision.toString())
                .put("actionId", action.token.actionId.hex)
                .toString()
        } finally {
            credential.authToken.fill(0)
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
