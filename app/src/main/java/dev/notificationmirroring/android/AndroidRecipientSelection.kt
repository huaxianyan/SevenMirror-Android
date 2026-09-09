package dev.notificationmirroring.android

import android.content.Context
import dev.notificationmirroring.crypto.WorkspaceNotificationRecipientDirectory

internal data class ReceivingDevice(val key: String, val displayName: String, val selected: Boolean)

internal data class RecipientSettingsState(
    val scope: String,
    val configured: Boolean,
    val devices: List<ReceivingDevice>,
)

/** User choice is separate from signed membership. Missing settings always mean no recipients. */
internal class AndroidRecipientSelection(
    context: Context,
    private val authorizedRecipients: WorkspaceNotificationRecipientDirectory,
) : WorkspaceNotificationRecipientDirectory {
    private val preferences = context.applicationContext.getSharedPreferences(
        "notification_recipients",
        Context.MODE_PRIVATE,
    )

    fun scope(workspaceId: ByteArray, localDeviceId: ByteArray): String =
        "${workspaceId.recipientKey()}/${localDeviceId.recipientKey()}"

    fun isSelected(workspaceId: ByteArray, localDeviceId: ByteArray, deviceId: ByteArray): Boolean =
        deviceId.recipientKey() in selected(scope(workspaceId, localDeviceId))

    override fun listNotificationRecipients(workspaceId: ByteArray, localDeviceId: ByteArray, nowUnixMs: Long) =
        authorizedRecipients.listNotificationRecipients(workspaceId, localDeviceId, nowUnixMs)
            .filter { isSelected(workspaceId, localDeviceId, it.deviceId) }

    fun settings(workspaceId: ByteArray, localDeviceId: ByteArray, nowUnixMs: Long): RecipientSettingsState {
        val scope = scope(workspaceId, localDeviceId)
        val selection = selected(scope)
        val devices = authorizedRecipients.listNotificationRecipients(
            workspaceId,
            localDeviceId,
            nowUnixMs,
        ).map { recipient ->
            val key = recipient.deviceId.recipientKey()
            ReceivingDevice(key, recipient.displayName, key in selection)
        }.sortedWith(
            compareBy(String.CASE_INSENSITIVE_ORDER, ReceivingDevice::displayName)
                .thenBy(ReceivingDevice::key),
        )
        return RecipientSettingsState(scope, preferences.contains(scope), devices)
    }

    fun save(settings: RecipientSettingsState, deviceKeys: Set<String>) {
        require(settings.scope.isNotEmpty()) { "Recipient settings are unavailable" }
        require(settings.devices.map { it.key }.containsAll(deviceKeys)) { "Recipient availability changed" }
        check(preferences.edit().putStringSet(settings.scope, deviceKeys.toSet()).commit()) {
            "Recipient settings could not be saved"
        }
    }

    fun clear() {
        check(preferences.edit().clear().commit()) { "Recipient settings could not be cleared" }
    }

    private fun selected(scope: String): Set<String> = preferences.getStringSet(scope, emptySet()).orEmpty().toSet()
}

private fun ByteArray.recipientKey(): String = joinToString("") { "%02x".format(it) }
