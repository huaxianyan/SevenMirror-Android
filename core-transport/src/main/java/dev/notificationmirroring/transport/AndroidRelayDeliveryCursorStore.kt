package dev.notificationmirroring.transport

import android.content.Context

data class RelayDeliveryCursorState(
    val committedDeliveryId: Long,
    val snapshotRequiredHighWater: Long? = null,
)

/** Non-secret, process-reconstructible recipient cursor keyed by exact workspace/device tuple. */
class AndroidRelayDeliveryCursorStore(
    context: Context,
    stateName: String = "default",
) {
    private val safeName = stateName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "stateName must be 1-64 URL-safe characters"
        }
    }
    private val preferences = context.applicationContext.getSharedPreferences(
        "syncnotifications.relay-delivery-cursor.$safeName",
        Context.MODE_PRIVATE,
    )

    @Synchronized
    fun load(workspaceId: ByteArray, deviceId: ByteArray): RelayDeliveryCursorState {
        val tuple = tuple(workspaceId, deviceId)
        val encoded = preferences.getString(tuple, null)
            ?: return RelayDeliveryCursorState(0)
        return decode(encoded)
    }

    @Synchronized
    fun commitDelivery(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        deliveryId: Long,
    ): RelayDeliveryCursorState {
        require(deliveryId > 0) { "Relay delivery cursor is out of range" }
        val tuple = tuple(workspaceId, deviceId)
        val current = preferences.getString(tuple, null)?.let(::decode)
            ?: RelayDeliveryCursorState(0)
        check(current.snapshotRequiredHighWater == null) {
            "Relay delivery cursor requires snapshot reconciliation"
        }
        if (deliveryId == current.committedDeliveryId) return current
        check(deliveryId == Math.addExact(current.committedDeliveryId, 1)) {
            "Relay deliveries are not contiguous"
        }
        val next = RelayDeliveryCursorState(deliveryId)
        persist(tuple, next)
        return next
    }

    @Synchronized
    fun requireSnapshot(
        workspaceId: ByteArray,
        deviceId: ByteArray,
        highWater: Long,
    ): RelayDeliveryCursorState {
        require(highWater >= 0) { "Relay snapshot high-water is out of range" }
        val tuple = tuple(workspaceId, deviceId)
        val current = preferences.getString(tuple, null)?.let(::decode)
            ?: RelayDeliveryCursorState(0)
        check(highWater >= current.committedDeliveryId) {
            "Relay snapshot high-water is behind the committed cursor"
        }
        val existing = current.snapshotRequiredHighWater
        val next = current.copy(
            snapshotRequiredHighWater = if (existing == null || highWater > existing) {
                highWater
            } else {
                existing
            },
        )
        persist(tuple, next)
        return next
    }

    @Synchronized
    fun clearForTests() {
        check(preferences.edit().clear().commit()) { "Failed to clear relay cursor state" }
    }

    private fun persist(tuple: String, state: RelayDeliveryCursorState) {
        validate(state)
        val encoded = buildString {
            append(state.committedDeliveryId)
            state.snapshotRequiredHighWater?.let {
                append(':')
                append(it)
            }
        }
        check(preferences.edit().putString(tuple, encoded).commit()) {
            "Failed to persist relay delivery cursor"
        }
    }

    private fun decode(encoded: String): RelayDeliveryCursorState {
        check(encoded.matches(Regex("0|[1-9][0-9]*(?::(?:0|[1-9][0-9]*))?"))) {
            "Stored relay delivery cursor is corrupt"
        }
        val parts = encoded.split(':')
        val state = try {
            RelayDeliveryCursorState(
                committedDeliveryId = parts[0].toLong(),
                snapshotRequiredHighWater = parts.getOrNull(1)?.toLong(),
            )
        } catch (error: NumberFormatException) {
            throw IllegalStateException("Stored relay delivery cursor is corrupt", error)
        }
        validate(state)
        return state
    }

    private fun validate(state: RelayDeliveryCursorState) {
        check(state.committedDeliveryId >= 0) { "Stored relay delivery cursor is corrupt" }
        state.snapshotRequiredHighWater?.let { highWater ->
            check(highWater >= state.committedDeliveryId) {
                "Stored relay snapshot high-water is corrupt"
            }
        }
    }

    private fun tuple(workspaceId: ByteArray, deviceId: ByteArray): String {
        requireId(workspaceId, "workspaceId")
        requireId(deviceId, "deviceId")
        return "${workspaceId.toHex()}:${deviceId.toHex()}"
    }

    private fun requireId(value: ByteArray, name: String) {
        require(value.size == 16 && value.any { it.toInt() != 0 }) {
            "$name must be a non-zero 16-byte identifier"
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
