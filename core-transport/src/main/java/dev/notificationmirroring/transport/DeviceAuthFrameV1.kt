package dev.notificationmirroring.transport

data class DeviceTransportCredential(
    val workspaceId: ByteArray,
    val deviceId: ByteArray,
    val authToken: ByteArray,
)

object DeviceAuthFrameCodecV1 {
    const val ENCODED_SIZE = 68
    const val AUTH_TOKEN_SIZE = 32
    private const val ID_SIZE = 16
    private val magic = byteArrayOf(0x53, 0x4e, 0x41, 0x31) // SNA1

    fun encode(credential: DeviceTransportCredential): ByteArray {
        validateIdentifier(credential.workspaceId, "workspaceId")
        validateIdentifier(credential.deviceId, "deviceId")
        require(credential.authToken.size == AUTH_TOKEN_SIZE) {
            "authToken must be $AUTH_TOKEN_SIZE bytes"
        }
        return ByteArray(ENCODED_SIZE).also { frame ->
            magic.copyInto(frame, 0)
            credential.workspaceId.copyInto(frame, 4)
            credential.deviceId.copyInto(frame, 20)
            credential.authToken.copyInto(frame, 36)
        }
    }

    /** Test/diagnostic decoder. Production clients only need to encode this frame. */
    fun decode(frame: ByteArray): DeviceTransportCredential {
        require(frame.size == ENCODED_SIZE) { "device auth frame must be $ENCODED_SIZE bytes" }
        require(frame.copyOfRange(0, 4).contentEquals(magic)) {
            "unsupported device auth frame magic/version"
        }
        return DeviceTransportCredential(
            workspaceId = frame.copyOfRange(4, 20),
            deviceId = frame.copyOfRange(20, 36),
            authToken = frame.copyOfRange(36, 68),
        ).also {
            validateIdentifier(it.workspaceId, "workspaceId")
            validateIdentifier(it.deviceId, "deviceId")
        }
    }

    private fun validateIdentifier(value: ByteArray, name: String) {
        require(value.size == ID_SIZE && value.any { it != 0.toByte() }) {
            "$name must be a non-zero $ID_SIZE-byte value"
        }
    }
}
