package com.neko7ina.sevenmirror.transport

/**
 * The four-byte authenticated-transport heartbeat, consumed at the transport boundary.
 *
 * The relay answers `SNH1` with `SNH2` on the same socket and never routes either frame through
 * the ciphertext hub. Neither may therefore reach envelope decoding or business reconciliation:
 * unreadable bytes are a verdict on the wire, and the coordinator's response to that verdict is to
 * park the device until it is opened again. A heartbeat that leaks past this boundary would look
 * exactly like a malformed envelope.
 */
object TransportHeartbeatV1 {
    const val ENCODED_SIZE = 4
    private val request = byteArrayOf(0x53, 0x4e, 0x48, 0x31) // SNH1
    private val response = byteArrayOf(0x53, 0x4e, 0x48, 0x32) // SNH2

    fun encodeRequest(): ByteArray = request.copyOf()

    fun isResponse(frame: ByteArray): Boolean = frame.contentEquals(response)
}

/**
 * The relay authenticated this socket and then stopped answering the transport heartbeat.
 *
 * This is the one failure the socket-level `pingInterval` cannot see: a peer whose WebSocket
 * implementation still answers protocol pings while its application layer no longer routes anything
 * looks perfectly healthy from below. It is its own type so the `failure=<class name>` the
 * diagnostics record names the cause outright rather than reading as a generic state error.
 */
class TransportHeartbeatTimeoutException(message: String) : IllegalStateException(message)
