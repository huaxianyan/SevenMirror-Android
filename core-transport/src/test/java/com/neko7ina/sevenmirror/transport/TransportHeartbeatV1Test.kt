package com.neko7ina.sevenmirror.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportHeartbeatV1Test {
    @Test
    fun encodesTheCanonicalRequestAndRecognizesOnlyTheCanonicalResponse() {
        assertArrayEquals(
            byteArrayOf(0x53, 0x4e, 0x48, 0x31),
            TransportHeartbeatV1.encodeRequest(),
        )
        assertTrue(TransportHeartbeatV1.isResponse(byteArrayOf(0x53, 0x4e, 0x48, 0x32)))
        assertFalse(
            "the request must not be accepted as the response",
            TransportHeartbeatV1.isResponse(TransportHeartbeatV1.encodeRequest()),
        )
        assertFalse(
            "a longer frame is not a heartbeat",
            TransportHeartbeatV1.isResponse(byteArrayOf(0x53, 0x4e, 0x48, 0x32, 0x00)),
        )
        assertFalse(
            "an empty frame is not a heartbeat",
            TransportHeartbeatV1.isResponse(byteArrayOf()),
        )
    }

    @Test
    fun handsOutAFreshRequestBuffer() {
        val first = TransportHeartbeatV1.encodeRequest()
        first.fill(0)
        assertArrayEquals(
            "a caller zeroing its frame must not poison later heartbeats",
            byteArrayOf(0x53, 0x4e, 0x48, 0x31),
            TransportHeartbeatV1.encodeRequest(),
        )
    }
}
