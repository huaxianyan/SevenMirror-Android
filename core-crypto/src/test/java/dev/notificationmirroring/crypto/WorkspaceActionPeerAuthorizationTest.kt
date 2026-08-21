package dev.notificationmirroring.crypto

import com.google.protobuf.ByteString
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceCertificate
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceRole
import dev.notificationmirroring.protocol.generated.membership.v1.DeviceType
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class WorkspaceActionPeerAuthorizationTest {
    private val now = 1_800_000_000_000L

    @Test
    fun requiresAndroidSendAndChromeInvokeRoles() {
        val local = certificate(
            DeviceType.DEVICE_TYPE_ANDROID,
            DeviceRole.DEVICE_ROLE_SEND_NOTIFICATIONS,
            2,
        )
        val peer = certificate(
            DeviceType.DEVICE_TYPE_CHROME,
            DeviceRole.DEVICE_ROLE_INVOKE_NOTIFICATION_ACTIONS,
            3,
        )

        val authorized = checkNotNull(authorizeWorkspaceActionPeer(local, peer, now))
        assertArrayEquals(peer.deviceId.toByteArray(), authorized.deviceId)
        assertArrayEquals(peer.identityKeyId.toByteArray(), authorized.identityKeyId)
        assertArrayEquals(peer.identityPublicKey.toByteArray(), authorized.identityPublicKey)
        assertNull(authorizeWorkspaceActionPeer(
            certificate(DeviceType.DEVICE_TYPE_ANDROID, DeviceRole.DEVICE_ROLE_MANAGE_DEVICES, 2),
            peer,
            now,
        ))
        assertNull(authorizeWorkspaceActionPeer(
            local,
            certificate(DeviceType.DEVICE_TYPE_CHROME, DeviceRole.DEVICE_ROLE_RECEIVE_NOTIFICATIONS, 3),
            now,
        ))
    }

    private fun certificate(type: DeviceType, role: DeviceRole, marker: Int): DeviceCertificate =
        DeviceCertificate.newBuilder()
            .setProtocolVersion(1)
            .setWorkspaceId(ByteString.copyFrom(ByteArray(16) { 1 }))
            .setDeviceId(ByteString.copyFrom(ByteArray(16) { marker.toByte() }))
            .setDeviceType(type)
            .addRoles(role)
            .setIdentityPublicKey(ByteString.copyFrom(byteArrayOf(4) + ByteArray(64) { marker.toByte() }))
            .setIdentityKeyId(ByteString.copyFrom(ByteArray(32) { marker.toByte() }))
            .setIssuedAtUnixMs(now - 1_000)
            .setExpiresAtUnixMs(0)
            .setMembershipEpoch(1)
            .build()
}
