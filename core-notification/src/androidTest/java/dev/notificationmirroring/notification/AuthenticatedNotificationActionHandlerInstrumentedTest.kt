package dev.notificationmirroring.notification

import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Process
import android.os.UserHandle
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.protobuf.ByteString
import dev.notificationmirroring.crypto.AndroidActionResultOutbox
import dev.notificationmirroring.crypto.AndroidOperationLedger
import dev.notificationmirroring.crypto.AndroidReplayLedger
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.protocol.EncryptedEnvelopeCodecV1
import dev.notificationmirroring.protocol.EncryptedEnvelopePartsV1
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderCodecV1
import dev.notificationmirroring.protocol.RoutingHeaderV1
import dev.notificationmirroring.protocol.generated.v1.ActionInvoke
import dev.notificationmirroring.protocol.generated.v1.ActionResultStatus
import dev.notificationmirroring.protocol.generated.v1.EncryptedPayload
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

class ActionSideEffectReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context?, intent: Intent?) {
        count.incrementAndGet()
        latch.countDown()
    }

    companion object {
        val count = AtomicInteger()
        @Volatile var latch = CountDownLatch(1)

        fun reset() {
            count.set(0)
            latch = CountDownLatch(1)
        }
    }
}

@RunWith(AndroidJUnit4::class)
class AuthenticatedNotificationActionHandlerInstrumentedTest {
    @Test
    fun invokesOpaqueLocalActionOnceAndReturnsRecoverableResults() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "notification-action-${System.nanoTime()}"
        val replay = AndroidReplayLedger(context, name)
        val operations = AndroidOperationLedger(context, name)
        val trustedPeers = AndroidTrustedPeerStore(context, name)
        val outbox = AndroidActionResultOutbox(context, name)
        val now = 1_800_000_000_000L
        val sender = AuthenticatedHpke.generateKeyPair()
        val recipient = AuthenticatedHpke.generateKeyPair()
        val workspace = ByteArray(16) { 1 }
        val recipientDevice = ByteArray(16) { 3 }
        val dispatcher = AndroidActionInvokeDispatcher(
            context = context,
            workspaceId = workspace,
            recipientDeviceId = recipientDevice,
            recipientIdentity = recipient,
            trustedPeers = trustedPeers,
            replayLedger = replay,
            operationLedger = operations,
            resultOutbox = outbox,
        )
        ActionSideEffectReceiver.reset()
        val sideEffectReceiver = ActionSideEffectReceiver()
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(
                sideEffectReceiver,
                IntentFilter(TEST_ACTION),
                Context.RECEIVER_NOT_EXPORTED,
            )
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(sideEffectReceiver, IntentFilter(TEST_ACTION))
        }
        LocalNotificationController.clear()

        try {
            val sbn = testNotification(context)
            LocalNotificationController.onPosted(context, sbn, isSilent = false)
            val original = LocalNotificationController.notifications.value.single()
            val token = original.actions.single().token

            val first = actionFrame(
                10,
                0xb2,
                token,
                now,
                workspace,
                recipientDevice,
                sender,
                recipient,
            )
            assertThrows(ActionSenderNotApprovedException::class.java) {
                dispatcher.receiveOnce(first, now)
            }
            trustedPeers.pinApproved(workspace, ByteArray(16) { 2 }, sender.publicKey)
            val firstResult = dispatcher.receiveOnce(first, now)
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED, firstResult.result.status)
            assertEquals(false, firstResult.recovered)
            assertTrue(ActionSideEffectReceiver.latch.await(2, TimeUnit.SECONDS))
            assertEquals(1, ActionSideEffectReceiver.count.get())

            val duplicate = actionFrame(
                11,
                0xb2,
                token,
                now,
                workspace,
                recipientDevice,
                sender,
                recipient,
            )
            val recovered = dispatcher.receiveOnce(duplicate, now)
            assertEquals(true, recovered.recovered)
            assertEquals(ActionResultStatus.ACTION_RESULT_STATUS_SUCCEEDED, recovered.result.status)
            assertEquals(1, ActionSideEffectReceiver.count.get())

            LocalNotificationController.onPosted(context, sbn, isSilent = false)
            val stale = actionFrame(
                12,
                0xc3,
                token,
                now,
                workspace,
                recipientDevice,
                sender,
                recipient,
            )
            val staleResult = dispatcher.receiveOnce(stale, now)
            assertEquals(
                ActionResultStatus.ACTION_RESULT_STATUS_STALE_NOTIFICATION_VERSION,
                staleResult.result.status,
            )
            assertEquals(1, ActionSideEffectReceiver.count.get())

            val current = LocalNotificationController.notifications.value.single().actions.single().token
            val unknownAction = current.copy(actionId = NotificationActionId("00".repeat(16)))
            val unknown = actionFrame(
                13,
                0xd4,
                unknownAction,
                now,
                workspace,
                recipientDevice,
                sender,
                recipient,
            )
            val unknownResult = dispatcher.receiveOnce(unknown, now)
            assertEquals(
                ActionResultStatus.ACTION_RESULT_STATUS_ACTION_NOT_FOUND,
                unknownResult.result.status,
            )
            assertEquals(1, ActionSideEffectReceiver.count.get())
        } finally {
            context.unregisterReceiver(sideEffectReceiver)
            LocalNotificationController.clear()
            replay.clear()
            operations.clear()
            trustedPeers.clear()
            outbox.clear()
        }
    }

    private fun testNotification(context: Context): StatusBarNotification {
        val intent = Intent(TEST_ACTION).setPackage(context.packageName)
        val pendingIntent = PendingIntent.getBroadcast(
            context,
            42,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val action = Notification.Action.Builder(0, "Mark as read", pendingIntent).build()
        val notification = Notification.Builder(context, "test")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Test")
            .addAction(action)
            .build()
        val constructor = StatusBarNotification::class.java.constructors
            .first { it.parameterTypes.size == 10 }
        val arguments: Array<Any?> =
            if (constructor.parameterTypes[6] == Int::class.javaPrimitiveType) {
                arrayOf(
                    context.packageName,
                    context.packageName,
                    42,
                    "test",
                    Process.myUid(),
                    Process.myPid(),
                    0,
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    System.currentTimeMillis(),
                )
            } else {
                arrayOf(
                    context.packageName,
                    context.packageName,
                    42,
                    "test",
                    Process.myUid(),
                    Process.myPid(),
                    notification,
                    UserHandle.getUserHandleForUid(Process.myUid()),
                    null,
                    System.currentTimeMillis(),
                )
            }
        return constructor.newInstance(*arguments) as StatusBarNotification
    }

    private fun actionFrame(
        messageByte: Int,
        idempotencyByte: Int,
        token: NotificationActionToken,
        now: Long,
        workspace: ByteArray,
        recipientDevice: ByteArray,
        sender: AuthenticatedHpke.KeyPair,
        recipient: AuthenticatedHpke.KeyPair,
    ): ByteArray {
        val request = ActionInvoke.newBuilder()
            .setNotificationId(token.notificationKey)
            .setNotificationRevision(token.notificationRevision)
            .setActionId(ByteString.copyFrom(token.actionId.toByteArray()))
            .setIdempotencyKey(ByteString.copyFrom(ByteArray(16) { idempotencyByte.toByte() }))
            .build()
        val plaintext = EncryptedPayloadCodecV1.encode(
            EncryptedPayload.newBuilder()
                .setSchemaVersion(1)
                .setActionInvoke(request)
                .build(),
        )
        val header = RoutingHeaderCodecV1.encode(
            RoutingHeaderV1(
                workspaceId = workspace,
                senderDeviceId = ByteArray(16) { 2 },
                recipientDeviceId = recipientDevice,
                senderKeyId = sha256(sender.publicKey),
                recipientKeyId = sha256(recipient.publicKey),
                messageId = ByteArray(16) { messageByte.toByte() },
                sequence = messageByte.toLong(),
                createdAtUnixMs = now,
                expiresAtUnixMs = now + 60_000,
            ),
        )
        val encrypted = AuthenticatedHpke.seal(recipient.publicKey, sender, plaintext, header)
        return EncryptedEnvelopeCodecV1.encode(
            EncryptedEnvelopePartsV1(header, encrypted.encapsulatedKey, encrypted.ciphertext),
        )
    }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private companion object {
        const val TEST_ACTION = "dev.notificationmirroring.TEST_ACTION"
    }
}
