package dev.notificationmirroring.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.crypto.WorkspaceNotificationRecipient
import dev.notificationmirroring.crypto.WorkspaceNotificationRecipientDirectory
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidRecipientSelectionInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val workspaceId = ByteArray(16) { 1 }
    private val localDeviceId = ByteArray(16) { 2 }
    private val first = recipient("Personal browser", 3)
    private val second = recipient("Work browser", 4)
    private var authorized = listOf(first, second)
    private lateinit var selection: AndroidRecipientSelection

    @Before
    fun setUp() {
        context.getSharedPreferences("notification_recipients", Context.MODE_PRIVATE).edit().clear().commit()
        selection = AndroidRecipientSelection(context, WorkspaceNotificationRecipientDirectory { _, _, _ -> authorized })
    }

    @After
    fun tearDown() {
        context.getSharedPreferences("notification_recipients", Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun userSelectionLimitsCurrentRecipientsAndRestoresExplicitChoices() {
        assertTrue(selection.listNotificationRecipients(workspaceId, localDeviceId, 1).isEmpty())

        val settings = selection.settings(workspaceId, localDeviceId, 1)
        assertEquals(false, settings.configured)
        selection.save(settings, emptySet())

        val restored = AndroidRecipientSelection(
            context,
            WorkspaceNotificationRecipientDirectory { _, _, _ -> authorized },
        )
        val restoredEmpty = restored.settings(workspaceId, localDeviceId, 1)
        assertEquals(true, restoredEmpty.configured)
        assertTrue(restored.listNotificationRecipients(workspaceId, localDeviceId, 1).isEmpty())

        val workKey = restoredEmpty.devices.single { it.displayName == "Work browser" }.key
        restored.save(restoredEmpty, setOf(workKey))
        assertEquals(listOf("Work browser"), restored.listNotificationRecipients(workspaceId, localDeviceId, 1).map { it.displayName })

        authorized = listOf(first)
        assertTrue(restored.listNotificationRecipients(workspaceId, localDeviceId, 1).isEmpty())
        assertEquals(emptyList<ReceivingDevice>(), restored.settings(workspaceId, localDeviceId, 1).devices.filter { it.selected })
    }

    private fun recipient(name: String, id: Int) = WorkspaceNotificationRecipient(
        displayName = name,
        deviceId = ByteArray(16) { id.toByte() },
        identityKeyId = ByteArray(32) { (id + 1).toByte() },
        identityPublicKey = ByteArray(65) { (id + 2).toByte() },
    )
}
