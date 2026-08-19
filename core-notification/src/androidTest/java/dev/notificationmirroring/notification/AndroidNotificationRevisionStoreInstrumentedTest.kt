package dev.notificationmirroring.notification

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidNotificationRevisionStoreInstrumentedTest {
    @Test
    fun postingAfterStoreRecreationUsesANewerRevision() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "notification-revision-${System.nanoTime()}"
        val firstProcess = AndroidNotificationRevisionStore(context, name)
        try {
            assertEquals(1L, firstProcess.allocate())
            val recreatedProcess = AndroidNotificationRevisionStore(context, name)
            assertEquals(2L, recreatedProcess.allocate())
        } finally {
            firstProcess.clear()
        }
    }
}
