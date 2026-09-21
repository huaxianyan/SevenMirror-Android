package com.neko7ina.sevenmirror

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** Security error screens with supplied recovery values, not a real Keystore or roster failure. */
class SecurityRecoveryInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test
    fun everySecurityErrorOffersRegisteringThisDeviceAgain() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        fun text(id: Int) = context.getString(id)
        var recovery by mutableStateOf(AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL)
        var reEnrollRequests = 0
        var retryRequests = 0
        compose.setContent {
            MaterialTheme {
                SecurityErrorScreen(
                    recovery = recovery,
                    onRetry = { retryRequests++ },
                    onReEnroll = { reEnrollRequests++ },
                )
            }
        }

        compose.onNodeWithText(text(R.string.device_removed_title)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.re_enroll_device)).assertIsDisplayed()

        compose.runOnIdle { recovery = AndroidSecurityRecovery.UNREADABLE_LOCAL_CREDENTIAL }
        compose.onNodeWithText(text(R.string.unreadable_credential_title)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.unreadable_credential_body)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.re_enroll_device)).assertIsDisplayed()

        // The generic security error is the only one that can still be transient, so it offers the
        // non-destructive retry before registering again, and it never tells the user to have the
        // device removed from the workspace: that advice destroys a valid enrollment.
        compose.runOnIdle { recovery = AndroidSecurityRecovery.NONE }
        compose.onNodeWithText(text(R.string.security_error_title)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.security_error_recovery)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.retry_connection)).performClick()
        compose.runOnIdle {
            assertEquals(1, retryRequests)
            assertEquals(0, reEnrollRequests)
        }
        compose.onNodeWithText(text(R.string.re_enroll_device)).performClick()
        compose.onNodeWithText(text(R.string.re_enroll_confirmation_title)).assertIsDisplayed()
        compose.onNodeWithText(text(R.string.re_enroll_confirm)).performClick()
        compose.runOnIdle { assertEquals(1, reEnrollRequests) }
    }
}
