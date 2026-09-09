package dev.notificationmirroring.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.performScrollToNode
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** Production screen integration with a fixed catalog and supplied platform status, not enrollment or OS permission E2E. */
class ProductNavigationInstrumentedTest {
    @get:Rule val compose = createComposeRule()

    @Test
    fun savedAppPolicyRestoresContentAndOperationChoicesTogether() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val preferences = AndroidProductPreferences(context)
        val pkg = "com.example.productsettingsfixture"
        val previousContent = preferences.notificationSharingSettings().settingsFor(pkg)
        val previousOverride = preferences.remoteOperationSettings().applicationOverrides[pkg]
        try {
            preferences.saveApplicationSettings(
                pkg, ApplicationNotificationSettings(showContent = false, syncOngoing = true),
                ApplicationOperationOverride(ApplicationOperationMode.VIEW_ONLY),
            )
            val restored = AndroidProductPreferences(context)
            assertEquals(false, restored.notificationSharingSettings().settingsFor(pkg).showContent)
            assertEquals(true, restored.notificationSharingSettings().settingsFor(pkg).syncOngoing)
            assertEquals(ApplicationOperationMode.VIEW_ONLY, restored.remoteOperationSettings().applicationOverrides[pkg]?.mode)
        } finally {
            preferences.saveApplicationSettings(pkg, previousContent, previousOverride)
        }
    }

    @Test
    fun userFindsAppPolicyInSettingsAndCanRecoverMissingPermission() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        fun text(id: Int) = context.getString(id)
        var selected by mutableStateOf(setOf("com.example.calendar"))
        var sharing by mutableStateOf(NotificationSharingSettings())
        var operations by mutableStateOf(RemoteOperationSettings())
        var access by mutableStateOf(true)
        var background by mutableStateOf(false)
        compose.setContent {
            MaterialTheme {
                MainScreen(
                    transportState = AndroidTransportState.ONLINE,
                    workspaceDevices = emptyList(),
                    serverOrigin = "https://mirror.example",
                    notificationAccessGranted = access,
                    applications = listOf(SelectableApplication("com.example.calendar", "Calendar example", false)),
                    applicationsLoaded = true,
                    applicationsLoadFailed = false,
                    selectedPackages = selected,
                    notificationSharingSettings = sharing,
                    remoteOperationSettings = operations,
                    backgroundConnectionEnabled = background,
                    foregroundNotificationGranted = true,
                    batteryOptimizationExempt = false,
                    omittedNotificationCount = 0,
                    onSaveApplicationSelection = { selected = it },
                    onSaveSyncSilentNotifications = { sharing = sharing.copy(syncSilent = it) },
                    onSaveApplicationSettings = { pkg, value, override ->
                        sharing = sharing.copy(hiddenContentPackages = if (value.showContent) emptySet() else setOf(pkg))
                        operations = operations.copy(applicationOverrides = override?.let { mapOf(pkg to it) }.orEmpty())
                    },
                    onSaveGlobalRemoteOperations = { operations = operations.copy(globalDefaults = it) },
                    onOpenNotificationAccess = { access = true },
                    onReconnect = {},
                    onSetBackgroundConnectionEnabled = { background = it },
                    onOpenStatusNotificationSettings = {},
                    onOpenBatterySettings = {},
                    onReloadApplications = {},
                    onPostDebugNotification = null,
                )
            }
        }
        compose.onNodeWithText(text(R.string.applications)).performClick()
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText("com.example.calendar"))
        compose.onNodeWithText("com.example.calendar").assertIsDisplayed()
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.configure_app)))
        compose.onNodeWithText(text(R.string.configure_app)).performClick()
        compose.onNodeWithText(text(R.string.settings)).assertIsSelected()
        compose.onNodeWithText("com.example.calendar").assertIsDisplayed()
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.show_notification_content)))
        compose.onNodeWithText(text(R.string.show_notification_content)).performClick()
        compose.onNodeWithContentDescription(text(R.string.back)).performClick()
        compose.onNodeWithText(text(R.string.keep_editing)).performClick()
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.save)))
        compose.onNodeWithText(text(R.string.save)).performClick()
        compose.runOnIdle { assertEquals(false, sharing.settingsFor("com.example.calendar").showContent) }
        compose.onNodeWithContentDescription(text(R.string.back)).performClick()
        compose.onNodeWithContentDescription(text(R.string.back)).performClick()
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.permissions_and_runtime)))
        compose.onNodeWithText(text(R.string.permissions_and_runtime)).performClick()
        compose.runOnIdle { access = false }
        compose.onNode(hasScrollToIndexAction()).performScrollToNode(hasText(text(R.string.needs_attention)))
        compose.onNodeWithText(text(R.string.needs_attention)).assertIsDisplayed()
        compose.onAllNodesWithText(text(R.string.open_system_settings))[0].performClick()
        compose.runOnIdle { assertEquals(true, access) }
        compose.onNodeWithText(text(R.string.notification_access_title)).assertIsDisplayed()
    }
}
