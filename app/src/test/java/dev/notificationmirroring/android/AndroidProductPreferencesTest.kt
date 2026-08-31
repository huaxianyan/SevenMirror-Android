package dev.notificationmirroring.android

import dev.notificationmirroring.notification.RemoteOperationType
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidProductPreferencesTest {
    @Test
    fun `application operation mode overrides global defaults`() {
        val settings = RemoteOperationSettings(
            globalDefaults = RemoteOperationPermissions(actions = true),
            applicationOverrides = mapOf(
                "com.example.allowed" to ApplicationOperationOverride(
                    ApplicationOperationMode.ALLOW_ALL,
                ),
                "com.example.blocked" to ApplicationOperationOverride(
                    ApplicationOperationMode.VIEW_ONLY,
                ),
                "com.example.custom" to ApplicationOperationOverride(
                    ApplicationOperationMode.CUSTOM,
                    RemoteOperationPermissions(replies = true),
                ),
            ),
        )

        assertEquals(true, settings.permissionsFor("com.example.default").allows(RemoteOperationType.ACTION))
        assertEquals(true, settings.permissionsFor("com.example.allowed").allows(RemoteOperationType.CLEAR))
        assertEquals(false, settings.permissionsFor("com.example.blocked").allows(RemoteOperationType.ACTION))
        assertEquals(true, settings.permissionsFor("com.example.custom").allows(RemoteOperationType.REPLY))
        assertEquals(false, settings.permissionsFor("com.example.custom").allows(RemoteOperationType.CLEAR))
    }

    @Test
    fun `search and category show only matching applications`() {
        val applications = listOf(
            SelectableApplication("com.example.calendar", "Calendar", false),
            SelectableApplication("com.example.camera", "Camera", true),
            SelectableApplication("org.example.notes", "Notes", false),
        )

        assertEquals(
            listOf("com.example.calendar"),
            filterApplications(applications, ApplicationFilter.ORDINARY, " CAL ")
                .map(SelectableApplication::packageName),
        )
        assertEquals(
            listOf("com.example.camera"),
            filterApplications(applications, ApplicationFilter.SYSTEM, "example.camera")
                .map(SelectableApplication::packageName),
        )
    }

    @Test
    fun `expanded windows use a navigation rail`() {
        assertEquals(NavigationLayout.COMPACT, navigationLayout(839f))
        assertEquals(NavigationLayout.EXPANDED, navigationLayout(840f))
    }

    @Test
    fun `welcome is always the first normal step`() {
        assertEquals(
            OnboardingStage.WELCOME,
            stage(
                welcomeCompleted = false,
                transportState = AndroidTransportState.NOT_CONFIGURED,
            ),
        )
    }

    @Test
    fun `saved setup is checked before showing an onboarding decision`() {
        assertEquals(
            OnboardingStage.LOADING,
            stage(transportState = AndroidTransportState.INITIALIZING),
        )
    }

    @Test
    fun `unconfigured device asks for server after welcome`() {
        assertEquals(OnboardingStage.SERVER, stage())
    }

    @Test
    fun `registration submission stays on the form until a durable request exists`() {
        assertEquals(
            OnboardingStage.SERVER,
            stage(transportState = AndroidTransportState.SUBMITTING_REGISTRATION),
        )
    }

    @Test
    fun `durable pending registration waits even when the network is offline`() {
        assertEquals(
            OnboardingStage.WAITING_FOR_APPROVAL,
            stage(
                transportState = AndroidTransportState.OFFLINE,
                enrollmentPending = true,
            ),
        )
    }

    @Test
    fun `permissions and explicit app selection are sequential`() {
        assertEquals(
            OnboardingStage.NOTIFICATION_ACCESS,
            stage(transportState = AndroidTransportState.ONLINE),
        )
        assertEquals(
            OnboardingStage.APPLICATIONS,
            stage(
                transportState = AndroidTransportState.ONLINE,
                notificationAccessGranted = true,
            ),
        )
        assertEquals(
            OnboardingStage.COMPLETE,
            stage(
                transportState = AndroidTransportState.ONLINE,
                notificationAccessGranted = true,
                applicationSelectionConfirmed = true,
            ),
        )
    }

    @Test
    fun `security error overrides normal onboarding`() {
        assertEquals(
            OnboardingStage.SECURITY_ERROR,
            stage(
                welcomeCompleted = false,
                transportState = AndroidTransportState.SECURITY_ERROR,
            ),
        )
    }

    private fun stage(
        welcomeCompleted: Boolean = true,
        transportState: AndroidTransportState = AndroidTransportState.NOT_CONFIGURED,
        enrollmentPending: Boolean = false,
        notificationAccessGranted: Boolean = false,
        applicationSelectionConfirmed: Boolean = false,
    ): OnboardingStage = onboardingStage(
        welcomeCompleted = welcomeCompleted,
        transportState = transportState,
        enrollmentPending = enrollmentPending,
        notificationAccessGranted = notificationAccessGranted,
        applicationSelectionConfirmed = applicationSelectionConfirmed,
    )
}
