package dev.notificationmirroring.android

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidProductPreferencesTest {
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
