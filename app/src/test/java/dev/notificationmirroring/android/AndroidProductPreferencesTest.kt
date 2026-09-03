package dev.notificationmirroring.android

import dev.notificationmirroring.notification.NotificationSnapshot
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
    fun `selected applications follow silent ongoing and content sharing settings`() {
        val notification = notificationSnapshot(packageName = "com.example.messages")
        val selected = setOf(notification.packageName)

        assertEquals(
            notification,
            prepareNotificationForMirroring(
                snapshot = notification,
                ownPackageName = "dev.notificationmirroring.android",
                debugFixtureEnabled = false,
                applicationSelectionConfirmed = true,
                selectedPackages = selected,
                sharingSettings = NotificationSharingSettings(),
            ),
        )
        assertEquals(
            null,
            prepareNotificationForMirroring(
                snapshot = notification.copy(isOngoing = true),
                ownPackageName = "dev.notificationmirroring.android",
                debugFixtureEnabled = false,
                applicationSelectionConfirmed = true,
                selectedPackages = selected,
                sharingSettings = NotificationSharingSettings(),
            ),
        )
        assertEquals(
            null,
            prepareNotificationForMirroring(
                snapshot = notification.copy(isSilent = true),
                ownPackageName = "dev.notificationmirroring.android",
                debugFixtureEnabled = false,
                applicationSelectionConfirmed = true,
                selectedPackages = selected,
                sharingSettings = NotificationSharingSettings(syncSilent = false),
            ),
        )
        val hidden = prepareNotificationForMirroring(
            snapshot = notification.copy(containsContentImage = true),
            ownPackageName = "dev.notificationmirroring.android",
            debugFixtureEnabled = false,
            applicationSelectionConfirmed = true,
            selectedPackages = selected,
            sharingSettings = NotificationSharingSettings(
                hiddenContentPackages = selected,
                ongoingNotificationPackages = selected,
            ),
        )
        assertEquals(null, hidden?.title)
        assertEquals(null, hidden?.text)
        assertEquals(false, hidden?.containsContentImage)
        assertEquals(0, hidden?.actions?.size)
    }

    @Test
    fun `background connection starts after selection and retains an explicit pause`() {
        assertEquals(false, backgroundConnectionEnabled(null, applicationSelectionConfirmed = false))
        assertEquals(true, backgroundConnectionEnabled(null, applicationSelectionConfirmed = true))
        assertEquals(false, backgroundConnectionEnabled(false, applicationSelectionConfirmed = true))
        assertEquals(true, backgroundConnectionEnabled(true, applicationSelectionConfirmed = true))
    }

    @Test
    fun `debug allowance is limited to the explicit fixture notification`() {
        val serviceNotification = notificationSnapshot(BuildConfig.APPLICATION_ID).copy(
            title = "SevenMirror notification sync",
            isOngoing = true,
        )
        val fixtureNotification = serviceNotification.copy(title = "Avatar test")

        assertEquals(false, ProductDebugActions.isFixtureNotification(serviceNotification))
        assertEquals(true, ProductDebugActions.isFixtureNotification(fixtureNotification))
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
    fun `only certified device removal offers re-enrollment`() {
        assertEquals(
            AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL,
            securityRecoveryForLocalMembership(false),
        )
        assertEquals(AndroidSecurityRecovery.NONE, securityRecoveryForLocalMembership(true))
        assertEquals(AndroidSecurityRecovery.NONE, securityRecoveryForLocalMembership(null))
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

    private fun notificationSnapshot(packageName: String): NotificationSnapshot = NotificationSnapshot(
        key = "notification-key",
        revision = 1,
        packageName = packageName,
        appName = "Messages",
        title = "Alex",
        text = "Meet at 6",
        expandedText = null,
        appIcon = null,
        avatar = null,
        containsContentImage = false,
        postedAtMillis = 1,
        isClearable = true,
        isOngoing = false,
        isSilent = false,
        groupKey = null,
        isGroupSummary = false,
        actions = emptyList(),
    )

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
