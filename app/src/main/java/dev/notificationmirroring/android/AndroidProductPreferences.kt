package dev.notificationmirroring.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import dev.notificationmirroring.notification.NotificationSnapshot
import dev.notificationmirroring.notification.RemoteOperationType
import java.util.Locale

internal enum class NavigationLayout { COMPACT, EXPANDED }

internal fun navigationLayout(widthDp: Float): NavigationLayout {
    require(widthDp >= 0f) { "Window width must not be negative" }
    return if (widthDp >= 840f) NavigationLayout.EXPANDED else NavigationLayout.COMPACT
}

internal enum class OnboardingStage {
    WELCOME,
    LOADING,
    SERVER,
    WAITING_FOR_APPROVAL,
    NOTIFICATION_ACCESS,
    APPLICATIONS,
    COMPLETE,
    SECURITY_ERROR,
}

internal fun onboardingStage(
    welcomeCompleted: Boolean,
    transportState: AndroidTransportState,
    enrollmentPending: Boolean,
    notificationAccessGranted: Boolean,
    applicationSelectionConfirmed: Boolean,
): OnboardingStage {
    if (transportState == AndroidTransportState.SECURITY_ERROR) return OnboardingStage.SECURITY_ERROR
    if (!welcomeCompleted) return OnboardingStage.WELCOME
    if (transportState == AndroidTransportState.INITIALIZING) return OnboardingStage.LOADING
    if (enrollmentPending || transportState == AndroidTransportState.REGISTERING) {
        return OnboardingStage.WAITING_FOR_APPROVAL
    }
    if (transportState == AndroidTransportState.NOT_CONFIGURED ||
        transportState == AndroidTransportState.SUBMITTING_REGISTRATION
    ) return OnboardingStage.SERVER
    if (!notificationAccessGranted) return OnboardingStage.NOTIFICATION_ACCESS
    if (!applicationSelectionConfirmed) return OnboardingStage.APPLICATIONS
    return OnboardingStage.COMPLETE
}

internal data class SelectableApplication(
    val packageName: String,
    val label: String,
    val isSystemApplication: Boolean,
)

internal enum class ApplicationFilter { ORDINARY, SYSTEM }

internal data class RemoteOperationPermissions(
    val actions: Boolean = false,
    val replies: Boolean = false,
    val clearing: Boolean = false,
) {
    fun allows(operation: RemoteOperationType): Boolean = when (operation) {
        RemoteOperationType.ACTION -> actions
        RemoteOperationType.REPLY -> replies
        RemoteOperationType.CLEAR -> clearing
    }
}

internal enum class ApplicationOperationMode {
    GLOBAL_DEFAULTS,
    ALLOW_ALL,
    VIEW_ONLY,
    CUSTOM,
}

internal data class ApplicationOperationOverride(
    val mode: ApplicationOperationMode,
    val customPermissions: RemoteOperationPermissions = RemoteOperationPermissions(),
) {
    init {
        require(mode != ApplicationOperationMode.GLOBAL_DEFAULTS) {
            "Global defaults must be represented by an absent application override"
        }
    }
}

internal data class ApplicationNotificationSettings(
    val showContent: Boolean = true,
    val syncOngoing: Boolean = false,
)

internal data class NotificationSharingSettings(
    val syncSilent: Boolean = true,
    val hiddenContentPackages: Set<String> = emptySet(),
    val ongoingNotificationPackages: Set<String> = emptySet(),
) {
    fun settingsFor(packageName: String): ApplicationNotificationSettings =
        ApplicationNotificationSettings(
            showContent = packageName !in hiddenContentPackages,
            syncOngoing = packageName in ongoingNotificationPackages,
        )

    fun prepare(snapshot: NotificationSnapshot): NotificationSnapshot? {
        if (snapshot.isSilent && !syncSilent) return null
        if (snapshot.isOngoing && snapshot.packageName !in ongoingNotificationPackages) return null
        if (snapshot.packageName !in hiddenContentPackages) return snapshot
        return snapshot.copy(
            title = null,
            text = null,
            expandedText = null,
            avatar = null,
            containsContentImage = false,
            actions = emptyList(),
        )
    }
}

internal fun prepareNotificationForMirroring(
    snapshot: NotificationSnapshot,
    ownPackageName: String,
    debugFixtureEnabled: Boolean,
    applicationSelectionConfirmed: Boolean,
    selectedPackages: Set<String>,
    sharingSettings: NotificationSharingSettings,
): NotificationSnapshot? {
    if (debugFixtureEnabled && snapshot.packageName == ownPackageName) return snapshot
    if (!applicationSelectionConfirmed || snapshot.packageName !in selectedPackages) return null
    return sharingSettings.prepare(snapshot)
}

internal data class RemoteOperationSettings(
    val globalDefaults: RemoteOperationPermissions = RemoteOperationPermissions(),
    val applicationOverrides: Map<String, ApplicationOperationOverride> = emptyMap(),
) {
    fun permissionsFor(packageName: String): RemoteOperationPermissions =
        when (val override = applicationOverrides[packageName]) {
            null -> globalDefaults
            else -> when (override.mode) {
                ApplicationOperationMode.ALLOW_ALL -> RemoteOperationPermissions(true, true, true)
                ApplicationOperationMode.VIEW_ONLY -> RemoteOperationPermissions()
                ApplicationOperationMode.CUSTOM -> override.customPermissions
                ApplicationOperationMode.GLOBAL_DEFAULTS -> error("Invalid persisted application override")
            }
        }
}

internal fun filterApplications(
    applications: List<SelectableApplication>,
    filter: ApplicationFilter,
    query: String,
): List<SelectableApplication> {
    val normalizedQuery = query.trim().lowercase(Locale.ROOT)
    return applications.filter { application ->
        application.isSystemApplication == (filter == ApplicationFilter.SYSTEM) &&
            (normalizedQuery.isEmpty() ||
                application.label.lowercase(Locale.ROOT).contains(normalizedQuery) ||
                application.packageName.lowercase(Locale.ROOT).contains(normalizedQuery))
    }
}

internal class AndroidProductPreferences(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )

    fun isWelcomeCompleted(): Boolean = preferences.getBoolean(KEY_WELCOME_COMPLETED, false)

    fun isCertifiedReEnrollmentResetPending(): Boolean =
        preferences.getBoolean(KEY_CERTIFIED_RE_ENROLLMENT_RESET_PENDING, false)

    @SuppressLint("UseKtx")
    fun beginCertifiedReEnrollmentReset() {
        check(
            preferences.edit()
                .putBoolean(KEY_CERTIFIED_RE_ENROLLMENT_RESET_PENDING, true)
                .commit(),
        ) { "Unable to persist re-enrollment reset intent" }
    }

    @SuppressLint("UseKtx")
    fun finishCertifiedReEnrollmentReset() {
        check(
            preferences.edit()
                .remove(KEY_CERTIFIED_RE_ENROLLMENT_RESET_PENDING)
                .commit(),
        ) { "Unable to finish re-enrollment reset" }
    }

    @SuppressLint("UseKtx")
    fun completeWelcome() {
        check(preferences.edit().putBoolean(KEY_WELCOME_COMPLETED, true).commit()) {
            "Unable to persist welcome completion"
        }
    }

    fun isApplicationSelectionConfirmed(): Boolean =
        preferences.getBoolean(KEY_APPLICATION_SELECTION_CONFIRMED, false)

    fun selectedPackages(): Set<String> =
        preferences.getStringSet(KEY_SELECTED_PACKAGES, emptySet()).orEmpty().toSet()

    fun notificationSharingSettings(): NotificationSharingSettings = NotificationSharingSettings(
        syncSilent = preferences.getBoolean(KEY_SYNC_SILENT, true),
        hiddenContentPackages = preferences.getStringSet(KEY_HIDDEN_CONTENT_PACKAGES, emptySet())
            .orEmpty()
            .toSet(),
        ongoingNotificationPackages = preferences
            .getStringSet(KEY_ONGOING_NOTIFICATION_PACKAGES, emptySet())
            .orEmpty()
            .toSet(),
    )

    fun remoteOperationSettings(): RemoteOperationSettings {
        val globalDefaults = RemoteOperationPermissions(
            actions = preferences.getBoolean(KEY_GLOBAL_ACTIONS, false),
            replies = preferences.getBoolean(KEY_GLOBAL_REPLIES, false),
            clearing = preferences.getBoolean(KEY_GLOBAL_CLEARING, false),
        )
        val overrides = preferences.all.asSequence()
            .filter { (key, _) -> key.startsWith(KEY_OVERRIDE_MODE_PREFIX) }
            .mapNotNull { (key, value) ->
                val packageName = key.removePrefix(KEY_OVERRIDE_MODE_PREFIX)
                if (!isValidPackageName(packageName)) return@mapNotNull null
                val mode = runCatching {
                    ApplicationOperationMode.valueOf(value as? String ?: "")
                }.getOrDefault(ApplicationOperationMode.VIEW_ONLY)
                if (mode == ApplicationOperationMode.GLOBAL_DEFAULTS) return@mapNotNull null
                packageName to ApplicationOperationOverride(
                    mode = mode,
                    customPermissions = RemoteOperationPermissions(
                        actions = preferences.getBoolean(KEY_OVERRIDE_ACTIONS_PREFIX + packageName, false),
                        replies = preferences.getBoolean(KEY_OVERRIDE_REPLIES_PREFIX + packageName, false),
                        clearing = preferences.getBoolean(KEY_OVERRIDE_CLEARING_PREFIX + packageName, false),
                    ),
                )
            }
            .toMap()
        return RemoteOperationSettings(globalDefaults, overrides)
    }

    fun isRemoteOperationAllowed(packageName: String, operation: RemoteOperationType): Boolean =
        remoteOperationSettings().permissionsFor(packageName).allows(operation)

    @SuppressLint("UseKtx")
    fun saveSyncSilentNotifications(enabled: Boolean) {
        check(preferences.edit().putBoolean(KEY_SYNC_SILENT, enabled).commit()) {
            "Unable to persist silent notification preference"
        }
    }

    @SuppressLint("UseKtx")
    fun saveApplicationNotificationSettings(
        packageName: String,
        settings: ApplicationNotificationSettings,
    ) {
        require(isValidPackageName(packageName)) { "Invalid application package name" }
        val current = notificationSharingSettings()
        val hiddenContentPackages = current.hiddenContentPackages.toMutableSet()
        val ongoingNotificationPackages = current.ongoingNotificationPackages.toMutableSet()
        if (settings.showContent) hiddenContentPackages -= packageName
        else hiddenContentPackages += packageName
        if (settings.syncOngoing) ongoingNotificationPackages += packageName
        else ongoingNotificationPackages -= packageName
        check(
            preferences.edit()
                .putStringSet(KEY_HIDDEN_CONTENT_PACKAGES, hiddenContentPackages)
                .putStringSet(KEY_ONGOING_NOTIFICATION_PACKAGES, ongoingNotificationPackages)
                .commit(),
        ) { "Unable to persist application notification settings" }
    }

    @SuppressLint("UseKtx")
    fun saveGlobalRemoteOperationPermissions(permissions: RemoteOperationPermissions) {
        check(
            preferences.edit()
                .putBoolean(KEY_GLOBAL_ACTIONS, permissions.actions)
                .putBoolean(KEY_GLOBAL_REPLIES, permissions.replies)
                .putBoolean(KEY_GLOBAL_CLEARING, permissions.clearing)
                .commit(),
        ) { "Unable to persist global remote operation permissions" }
    }

    @SuppressLint("UseKtx")
    fun saveApplicationOperationOverride(
        packageName: String,
        override: ApplicationOperationOverride?,
    ) {
        require(isValidPackageName(packageName)) { "Invalid application package name" }
        val editor = preferences.edit()
        if (override == null) {
            editor.remove(KEY_OVERRIDE_MODE_PREFIX + packageName)
                .remove(KEY_OVERRIDE_ACTIONS_PREFIX + packageName)
                .remove(KEY_OVERRIDE_REPLIES_PREFIX + packageName)
                .remove(KEY_OVERRIDE_CLEARING_PREFIX + packageName)
        } else {
            editor.putString(KEY_OVERRIDE_MODE_PREFIX + packageName, override.mode.name)
                .putBoolean(KEY_OVERRIDE_ACTIONS_PREFIX + packageName, override.customPermissions.actions)
                .putBoolean(KEY_OVERRIDE_REPLIES_PREFIX + packageName, override.customPermissions.replies)
                .putBoolean(KEY_OVERRIDE_CLEARING_PREFIX + packageName, override.customPermissions.clearing)
        }
        check(editor.commit()) { "Unable to persist application remote operation override" }
    }

    @SuppressLint("UseKtx")
    fun saveApplicationSelection(packageNames: Set<String>) {
        require(packageNames.all(::isValidPackageName)) { "Invalid selected application package name" }
        check(
            preferences.edit()
                .putStringSet(KEY_SELECTED_PACKAGES, packageNames.toSet())
                .putBoolean(KEY_APPLICATION_SELECTION_CONFIRMED, true)
                .commit(),
        ) { "Unable to persist application selection" }
    }

    companion object {
        private const val PREFERENCES_NAME = "syncnotifications.product-preferences.v1"
        private const val KEY_WELCOME_COMPLETED = "welcome-completed"
        private const val KEY_CERTIFIED_RE_ENROLLMENT_RESET_PENDING =
            "certified-re-enrollment-reset-pending"
        private const val KEY_APPLICATION_SELECTION_CONFIRMED = "application-selection-confirmed"
        private const val KEY_SELECTED_PACKAGES = "selected-packages"
        private const val KEY_SYNC_SILENT = "notification-sharing.sync-silent"
        private const val KEY_HIDDEN_CONTENT_PACKAGES = "notification-sharing.hidden-content-packages"
        private const val KEY_ONGOING_NOTIFICATION_PACKAGES =
            "notification-sharing.ongoing-notification-packages"
        private const val KEY_GLOBAL_ACTIONS = "remote-operations.global.actions"
        private const val KEY_GLOBAL_REPLIES = "remote-operations.global.replies"
        private const val KEY_GLOBAL_CLEARING = "remote-operations.global.clearing"
        private const val KEY_OVERRIDE_MODE_PREFIX = "remote-operations.application.mode."
        private const val KEY_OVERRIDE_ACTIONS_PREFIX = "remote-operations.application.actions."
        private const val KEY_OVERRIDE_REPLIES_PREFIX = "remote-operations.application.replies."
        private const val KEY_OVERRIDE_CLEARING_PREFIX = "remote-operations.application.clearing."

        private fun isValidPackageName(value: String): Boolean =
            value.length in 1..255 && value.matches(Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+"))
    }
}

internal object InstalledApplicationCatalog {
    fun load(context: Context): List<SelectableApplication> {
        val packageManager = context.packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val launcherActivities = packageManager.queryIntentActivities(
            launcherIntent,
            PackageManager.MATCH_ALL,
        )
        return launcherActivities.asSequence()
            .map { it.activityInfo.applicationInfo }
            .filter { it.packageName != context.packageName }
            .distinctBy(ApplicationInfo::packageName)
            .map { applicationInfo ->
                SelectableApplication(
                    packageName = applicationInfo.packageName,
                    label = packageManager.getApplicationLabel(applicationInfo).toString()
                        .ifBlank { applicationInfo.packageName },
                    isSystemApplication =
                    applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .sortedWith(
                compareBy<SelectableApplication> { it.isSystemApplication }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.label },
            )
            .toList()
    }
}
