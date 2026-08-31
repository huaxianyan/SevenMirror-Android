package dev.notificationmirroring.android

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
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
        private const val KEY_APPLICATION_SELECTION_CONFIRMED = "application-selection-confirmed"
        private const val KEY_SELECTED_PACKAGES = "selected-packages"

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
