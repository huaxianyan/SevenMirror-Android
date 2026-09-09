package dev.notificationmirroring.android

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import dev.notificationmirroring.notification.LocalNotificationController
import java.util.concurrent.Executors

private const val PRODUCT_UI_STATE_KEY = "sevenmirror-product-ui-version"
private const val PRODUCT_UI_STATE_VERSION = 1

class MainActivity : ComponentActivity() {
    private lateinit var productPreferences: AndroidProductPreferences
    private val applicationLoader = Executors.newSingleThreadExecutor { task ->
        Thread(task, "installed-application-loader").apply { isDaemon = true }
    }

    private var notificationAccessGranted by mutableStateOf(false)
    private var foregroundNotificationGranted by mutableStateOf(false)
    private var backgroundConnectionEnabled by mutableStateOf(false)
    private var batteryOptimizationExempt by mutableStateOf(false)
    private var pendingDebugNotification = false
    private var welcomeCompleted by mutableStateOf(false)
    private var applicationSelectionConfirmed by mutableStateOf(false)
    private var selectedPackages by mutableStateOf<Set<String>>(emptySet())
    private var installedApplications by mutableStateOf<List<SelectableApplication>>(emptyList())
    private var applicationsLoaded by mutableStateOf(false)
    private var applicationsLoadFailed by mutableStateOf(false)
    private var notificationSharingSettings by mutableStateOf(NotificationSharingSettings())
    private var remoteOperationSettings by mutableStateOf(RemoteOperationSettings())

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        foregroundNotificationGranted = canShowForegroundStatus(this)
        BackgroundConnectionService.reconcile(this, foregroundNotificationGranted)
        if (granted && pendingDebugNotification && ProductDebugActions.available) {
            ProductDebugActions.postNotification(this)
        }
        pendingDebugNotification = false
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Old builds saved the removed MainDestination enum. Drop only that UI snapshot,
        // not persisted enrollment, keys or user settings, when adopting this navigation.
        super.onCreate(savedInstanceState?.takeIf { it.getInt(PRODUCT_UI_STATE_KEY) == PRODUCT_UI_STATE_VERSION })
        enableEdgeToEdge()
        productPreferences = AndroidProductPreferences(this)
        welcomeCompleted = productPreferences.isWelcomeCompleted()
        applicationSelectionConfirmed = productPreferences.isApplicationSelectionConfirmed()
        selectedPackages = productPreferences.selectedPackages()
        notificationSharingSettings = productPreferences.notificationSharingSettings()
        remoteOperationSettings = productPreferences.remoteOperationSettings()
        backgroundConnectionEnabled = productPreferences.isBackgroundConnectionEnabled()
        refreshSystemStatus()
        loadApplications()
        reconcileBackgroundConnection()

        setContent {
            SevenMirrorTheme {
                SevenMirrorApp(
                    transportCoordinator =
                    (application as NotificationMirroringApplication).transportCoordinator,
                    welcomeCompleted = welcomeCompleted,
                    notificationAccessGranted = notificationAccessGranted,
                    applicationSelectionConfirmed = applicationSelectionConfirmed,
                    applications = installedApplications,
                    applicationsLoaded = applicationsLoaded,
                    applicationsLoadFailed = applicationsLoadFailed,
                    onReloadApplications = ::loadApplications,
                    selectedPackages = selectedPackages,
                    notificationSharingSettings = notificationSharingSettings,
                    remoteOperationSettings = remoteOperationSettings,
                    backgroundConnectionEnabled = backgroundConnectionEnabled,
                    foregroundNotificationGranted = foregroundNotificationGranted,
                    batteryOptimizationExempt = batteryOptimizationExempt,
                    onCompleteWelcome = {
                        productPreferences.completeWelcome()
                        welcomeCompleted = true
                    },
                    onOpenNotificationAccess = {
                        startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    },
                    onRefreshNotificationAccess = ::refreshSystemStatus,
                    onSaveApplicationSelection = { packages ->
                        productPreferences.saveApplicationSelection(packages)
                        LocalNotificationController.refreshMirroringPolicy(this)
                        selectedPackages = packages.toSet()
                        applicationSelectionConfirmed = true
                        backgroundConnectionEnabled = productPreferences.isBackgroundConnectionEnabled()
                        requestForegroundNotificationAndReconcile()
                    },
                    onSaveSyncSilentNotifications = { enabled ->
                        productPreferences.saveSyncSilentNotifications(enabled)
                        notificationSharingSettings = productPreferences.notificationSharingSettings()
                        LocalNotificationController.refreshMirroringPolicy(this)
                    },
                    onSaveApplicationSettings = { packageName, settings, override ->
                        productPreferences.saveApplicationSettings(packageName, settings, override)
                        notificationSharingSettings = productPreferences.notificationSharingSettings()
                        remoteOperationSettings = productPreferences.remoteOperationSettings()
                        LocalNotificationController.refreshMirroringPolicy(this)
                    },
                    onSaveGlobalRemoteOperations = { permissions ->
                        productPreferences.saveGlobalRemoteOperationPermissions(permissions)
                        remoteOperationSettings = productPreferences.remoteOperationSettings()
                    },

                    onSetBackgroundConnectionEnabled = { enabled ->
                        productPreferences.saveBackgroundConnectionEnabled(enabled)
                        backgroundConnectionEnabled = enabled
                        if (enabled) requestForegroundNotificationAndReconcile()
                        else BackgroundConnectionService.reconcile(this, foregroundNotificationGranted)
                    },
                    onOpenStatusNotificationSettings = {
                        startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
                    },
                    onOpenBatterySettings = {
                        startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    },
                    onPostDebugNotification =
                    if (ProductDebugActions.available) ::postDebugNotification else null,
                )
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(PRODUCT_UI_STATE_KEY, PRODUCT_UI_STATE_VERSION)
    }

    override fun onStart() {
        super.onStart()
        (application as NotificationMirroringApplication).transportCoordinator.acquireConnection(this)
    }

    override fun onStop() {
        (application as NotificationMirroringApplication).transportCoordinator.releaseConnection(this)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        if (::productPreferences.isInitialized) {
            backgroundConnectionEnabled = productPreferences.isBackgroundConnectionEnabled()
            refreshSystemStatus()
            reconcileBackgroundConnection()
        }
    }

    override fun onDestroy() {
        applicationLoader.shutdownNow()
        super.onDestroy()
    }

    private fun refreshSystemStatus() {
        notificationAccessGranted =
            NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)
        foregroundNotificationGranted = canShowForegroundStatus(this)
        batteryOptimizationExempt =
            getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)
    }

    private fun reconcileBackgroundConnection() {
        BackgroundConnectionService.reconcile(this, foregroundNotificationGranted)
    }

    private fun requestForegroundNotificationAndReconcile() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !canShowForegroundStatus(this)) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            foregroundNotificationGranted = canShowForegroundStatus(this)
            BackgroundConnectionService.reconcile(this, foregroundNotificationGranted)
        }
    }

    private fun loadApplications() {
        applicationsLoaded = false
        applicationsLoadFailed = false
        applicationLoader.execute {
            val loaded = runCatching { InstalledApplicationCatalog.load(this) }
            runOnUiThread {
                if (!isDestroyed) {
                    installedApplications = loaded.getOrDefault(emptyList())
                    applicationsLoadFailed = loaded.isFailure
                    applicationsLoaded = true
                }
            }
        }
    }

    private fun postDebugNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !canShowForegroundStatus(this)) {
            pendingDebugNotification = true
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            ProductDebugActions.postNotification(this)
        }
    }
}

@Composable
private fun SevenMirrorTheme(content: @Composable () -> Unit) {
    val context = LocalContext.current
    val darkTheme = isSystemInDarkTheme()
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && darkTheme -> dynamicDarkColorScheme(context)
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> dynamicLightColorScheme(context)
        darkTheme -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

@Composable
private fun SevenMirrorApp(
    transportCoordinator: AndroidTransportCoordinator,
    welcomeCompleted: Boolean,
    notificationAccessGranted: Boolean,
    applicationSelectionConfirmed: Boolean,
    applications: List<SelectableApplication>,
    applicationsLoaded: Boolean,
    applicationsLoadFailed: Boolean,
    onReloadApplications: () -> Unit,
    selectedPackages: Set<String>,
    notificationSharingSettings: NotificationSharingSettings,
    remoteOperationSettings: RemoteOperationSettings,
    backgroundConnectionEnabled: Boolean,
    foregroundNotificationGranted: Boolean,
    batteryOptimizationExempt: Boolean,
    onCompleteWelcome: () -> Unit,
    onOpenNotificationAccess: () -> Unit,
    onRefreshNotificationAccess: () -> Unit,
    onSaveApplicationSelection: (Set<String>) -> Unit,
    onSaveSyncSilentNotifications: (Boolean) -> Unit,
    onSaveApplicationSettings: (String, ApplicationNotificationSettings, ApplicationOperationOverride?) -> Unit,
    onSaveGlobalRemoteOperations: (RemoteOperationPermissions) -> Unit,
    onSetBackgroundConnectionEnabled: (Boolean) -> Unit,
    onOpenStatusNotificationSettings: () -> Unit,
    onOpenBatterySettings: () -> Unit,
    onPostDebugNotification: (() -> Unit)?,
) {
    val transportState by transportCoordinator.state.collectAsState()
    val enrollmentPending by transportCoordinator.enrollmentPending.collectAsState()
    val workspaceDevices by transportCoordinator.workspaceDevices.collectAsState()
    val serverOrigin by transportCoordinator.serverOrigin.collectAsState()
    val securityRecovery by transportCoordinator.securityRecovery.collectAsState()
    val omittedNotificationCount by LocalNotificationController.omittedNotificationCount.collectAsState()
    val stage = onboardingStage(
        welcomeCompleted = welcomeCompleted,
        transportState = transportState,
        enrollmentPending = enrollmentPending,
        notificationAccessGranted = notificationAccessGranted,
        applicationSelectionConfirmed = applicationSelectionConfirmed,
    )

    Surface(modifier = Modifier.fillMaxSize()) {
        when (stage) {
            OnboardingStage.WELCOME -> WelcomeScreen(onContinue = onCompleteWelcome)
            OnboardingStage.LOADING -> LoadingScreen()
            OnboardingStage.SERVER -> ServerSetupScreen(transportCoordinator)
            OnboardingStage.WAITING_FOR_APPROVAL -> ApprovalScreen(
                onRetry = transportCoordinator::retryConnection,
            )
            OnboardingStage.NOTIFICATION_ACCESS -> NotificationAccessScreen(
                onOpenSettings = onOpenNotificationAccess,
                onCheckAgain = onRefreshNotificationAccess,
            )
            OnboardingStage.APPLICATIONS -> ApplicationSelectionScreen(
                applications = applications,
                applicationsLoaded = applicationsLoaded,
                applicationsLoadFailed = applicationsLoadFailed,
                initialSelection = selectedPackages,
                onboarding = true,
                onSave = {
                    try { onSaveApplicationSelection(it); true } catch (_: RuntimeException) { false }
                },
                onReload = onReloadApplications,
                onConfigure = null,
                onDirtyChange = null,
            )
            OnboardingStage.COMPLETE -> MainScreen(
                transportState = transportState,
                workspaceDevices = workspaceDevices,
                serverOrigin = serverOrigin,
                notificationAccessGranted = notificationAccessGranted,
                applications = applications,
                applicationsLoaded = applicationsLoaded,
                applicationsLoadFailed = applicationsLoadFailed,
                onReloadApplications = onReloadApplications,
                selectedPackages = selectedPackages,
                notificationSharingSettings = notificationSharingSettings,
                remoteOperationSettings = remoteOperationSettings,
                backgroundConnectionEnabled = backgroundConnectionEnabled,
                foregroundNotificationGranted = foregroundNotificationGranted,
                batteryOptimizationExempt = batteryOptimizationExempt,
                omittedNotificationCount = omittedNotificationCount,
                onSaveApplicationSelection = onSaveApplicationSelection,
                onSaveSyncSilentNotifications = onSaveSyncSilentNotifications,
                onSaveApplicationSettings = onSaveApplicationSettings,
                onSaveGlobalRemoteOperations = onSaveGlobalRemoteOperations,
                onOpenNotificationAccess = onOpenNotificationAccess,
                onReconnect = transportCoordinator::retryConnection,
                onSetBackgroundConnectionEnabled = onSetBackgroundConnectionEnabled,
                onOpenStatusNotificationSettings = onOpenStatusNotificationSettings,
                onOpenBatterySettings = onOpenBatterySettings,
                onPostDebugNotification = onPostDebugNotification,
            )
            OnboardingStage.SECURITY_ERROR -> SecurityErrorScreen(
                recovery = securityRecovery,
                onReEnroll = transportCoordinator::reEnrollAfterCertifiedRemoval,
            )
        }
    }
}

@Composable
private fun Page(content: @Composable (Modifier) -> Unit) {
    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val horizontalPadding = if (maxWidth >= 600.dp) 32.dp else 20.dp
        Box(
            modifier = Modifier.fillMaxSize().padding(horizontal = horizontalPadding),
            contentAlignment = Alignment.Center,
        ) {
            content(Modifier.fillMaxWidth().widthIn(max = 720.dp))
        }
    }
}

@Composable
private fun LoadingScreen() {
    Page { modifier ->
        Column(
            modifier = modifier,
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator()
            Text(stringResource(R.string.loading_saved_setup))
        }
    }
}

@Composable
private fun WelcomeScreen(onContinue: () -> Unit) {
    Page { modifier ->
        Column(
            modifier = modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Text(
                stringResource(R.string.welcome_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineLarge,
            )
            Text(stringResource(R.string.welcome_body), style = MaterialTheme.typography.bodyLarge)
            Card {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(stringResource(R.string.e2ee_title), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(R.string.e2ee_body))
                }
            }
            Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.continue_action))
            }
        }
    }
}

@Composable
private fun ServerSetupScreen(transportCoordinator: AndroidTransportCoordinator) {
    var serverOrigin by rememberSaveable { mutableStateOf("") }
    var pairingCode by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf(Build.MODEL.take(100)) }
    var message by remember { mutableStateOf<Int?>(null) }
    val transportState by transportCoordinator.state.collectAsState()

    Page { modifier ->
        LazyColumn(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            item {
                Text(
                    stringResource(R.string.connect_server_title),
                    modifier = Modifier.semantics { heading() },
                    style = MaterialTheme.typography.headlineMedium,
                )
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.connect_server_body))
            }
            item {
                OutlinedTextField(
                    value = serverOrigin,
                    onValueChange = { serverOrigin = it.trim().take(2048) },
                    label = { Text(stringResource(R.string.server_origin)) },
                    placeholder = { Text(stringResource(R.string.server_origin_placeholder)) },
                    supportingText = { Text(stringResource(R.string.server_origin_help)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                OutlinedTextField(
                    value = pairingCode,
                    onValueChange = { pairingCode = it.filterNot(Char::isWhitespace).take(32) },
                    label = { Text(stringResource(R.string.one_time_pairing_code)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = { deviceName = it.take(100) },
                    label = { Text(stringResource(R.string.device_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            item {
                Button(
                    onClick = {
                        val oneTimeCode = pairingCode
                        pairingCode = ""
                        message = R.string.registration_started
                        transportCoordinator.register(
                            serverOrigin = serverOrigin,
                            pairingCode = oneTimeCode,
                            deviceName = deviceName.trim(),
                        ) { succeeded ->
                            message = if (succeeded) {
                                R.string.registration_succeeded
                            } else {
                                R.string.registration_failed
                            }
                        }
                    },
                    enabled = serverOrigin.isNotBlank() && pairingCode.length == 32 &&
                        deviceName.isNotBlank() &&
                        transportState != AndroidTransportState.SUBMITTING_REGISTRATION,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.submit_join_request))
                }
            }
            message?.let { resource ->
                item {
                    Text(
                        stringResource(resource),
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    )
                }
            }
        }
    }
}

@Composable
private fun ApprovalScreen(onRetry: () -> Unit) {
    Page { modifier ->
        Column(
            modifier = modifier.verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            CircularProgressIndicator()
            Text(
                stringResource(R.string.waiting_approval_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.waiting_approval_body))
            OutlinedButton(onClick = onRetry) { Text(stringResource(R.string.check_status)) }
        }
    }
}

@Composable
private fun NotificationAccessScreen(
    onOpenSettings: () -> Unit,
    onCheckAgain: () -> Unit,
) {
    Page { modifier ->
        Column(
            modifier = modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            Text(
                stringResource(R.string.notification_access_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.notification_access_body))
            Card {
                Text(
                    text = stringResource(R.string.notification_access_privacy),
                    modifier = Modifier.padding(20.dp),
                )
            }
            Button(onClick = onOpenSettings, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.open_notification_access))
            }
            OutlinedButton(onClick = onCheckAgain, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.permission_granted_check_again))
            }
        }
    }
}

@Composable
private fun SecurityErrorScreen(
    recovery: AndroidSecurityRecovery,
    onReEnroll: () -> Unit,
) {
    var showReEnrollmentConfirmation by rememberSaveable { mutableStateOf(false) }
    val certifiedRemoval = recovery == AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL

    Page { modifier ->
        Column(
            modifier = modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(
                    if (certifiedRemoval) R.string.device_removed_title
                    else R.string.security_error_title,
                ),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(
                stringResource(
                    if (certifiedRemoval) R.string.device_removed_body
                    else R.string.stored_state_security_error,
                ),
            )
            if (certifiedRemoval) {
                Button(onClick = { showReEnrollmentConfirmation = true }) {
                    Text(stringResource(R.string.re_enroll_device))
                }
            } else {
                Card {
                    Text(stringResource(R.string.security_error_recovery), Modifier.padding(20.dp))
                }
            }
        }
    }

    if (showReEnrollmentConfirmation) {
        AlertDialog(
            onDismissRequest = { showReEnrollmentConfirmation = false },
            title = { Text(stringResource(R.string.re_enroll_confirmation_title)) },
            text = { Text(stringResource(R.string.re_enroll_confirmation_body)) },
            confirmButton = {
                Button(
                    onClick = {
                        showReEnrollmentConfirmation = false
                        onReEnroll()
                    },
                ) {
                    Text(stringResource(R.string.re_enroll_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showReEnrollmentConfirmation = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }
}
