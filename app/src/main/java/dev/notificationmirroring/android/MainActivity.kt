package dev.notificationmirroring.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import dev.notificationmirroring.crypto.WorkspaceDeviceSummary
import dev.notificationmirroring.crypto.WorkspaceDeviceType
import java.util.concurrent.Executors

class MainActivity : ComponentActivity() {
    private lateinit var productPreferences: AndroidProductPreferences
    private val applicationLoader = Executors.newSingleThreadExecutor { task ->
        Thread(task, "installed-application-loader").apply { isDaemon = true }
    }

    private var notificationAccessGranted by mutableStateOf(false)
    private var welcomeCompleted by mutableStateOf(false)
    private var applicationSelectionConfirmed by mutableStateOf(false)
    private var selectedPackages by mutableStateOf<Set<String>>(emptySet())
    private var installedApplications by mutableStateOf<List<SelectableApplication>>(emptyList())
    private var applicationsLoaded by mutableStateOf(false)
    private var remoteOperationSettings by mutableStateOf(RemoteOperationSettings())

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted && ProductDebugActions.available) {
            ProductDebugActions.postNotification(this)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        productPreferences = AndroidProductPreferences(this)
        welcomeCompleted = productPreferences.isWelcomeCompleted()
        applicationSelectionConfirmed = productPreferences.isApplicationSelectionConfirmed()
        selectedPackages = productPreferences.selectedPackages()
        remoteOperationSettings = productPreferences.remoteOperationSettings()
        refreshNotificationAccess()
        loadApplications()

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
                    selectedPackages = selectedPackages,
                    remoteOperationSettings = remoteOperationSettings,
                    onCompleteWelcome = {
                        productPreferences.completeWelcome()
                        welcomeCompleted = true
                    },
                    onOpenNotificationAccess = {
                        startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    },
                    onRefreshNotificationAccess = ::refreshNotificationAccess,
                    onSaveApplicationSelection = { packages ->
                        productPreferences.saveApplicationSelection(packages)
                        selectedPackages = packages.toSet()
                        applicationSelectionConfirmed = true
                    },
                    onSaveGlobalRemoteOperations = { permissions ->
                        productPreferences.saveGlobalRemoteOperationPermissions(permissions)
                        remoteOperationSettings = productPreferences.remoteOperationSettings()
                    },
                    onSaveApplicationOperationOverride = { packageName, override ->
                        productPreferences.saveApplicationOperationOverride(packageName, override)
                        remoteOperationSettings = productPreferences.remoteOperationSettings()
                    },
                    onPostDebugNotification =
                    if (ProductDebugActions.available) ::postDebugNotification else null,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::productPreferences.isInitialized) refreshNotificationAccess()
    }

    override fun onDestroy() {
        applicationLoader.shutdownNow()
        super.onDestroy()
    }

    private fun refreshNotificationAccess() {
        notificationAccessGranted =
            NotificationManagerCompat.getEnabledListenerPackages(this).contains(packageName)
    }

    private fun loadApplications() {
        applicationLoader.execute {
            val loaded = runCatching { InstalledApplicationCatalog.load(this) }.getOrDefault(emptyList())
            runOnUiThread {
                installedApplications = loaded
                applicationsLoaded = true
            }
        }
    }

    private fun postDebugNotification() {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
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
    selectedPackages: Set<String>,
    remoteOperationSettings: RemoteOperationSettings,
    onCompleteWelcome: () -> Unit,
    onOpenNotificationAccess: () -> Unit,
    onRefreshNotificationAccess: () -> Unit,
    onSaveApplicationSelection: (Set<String>) -> Unit,
    onSaveGlobalRemoteOperations: (RemoteOperationPermissions) -> Unit,
    onSaveApplicationOperationOverride: (String, ApplicationOperationOverride?) -> Unit,
    onPostDebugNotification: (() -> Unit)?,
) {
    val transportState by transportCoordinator.state.collectAsState()
    val enrollmentPending by transportCoordinator.enrollmentPending.collectAsState()
    val workspaceDevices by transportCoordinator.workspaceDevices.collectAsState()
    val serverOrigin by transportCoordinator.serverOrigin.collectAsState()
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
                onRetry = transportCoordinator::connect,
            )
            OnboardingStage.NOTIFICATION_ACCESS -> NotificationAccessScreen(
                onOpenSettings = onOpenNotificationAccess,
                onCheckAgain = onRefreshNotificationAccess,
            )
            OnboardingStage.APPLICATIONS -> ApplicationSelectionScreen(
                applications = applications,
                applicationsLoaded = applicationsLoaded,
                initialSelection = selectedPackages,
                onboarding = true,
                remoteOperationSettings = remoteOperationSettings,
                onSave = onSaveApplicationSelection,
                onSaveGlobalRemoteOperations = onSaveGlobalRemoteOperations,
                onSaveApplicationOperationOverride = onSaveApplicationOperationOverride,
            )
            OnboardingStage.COMPLETE -> MainScreen(
                transportState = transportState,
                workspaceDevices = workspaceDevices,
                serverOrigin = serverOrigin,
                notificationAccessGranted = notificationAccessGranted,
                applications = applications,
                applicationsLoaded = applicationsLoaded,
                selectedPackages = selectedPackages,
                remoteOperationSettings = remoteOperationSettings,
                onSaveApplicationSelection = onSaveApplicationSelection,
                onSaveGlobalRemoteOperations = onSaveGlobalRemoteOperations,
                onSaveApplicationOperationOverride = onSaveApplicationOperationOverride,
                onOpenNotificationAccess = onOpenNotificationAccess,
                onReconnect = transportCoordinator::connect,
                onPostDebugNotification = onPostDebugNotification,
            )
            OnboardingStage.SECURITY_ERROR -> SecurityErrorScreen()
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
private fun ApplicationSelectionScreen(
    applications: List<SelectableApplication>,
    applicationsLoaded: Boolean,
    initialSelection: Set<String>,
    onboarding: Boolean,
    remoteOperationSettings: RemoteOperationSettings,
    onSave: (Set<String>) -> Unit,
    onSaveGlobalRemoteOperations: (RemoteOperationPermissions) -> Unit,
    onSaveApplicationOperationOverride: (String, ApplicationOperationOverride?) -> Unit,
) {
    var selection by remember(initialSelection) { mutableStateOf(initialSelection.toSet()) }
    var query by rememberSaveable { mutableStateOf("") }
    var configuringPackage by rememberSaveable { mutableStateOf<String?>(null) }
    var filter by rememberSaveable { mutableStateOf(ApplicationFilter.ORDINARY) }
    val visibleApplications = remember(applications, filter, query) {
        filterApplications(applications, filter, query)
    }
    val visiblePackages = remember(visibleApplications) {
        visibleApplications.mapTo(mutableSetOf(), SelectableApplication::packageName)
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { Spacer(Modifier.height(20.dp)) }
        item {
            Text(
                stringResource(if (onboarding) R.string.choose_apps_title else R.string.apps_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.choose_apps_body))
            Spacer(Modifier.height(8.dp))
            Text(
                pluralStringResource(R.plurals.selected_apps_count, selection.size, selection.size),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (!onboarding) {
            item {
                GlobalRemoteOperationsCard(
                    permissions = remoteOperationSettings.globalDefaults,
                    onSave = onSaveGlobalRemoteOperations,
                )
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.search_apps)) },
                singleLine = true,
            )
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                FilterChip(
                    selected = filter == ApplicationFilter.ORDINARY,
                    onClick = { filter = ApplicationFilter.ORDINARY },
                    label = { Text(stringResource(R.string.ordinary_apps)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                FilterChip(
                    selected = filter == ApplicationFilter.SYSTEM,
                    onClick = { filter = ApplicationFilter.SYSTEM },
                    label = { Text(stringResource(R.string.system_apps)) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                OutlinedButton(
                    onClick = { selection = selection + visiblePackages },
                    enabled = visiblePackages.any { it !in selection },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.select_shown_apps))
                }
                OutlinedButton(
                    onClick = { selection = emptySet() },
                    enabled = selection.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.clear_selection))
                }
            }
        }
        if (!applicationsLoaded) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(24.dp),
                    horizontalArrangement = Arrangement.Center,
                ) { CircularProgressIndicator() }
            }
        } else if (applications.isEmpty()) {
            item { Text(stringResource(R.string.no_selectable_apps)) }
        } else if (visibleApplications.isEmpty()) {
            item { Text(stringResource(R.string.no_apps_match_filters)) }
        } else {
            items(visibleApplications, key = SelectableApplication::packageName) { app ->
                val selected = app.packageName in selection
                Column {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .semantics(mergeDescendants = true) {}
                            .toggleable(
                                value = selected,
                                role = Role.Checkbox,
                                onValueChange = { selection = selection.toggled(app.packageName) },
                            )
                            .heightIn(min = 48.dp)
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = selected,
                            onCheckedChange = null,
                        )
                        Column(modifier = Modifier.padding(start = 8.dp).weight(1f)) {
                            Text(app.label, style = MaterialTheme.typography.bodyLarge)
                            if (app.isSystemApplication) {
                                Text(
                                    stringResource(R.string.system_application),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }
                    if (!onboarding && selected) {
                        TextButton(onClick = { configuringPackage = app.packageName }) {
                            Text(
                                applicationOperationModeLabel(
                                    remoteOperationSettings.applicationOverrides[app.packageName]?.mode,
                                ),
                            )
                        }
                    }
                }
            }
        }
        item {
            Text(stringResource(R.string.alpha_app_selection_notice), style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { onSave(selection) },
                enabled = applicationsLoaded,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.save_app_selection, selection.size))
            }
            Spacer(Modifier.height(24.dp))
        }
    }

    configuringPackage?.let { packageName ->
        applications.firstOrNull { it.packageName == packageName }?.let { application ->
            ApplicationOperationDialog(
                applicationName = application.label,
                globalDefaults = remoteOperationSettings.globalDefaults,
                currentOverride = remoteOperationSettings.applicationOverrides[packageName],
                onDismiss = { configuringPackage = null },
                onSave = { override ->
                    onSaveApplicationOperationOverride(packageName, override)
                    configuringPackage = null
                },
            )
        }
    }
}

@Composable
private fun GlobalRemoteOperationsCard(
    permissions: RemoteOperationPermissions,
    onSave: (RemoteOperationPermissions) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(R.string.remote_operations), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.remote_operations_body), style = MaterialTheme.typography.bodySmall)
            PermissionSwitchRow(
                label = stringResource(R.string.allow_actions),
                checked = permissions.actions,
                onCheckedChange = { onSave(permissions.copy(actions = it)) },
            )
            PermissionSwitchRow(
                label = stringResource(R.string.allow_replies),
                checked = permissions.replies,
                onCheckedChange = { onSave(permissions.copy(replies = it)) },
            )
            PermissionSwitchRow(
                label = stringResource(R.string.allow_clearing),
                checked = permissions.clearing,
                onCheckedChange = { onSave(permissions.copy(clearing = it)) },
            )
        }
    }
}

@Composable
private fun PermissionSwitchRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .heightIn(min = 48.dp)
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = onCheckedChange,
            ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = null)
    }
}

@Composable
private fun applicationOperationModeLabel(mode: ApplicationOperationMode?): String =
    stringResource(
        when (mode) {
            null, ApplicationOperationMode.GLOBAL_DEFAULTS -> R.string.use_global_defaults
            ApplicationOperationMode.ALLOW_ALL -> R.string.allow_all_operations
            ApplicationOperationMode.VIEW_ONLY -> R.string.view_only
            ApplicationOperationMode.CUSTOM -> R.string.custom_permissions
        },
    )

@Composable
private fun ApplicationOperationDialog(
    applicationName: String,
    globalDefaults: RemoteOperationPermissions,
    currentOverride: ApplicationOperationOverride?,
    onDismiss: () -> Unit,
    onSave: (ApplicationOperationOverride?) -> Unit,
) {
    var mode by remember(currentOverride) {
        mutableStateOf(currentOverride?.mode ?: ApplicationOperationMode.GLOBAL_DEFAULTS)
    }
    var customPermissions by remember(currentOverride, globalDefaults) {
        mutableStateOf(
            currentOverride?.customPermissions
                ?.takeIf { currentOverride.mode == ApplicationOperationMode.CUSTOM }
                ?: globalDefaults,
        )
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.app_operation_permissions, applicationName)) },
        text = {
            LazyColumn(modifier = Modifier.heightIn(max = 480.dp)) {
                ApplicationOperationMode.entries.forEach { option ->
                    item(option.name) {
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { mode = option }
                                .padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = mode == option,
                                onClick = { mode = option },
                            )
                            Text(applicationOperationModeLabel(option))
                        }
                    }
                }
                if (mode == ApplicationOperationMode.CUSTOM) {
                    item {
                        PermissionSwitchRow(
                            label = stringResource(R.string.allow_actions),
                            checked = customPermissions.actions,
                            onCheckedChange = {
                                customPermissions = customPermissions.copy(actions = it)
                            },
                        )
                    }
                    item {
                        PermissionSwitchRow(
                            label = stringResource(R.string.allow_replies),
                            checked = customPermissions.replies,
                            onCheckedChange = {
                                customPermissions = customPermissions.copy(replies = it)
                            },
                        )
                    }
                    item {
                        PermissionSwitchRow(
                            label = stringResource(R.string.allow_clearing),
                            checked = customPermissions.clearing,
                            onCheckedChange = {
                                customPermissions = customPermissions.copy(clearing = it)
                            },
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSave(
                        if (mode == ApplicationOperationMode.GLOBAL_DEFAULTS) {
                            null
                        } else {
                            ApplicationOperationOverride(mode, customPermissions)
                        },
                    )
                },
            ) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        },
    )
}

private fun Set<String>.toggled(value: String): Set<String> =
    if (value in this) this - value else this + value

private enum class MainDestination { HOME, APPLICATIONS, DEVICES, SETTINGS }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(
    transportState: AndroidTransportState,
    workspaceDevices: List<WorkspaceDeviceSummary>,
    serverOrigin: String?,
    notificationAccessGranted: Boolean,
    applications: List<SelectableApplication>,
    applicationsLoaded: Boolean,
    selectedPackages: Set<String>,
    remoteOperationSettings: RemoteOperationSettings,
    onSaveApplicationSelection: (Set<String>) -> Unit,
    onSaveGlobalRemoteOperations: (RemoteOperationPermissions) -> Unit,
    onSaveApplicationOperationOverride: (String, ApplicationOperationOverride?) -> Unit,
    onOpenNotificationAccess: () -> Unit,
    onReconnect: () -> Unit,
    onPostDebugNotification: (() -> Unit)?,
) {
    var destination by rememberSaveable { mutableStateOf(MainDestination.HOME) }
    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val layout = navigationLayout(maxWidth.value)
        Scaffold(
            topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
            bottomBar = {
                if (layout == NavigationLayout.COMPACT) {
                    NavigationBar {
                        MainDestination.entries.forEach { item ->
                            NavigationBarItem(
                                selected = destination == item,
                                onClick = { destination = item },
                                icon = {
                                    Icon(
                                        painter = painterResource(destinationIcon(item)),
                                        contentDescription = null,
                                    )
                                },
                                label = { Text(destinationLabel(item)) },
                            )
                        }
                    }
                }
            },
        ) { padding ->
            Row(modifier = Modifier.fillMaxSize().padding(padding)) {
                if (layout == NavigationLayout.EXPANDED) {
                    NavigationRail {
                        MainDestination.entries.forEach { item ->
                            NavigationRailItem(
                                selected = destination == item,
                                onClick = { destination = item },
                                icon = {
                                    Icon(
                                        painter = painterResource(destinationIcon(item)),
                                        contentDescription = null,
                                    )
                                },
                                label = { Text(destinationLabel(item)) },
                                alwaysShowLabel = true,
                            )
                        }
                    }
                }
                Box(
                    modifier = Modifier.fillMaxSize().weight(1f),
                    contentAlignment = Alignment.TopCenter,
                ) {
                    Box(modifier = Modifier.fillMaxSize().widthIn(max = 960.dp)) {
                        when (destination) {
                            MainDestination.HOME -> HomeScreen(
                                transportState,
                                workspaceDevices,
                                notificationAccessGranted,
                                selectedPackages.size,
                                onReconnect,
                            )
                            MainDestination.APPLICATIONS -> ApplicationSelectionScreen(
                                applications,
                                applicationsLoaded,
                                selectedPackages,
                                onboarding = false,
                                remoteOperationSettings = remoteOperationSettings,
                                onSave = onSaveApplicationSelection,
                                onSaveGlobalRemoteOperations = onSaveGlobalRemoteOperations,
                                onSaveApplicationOperationOverride =
                                    onSaveApplicationOperationOverride,
                            )
                            MainDestination.DEVICES -> DevicesScreen(workspaceDevices)
                            MainDestination.SETTINGS -> SettingsScreen(
                                serverOrigin = serverOrigin,
                                currentDeviceName = workspaceDevices
                                    .firstOrNull(WorkspaceDeviceSummary::isCurrentDevice)
                                    ?.displayName,
                                notificationAccessGranted = notificationAccessGranted,
                                onOpenNotificationAccess = onOpenNotificationAccess,
                                onPostDebugNotification = onPostDebugNotification,
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun destinationIcon(destination: MainDestination): Int = when (destination) {
    MainDestination.HOME -> R.drawable.ic_home
    MainDestination.APPLICATIONS -> R.drawable.ic_apps
    MainDestination.DEVICES -> R.drawable.ic_devices
    MainDestination.SETTINGS -> R.drawable.ic_settings
}

@Composable
private fun destinationLabel(destination: MainDestination): String = when (destination) {
    MainDestination.HOME -> stringResource(R.string.home)
    MainDestination.APPLICATIONS -> stringResource(R.string.applications)
    MainDestination.DEVICES -> stringResource(R.string.devices)
    MainDestination.SETTINGS -> stringResource(R.string.settings)
}

@Composable
private fun HomeScreen(
    transportState: AndroidTransportState,
    workspaceDevices: List<WorkspaceDeviceSummary>,
    notificationAccessGranted: Boolean,
    selectedApplicationCount: Int,
    onReconnect: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.home_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.home_subtitle))
        }
        workspaceDevices.firstOrNull(WorkspaceDeviceSummary::isCurrentDevice)?.let { current ->
            item {
                StatusCard(
                    title = stringResource(R.string.current_device),
                    value = current.displayName,
                )
            }
        }
        item {
            ConnectionCard(
                state = transportState,
                onReconnect = onReconnect,
            )
        }
        item {
            StatusCard(
                title = stringResource(R.string.authorized_devices),
                value = pluralStringResource(
                    R.plurals.authorized_devices_count,
                    workspaceDevices.size,
                    workspaceDevices.size,
                ),
            )
        }
        item {
            StatusCard(
                title = stringResource(R.string.notification_access_title),
                value = stringResource(
                    if (notificationAccessGranted) R.string.enabled else R.string.needs_attention,
                ),
            )
        }
        item {
            StatusCard(
                title = stringResource(R.string.selected_apps),
                value = pluralStringResource(
                    R.plurals.selected_apps_count,
                    selectedApplicationCount,
                    selectedApplicationCount,
                ),
            )
        }
        item {
            Text(stringResource(R.string.alpha_synthetic_boundary), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun ConnectionCard(state: AndroidTransportState, onReconnect: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.connection), style = MaterialTheme.typography.titleMedium)
            Text(connectionLabel(state), style = MaterialTheme.typography.bodyLarge)
            if (state == AndroidTransportState.OFFLINE) {
                OutlinedButton(onClick = onReconnect) {
                    Text(stringResource(R.string.retry_connection))
                }
            }
        }
    }
}

@Composable
private fun StatusCard(title: String, value: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@Composable
private fun connectionLabel(state: AndroidTransportState): String = when (state) {
    AndroidTransportState.ONLINE -> stringResource(R.string.connected)
    AndroidTransportState.INITIALIZING,
    AndroidTransportState.CONNECTING,
    AndroidTransportState.SUBMITTING_REGISTRATION,
    AndroidTransportState.REGISTERING,
    AndroidTransportState.ROTATING,
    -> stringResource(R.string.connecting)
    AndroidTransportState.OFFLINE -> stringResource(R.string.connection_interrupted)
    AndroidTransportState.NOT_CONFIGURED -> stringResource(R.string.not_configured)
    AndroidTransportState.SECURITY_ERROR -> stringResource(R.string.needs_attention)
}

@Composable
private fun DevicesScreen(devices: List<WorkspaceDeviceSummary>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.devices),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.devices_body))
        }
        item {
            val androidCount = devices.count { it.deviceType == WorkspaceDeviceType.ANDROID }
            val chromeCount = devices.count { it.deviceType == WorkspaceDeviceType.CHROME }
            Text(stringResource(R.string.device_type_counts, androidCount, chromeCount))
        }
        if (devices.isEmpty()) {
            item { Text(stringResource(R.string.devices_empty)) }
        } else {
            items(devices) { device ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(device.displayName, style = MaterialTheme.typography.titleMedium)
                            if (device.isCurrentDevice) {
                                Text(
                                    stringResource(R.string.this_device),
                                    style = MaterialTheme.typography.labelLarge,
                                )
                            }
                        }
                        Text(
                            stringResource(
                                when (device.deviceType) {
                                    WorkspaceDeviceType.ANDROID -> R.string.android_device
                                    WorkspaceDeviceType.CHROME -> R.string.chrome_device
                                },
                            ),
                        )
                        Text(
                            stringResource(
                                if (device.accessCurrent) R.string.device_authorized
                                else R.string.device_access_expired,
                            ),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
        item {
            Card { Text(stringResource(R.string.devices_admin_boundary), Modifier.padding(20.dp)) }
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun SettingsScreen(
    serverOrigin: String?,
    currentDeviceName: String?,
    notificationAccessGranted: Boolean,
    onOpenNotificationAccess: () -> Unit,
    onPostDebugNotification: (() -> Unit)?,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.settings),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
        }
        item {
            SettingsCard(stringResource(R.string.private_service)) {
                Text(stringResource(R.string.server_address_label), style = MaterialTheme.typography.labelLarge)
                Text(serverOrigin ?: stringResource(R.string.not_available))
                Text(stringResource(R.string.current_device), style = MaterialTheme.typography.labelLarge)
                Text(currentDeviceName ?: stringResource(R.string.not_available))
                Text(stringResource(R.string.server_change_help), style = MaterialTheme.typography.bodySmall)
            }
        }
        item {
            SettingsCard(stringResource(R.string.notification_access_title)) {
                Text(
                    stringResource(
                        if (notificationAccessGranted) R.string.enabled else R.string.needs_attention,
                    ),
                )
                OutlinedButton(onClick = onOpenNotificationAccess) {
                    Text(stringResource(R.string.open_notification_access))
                }
            }
        }
        item {
            SettingsCard(stringResource(R.string.data_and_privacy)) {
                Text(stringResource(R.string.data_and_privacy_body))
                Text(stringResource(R.string.alpha_synthetic_boundary), style = MaterialTheme.typography.bodySmall)
            }
        }
        item {
            SettingsCard(stringResource(R.string.access_recovery)) {
                Text(stringResource(R.string.access_recovery_body))
            }
        }
        item {
            SettingsCard(stringResource(R.string.about)) {
                Text(stringResource(R.string.version_value, BuildConfig.VERSION_NAME))
                Text(stringResource(R.string.license_value))
            }
        }
        onPostDebugNotification?.let { post ->
            item {
                OutlinedButton(onClick = post) {
                    Text(stringResource(R.string.debug_post_test_notification))
                }
            }
        }
        item { Spacer(Modifier.height(20.dp)) }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@Composable
private fun SecurityErrorScreen() {
    Page { modifier ->
        Column(
            modifier = modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(R.string.security_error_title),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineMedium,
            )
            Text(stringResource(R.string.stored_state_security_error))
            Card { Text(stringResource(R.string.security_error_recovery), Modifier.padding(20.dp)) }
        }
    }
}
