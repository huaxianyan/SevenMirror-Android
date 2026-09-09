package dev.notificationmirroring.android

import android.content.pm.PackageManager
import android.content.res.Resources
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import dev.notificationmirroring.crypto.WorkspaceDeviceSummary
import dev.notificationmirroring.crypto.WorkspaceDeviceType
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private enum class ProductPage(val title: Int) {
    SYNC(R.string.home), APPLICATIONS(R.string.applications), SETTINGS(R.string.settings),
    DEFAULTS(R.string.sync_defaults), APP_SETTINGS(R.string.application_settings_title),
    APP_DETAIL(R.string.application_settings_title), PERMISSIONS(R.string.permissions_and_runtime),
    DEVICES(R.string.service_and_devices), PRIVACY(R.string.data_and_privacy),
    ABOUT(R.string.about), DIAGNOSTICS(R.string.developer_diagnostics);

    val primary: ProductPage
        get() = if (this == SYNC || this == APPLICATIONS) this else SETTINGS
    val parent: ProductPage
        get() = if (this == APP_DETAIL) APP_SETTINGS else if (primary == SETTINGS && this != SETTINGS) SETTINGS else SYNC
}

private val productPageSaver = Saver<ProductPage, String>(save = { it.name }, restore = { ProductPage.valueOf(it) })
private val primaryPages = listOf(ProductPage.SYNC, ProductPage.APPLICATIONS, ProductPage.SETTINGS)
private val packageSelectionSaver = listSaver<Set<String>, String>(save = { it.toList() }, restore = { it.toSet() })

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun MainScreen(
    transportState: AndroidTransportState,
    workspaceDevices: List<WorkspaceDeviceSummary>,
    serverOrigin: String?,
    notificationAccessGranted: Boolean,
    applications: List<SelectableApplication>,
    applicationsLoaded: Boolean,
    applicationsLoadFailed: Boolean,
    selectedPackages: Set<String>,
    notificationSharingSettings: NotificationSharingSettings,
    remoteOperationSettings: RemoteOperationSettings,
    backgroundConnectionEnabled: Boolean,
    foregroundNotificationGranted: Boolean,
    batteryOptimizationExempt: Boolean,
    omittedNotificationCount: Int,
    onSaveApplicationSelection: (Set<String>) -> Unit,
    onSaveSyncSilentNotifications: (Boolean) -> Unit,
    onSaveApplicationSettings: (String, ApplicationNotificationSettings, ApplicationOperationOverride?) -> Unit,
    onSaveGlobalRemoteOperations: (RemoteOperationPermissions) -> Unit,
    onOpenNotificationAccess: () -> Unit,
    onReconnect: () -> Unit,
    onSetBackgroundConnectionEnabled: (Boolean) -> Unit,
    onOpenStatusNotificationSettings: () -> Unit,
    onOpenBatterySettings: () -> Unit,
    onReloadApplications: () -> Unit,
    onPostDebugNotification: (() -> Unit)?,
) {
    var page by rememberSaveable(stateSaver = productPageSaver) { mutableStateOf(ProductPage.SYNC) }
    var selectedApplication by rememberSaveable { mutableStateOf<String?>(null) }
    var dirty by rememberSaveable { mutableStateOf(false) }
    var pendingPage by remember { mutableStateOf<ProductPage?>(null) }
    var saveFailed by remember { mutableStateOf(false) }
    fun navigate(next: ProductPage) {
        if (next == page) return
        if (dirty) pendingPage = next else { page = next; saveFailed = false }
    }
    fun save(operation: () -> Unit): Boolean = try {
        operation()
        saveFailed = false
        true
    } catch (_: RuntimeException) {
        saveFailed = true
        false
    }
    BackHandler(page != ProductPage.SYNC) { navigate(page.parent) }

    BoxWithConstraints(Modifier.fillMaxSize()) {
        val rail = navigationLayout(maxWidth.value) == NavigationLayout.EXPANDED
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(stringResource(if (page in primaryPages) R.string.app_name else page.title)) },
                    navigationIcon = {
                        if (page !in primaryPages) IconButton(onClick = { navigate(page.parent) }) {
                            Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.back))
                        }
                    },
                )
            },
            bottomBar = {
                if (!rail) NavigationBar {
                    primaryPages.forEach { target ->
                        NavigationBarItem(
                            selected = page.primary == target,
                            onClick = { navigate(target) },
                            icon = { NavigationIcon(target) },
                            label = { Text(stringResource(target.title)) },
                        )
                    }
                }
            },
        ) { padding ->
            Row(Modifier.fillMaxSize().padding(padding)) {
                if (rail) NavigationRail {
                    primaryPages.forEach { target ->
                        NavigationRailItem(
                            selected = page.primary == target,
                            onClick = { navigate(target) },
                            icon = { NavigationIcon(target) },
                            label = { Text(stringResource(target.title)) },
                        )
                    }
                }
                Column(Modifier.weight(1f).fillMaxHeight(), horizontalAlignment = Alignment.CenterHorizontally) {
                    if (saveFailed && page != ProductPage.APPLICATIONS && page != ProductPage.APP_DETAIL) Text(
                        stringResource(R.string.settings_save_failed),
                        modifier = Modifier.padding(20.dp).semantics { liveRegion = LiveRegionMode.Polite },
                        color = MaterialTheme.colorScheme.error,
                    )
                    Box(Modifier.widthIn(max = 840.dp).fillMaxSize()) {
                        when (page) {
                            ProductPage.SYNC -> ProductList {
                                item { PageHeading(R.string.home) }
                                item {
                                    Card(Modifier.fillMaxWidth()) {
                                        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                            workspaceDevices.firstOrNull { it.isCurrentDevice }?.let {
                                                Text(it.displayName, style = MaterialTheme.typography.labelLarge)
                                            }
                                            Text(connectionLabel(transportState), style = MaterialTheme.typography.headlineSmall)
                                            Text(stringResource(R.string.connection_delivery_boundary))
                                            if (transportState == AndroidTransportState.OFFLINE) {
                                                OutlinedButton(onClick = onReconnect) { Text(stringResource(R.string.retry_connection)) }
                                            }
                                        }
                                    }
                                }
                                if (!notificationAccessGranted || !foregroundNotificationGranted) item {
                                    SettingsLink(R.string.permissions_need_attention, R.string.permissions_recovery_hint) {
                                        navigate(ProductPage.PERMISSIONS)
                                    }
                                }
                                item {
                                    SettingsLink(
                                        title = stringResource(R.string.selected_apps),
                                        supporting = pluralStringResource(R.plurals.selected_apps_count, selectedPackages.size, selectedPackages.size),
                                    ) { navigate(ProductPage.APPLICATIONS) }
                                }
                                item {
                                    SettingsLink(
                                        title = stringResource(R.string.background_connection),
                                        supporting = stringResource(if (backgroundConnectionEnabled) R.string.background_enabled_summary else R.string.background_disabled_summary),
                                    ) { navigate(ProductPage.DEFAULTS) }
                                }
                                item { SettingsLink(R.string.service_and_devices, R.string.devices_membership_summary) { navigate(ProductPage.DEVICES) } }
                                if (omittedNotificationCount > 0) item {
                                    Text(pluralStringResource(R.plurals.notification_limit_body, omittedNotificationCount, omittedNotificationCount, EncryptedPayloadCodecV1.MAX_SNAPSHOT_ENTRIES))
                                }
                            }
                            ProductPage.APPLICATIONS -> ApplicationSelectionScreen(
                                applications, applicationsLoaded, applicationsLoadFailed, selectedPackages,
                                onboarding = false,
                                onSave = { save { onSaveApplicationSelection(it) } },
                                onReload = onReloadApplications,
                                onConfigure = { selectedApplication = it; navigate(ProductPage.APP_DETAIL) },
                                onDirtyChange = { dirty = it },
                            )
                            ProductPage.SETTINGS -> ProductList {
                                item { PageHeading(R.string.settings) }
                                item { SettingsLink(R.string.sync_defaults, R.string.sync_defaults_summary) { navigate(ProductPage.DEFAULTS) } }
                                item { SettingsLink(R.string.application_settings_title, R.string.application_settings_summary) { navigate(ProductPage.APP_SETTINGS) } }
                                item { SettingsLink(R.string.permissions_and_runtime, R.string.permissions_recovery_hint) { navigate(ProductPage.PERMISSIONS) } }
                                item { SettingsLink(R.string.service_and_devices, R.string.devices_membership_summary) { navigate(ProductPage.DEVICES) } }
                                item { SettingsLink(R.string.data_and_privacy) { navigate(ProductPage.PRIVACY) } }
                                item { SettingsLink(R.string.about) { navigate(ProductPage.ABOUT) } }
                                if (onPostDebugNotification != null) item { SettingsLink(R.string.developer_diagnostics) { navigate(ProductPage.DIAGNOSTICS) } }
                            }
                            ProductPage.DEFAULTS -> ProductList {
                                item { Text(stringResource(R.string.settings_apply_immediately)) }
                                item { SectionHeading(R.string.background_connection) }
                                item {
                                    PermissionSwitchRow(stringResource(R.string.keep_connection_active), backgroundConnectionEnabled) {
                                        save { onSetBackgroundConnectionEnabled(it) }
                                    }
                                    Text(stringResource(R.string.background_connection_body), style = MaterialTheme.typography.bodySmall)
                                }
                                item { SettingsLink(R.string.permissions_and_runtime) { navigate(ProductPage.PERMISSIONS) } }
                                item { SectionHeading(R.string.notification_sharing) }
                                item { PermissionSwitchRow(stringResource(R.string.sync_silent_notifications), notificationSharingSettings.syncSilent) { save { onSaveSyncSilentNotifications(it) } } }
                                item {
                                    SectionHeading(R.string.remote_operations)
                                    Text(stringResource(R.string.remote_operations_body), style = MaterialTheme.typography.bodySmall)
                                }
                                item { OperationSwitches(remoteOperationSettings.globalDefaults) { save { onSaveGlobalRemoteOperations(it) } } }
                            }
                            ProductPage.APP_SETTINGS -> ProductList {
                                item { Text(stringResource(R.string.application_settings_summary)) }
                                applicationLoadItems(applicationsLoaded, applicationsLoadFailed, onReloadApplications)
                                if (applicationsLoaded && !applicationsLoadFailed && applications.isEmpty()) item { Text(stringResource(R.string.no_selectable_apps)) }
                                items(applications, key = { it.packageName }) { app ->
                                    Surface(onClick = { selectedApplication = app.packageName; navigate(ProductPage.APP_DETAIL) }) {
                                        ApplicationIdentity(app, Modifier.padding(vertical = 12.dp))
                                    }
                                }
                            }
                            ProductPage.APP_DETAIL -> {
                                val app = applications.firstOrNull { it.packageName == selectedApplication }
                                if (app == null) ProductList {
                                    item { Text(stringResource(R.string.application_unavailable)) }
                                    item { OutlinedButton(onClick = onReloadApplications) { Text(stringResource(R.string.reload_applications)) } }
                                } else ApplicationSettingsScreen(
                                    app,
                                    notificationSharingSettings.settingsFor(app.packageName),
                                    remoteOperationSettings.globalDefaults,
                                    remoteOperationSettings.applicationOverrides[app.packageName],
                                    onDirtyChange = { dirty = it },
                                    onSave = { settings, override -> save { onSaveApplicationSettings(app.packageName, settings, override) } },
                                )
                            }
                            ProductPage.PERMISSIONS -> PermissionsScreen(
                                notificationAccessGranted, foregroundNotificationGranted, batteryOptimizationExempt,
                                onOpenNotificationAccess, onOpenStatusNotificationSettings, onOpenBatterySettings,
                            )
                            ProductPage.DEVICES -> ProductList {
                                item { SectionHeading(R.string.private_service); SelectionContainer { Text(serverOrigin ?: stringResource(R.string.not_available)) } }
                                item { Text(stringResource(R.string.devices_membership_summary)) }
                                items(workspaceDevices) { device ->
                                    ListItem(
                                        headlineContent = { Text(device.displayName) },
                                        supportingContent = { Text(stringResource(if (device.deviceType == WorkspaceDeviceType.ANDROID) R.string.android_device else R.string.chrome_device)) },
                                        trailingContent = { Text(stringResource(if (device.isCurrentDevice) R.string.this_device else if (device.accessCurrent) R.string.device_authorized else R.string.device_access_expired)) },
                                    )
                                }
                                if (workspaceDevices.isEmpty()) item { Text(stringResource(R.string.devices_empty)) }
                                item { Text(stringResource(R.string.devices_admin_boundary)) }
                            }
                            ProductPage.PRIVACY -> ProductList {
                                item { Text(stringResource(R.string.data_and_privacy_body)) }
                                item { SectionHeading(R.string.access_recovery); Text(stringResource(R.string.access_recovery_body)) }
                                item { Text(stringResource(R.string.server_change_help)) }
                            }
                            ProductPage.ABOUT -> ProductList {
                                item { Text(stringResource(R.string.version_value, BuildConfig.VERSION_NAME)) }
                                item { Text(stringResource(R.string.license_value)) }
                            }
                            ProductPage.DIAGNOSTICS -> ProductList {
                                onPostDebugNotification?.let { post -> item { OutlinedButton(onClick = post) { Text(stringResource(R.string.debug_post_test_notification)) } } }
                            }
                        }
                    }
                }
            }
        }
    }
    pendingPage?.let { next ->
        AlertDialog(
            onDismissRequest = { pendingPage = null },
            title = { Text(stringResource(R.string.unsaved_changes_title)) },
            text = { Text(stringResource(R.string.unsaved_changes_body)) },
            confirmButton = { TextButton(onClick = { dirty = false; page = next; pendingPage = null; saveFailed = false }) { Text(stringResource(R.string.discard_changes)) } },
            dismissButton = { TextButton(onClick = { pendingPage = null }) { Text(stringResource(R.string.keep_editing)) } },
        )
    }
}

@Composable
private fun NavigationIcon(page: ProductPage) {
    Icon(painterResource(when (page) {
        ProductPage.SYNC -> R.drawable.ic_home
        ProductPage.APPLICATIONS -> R.drawable.ic_apps
        else -> R.drawable.ic_settings
    }), contentDescription = null)
}

@Composable
private fun ProductList(content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        content = content,
    )
}

@Composable
private fun PageHeading(resource: Int) {
    Text(stringResource(resource), Modifier.semantics { heading() }, style = MaterialTheme.typography.headlineMedium)
}

@Composable
private fun SectionHeading(resource: Int) {
    Text(stringResource(resource), Modifier.padding(top = 12.dp).semantics { heading() }, style = MaterialTheme.typography.titleMedium)
}

@Composable
private fun SettingsLink(title: Int, supporting: Int? = null, onClick: () -> Unit) {
    SettingsLink(stringResource(title), supporting?.let { stringResource(it) }, onClick)
}

@Composable
private fun SettingsLink(title: String, supporting: String? = null, onClick: () -> Unit) {
    Surface(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(title) },
            supportingContent = supporting?.let { { Text(it) } },
            trailingContent = { Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null) },
        )
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.applicationLoadItems(loaded: Boolean, failed: Boolean, onReload: () -> Unit) {
    if (!loaded) item { CircularProgressIndicator() }
    if (failed) item {
        Text(stringResource(R.string.applications_load_failed))
        OutlinedButton(onClick = onReload) { Text(stringResource(R.string.reload_applications)) }
    }
}

@Composable
internal fun ApplicationSelectionScreen(
    applications: List<SelectableApplication>,
    applicationsLoaded: Boolean,
    applicationsLoadFailed: Boolean,
    initialSelection: Set<String>,
    onboarding: Boolean,
    onSave: (Set<String>) -> Boolean,
    onReload: () -> Unit,
    onConfigure: ((String) -> Unit)?,
    onDirtyChange: ((Boolean) -> Unit)?,
) {
    var selection by rememberSaveable(initialSelection, stateSaver = packageSelectionSaver) { mutableStateOf(initialSelection.toSet()) }
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(ApplicationFilter.ORDINARY) }
    var selectedOnly by rememberSaveable { mutableStateOf(false) }
    var saveFailed by remember { mutableStateOf(false) }
    val dirty = selection != initialSelection
    SideEffect { onDirtyChange?.invoke(dirty) }
    val visible = remember(applications, filter, query, selectedOnly, selection) {
        filterApplications(applications, filter, query).filter { !selectedOnly || it.packageName in selection }
    }
    Column(Modifier.fillMaxSize()) {
        LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item { PageHeading(if (onboarding) R.string.choose_apps_title else R.string.applications) }
            item { Text(stringResource(R.string.choose_apps_body)) }
            item { OutlinedTextField(query, { query = it }, label = { Text(stringResource(R.string.search_apps)) }, modifier = Modifier.fillMaxWidth(), singleLine = true) }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(filter == ApplicationFilter.ORDINARY, { filter = ApplicationFilter.ORDINARY }, label = { Text(stringResource(R.string.ordinary_apps)) })
                    FilterChip(filter == ApplicationFilter.SYSTEM, { filter = ApplicationFilter.SYSTEM }, label = { Text(stringResource(R.string.system_apps)) })
                }
                FilterChip(selectedOnly, { selectedOnly = !selectedOnly }, label = { Text(stringResource(R.string.selected_apps)) })
            }
            item {
                OutlinedButton(onClick = { selection = selection + visible.map { it.packageName } }, enabled = visible.any { it.packageName !in selection }) { Text(stringResource(R.string.select_shown_apps)) }
                TextButton(onClick = { selection = emptySet() }, enabled = selection.isNotEmpty()) { Text(stringResource(R.string.clear_selection)) }
            }
            applicationLoadItems(applicationsLoaded, applicationsLoadFailed, onReload)
            if (applicationsLoaded && !applicationsLoadFailed && visible.isEmpty()) item { Text(stringResource(R.string.no_apps_match_filters)) }
            items(visible, key = { it.packageName }) { app ->
                Column {
                    Row(
                        Modifier.fillMaxWidth().toggleable(app.packageName in selection, role = Role.Checkbox) {
                            selection = if (it) selection + app.packageName else selection - app.packageName
                        }.heightIn(min = 64.dp), verticalAlignment = Alignment.CenterVertically,
                    ) {
                        ApplicationIdentity(app, Modifier.weight(1f))
                        Checkbox(app.packageName in selection, onCheckedChange = null)
                    }
                    if (onConfigure != null) TextButton(onClick = { onConfigure(app.packageName) }) { Text(stringResource(R.string.configure_app)) }
                    HorizontalDivider()
                }
            }
        }
        Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
            if (saveFailed) Text(stringResource(R.string.settings_save_failed), color = MaterialTheme.colorScheme.error)
            Text(stringResource(if (dirty) R.string.unsaved_changes_title else R.string.alpha_app_selection_notice), style = MaterialTheme.typography.bodySmall)
            Button(
                onClick = { saveFailed = !onSave(selection) },
                enabled = applicationsLoaded && !applicationsLoadFailed && (onboarding || dirty),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.save_app_selection, selection.size)) }
        }
    }
}

@Composable
private fun ApplicationIdentity(app: SelectableApplication, modifier: Modifier = Modifier) {
    val context = LocalContext.current.applicationContext
    val sizePx = with(LocalDensity.current) { 40.dp.roundToPx() }
    val bitmap by produceState<ImageBitmap?>(null, app.packageName, sizePx) {
        value = withContext(Dispatchers.IO) {
            try {
                context.packageManager.getApplicationIcon(app.packageName).toBitmap(sizePx, sizePx).asImageBitmap()
            } catch (_: PackageManager.NameNotFoundException) { null }
            catch (_: Resources.NotFoundException) { null }
        }
    }
    Row(modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        bitmap?.let { Image(it, contentDescription = null, modifier = Modifier.size(40.dp)) }
            ?: Icon(painterResource(R.drawable.ic_apps), contentDescription = null, modifier = Modifier.size(40.dp))
        Column(Modifier.weight(1f)) {
            Text(app.label, style = MaterialTheme.typography.bodyLarge)
            SelectionContainer { Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

@Composable
private fun ApplicationSettingsScreen(
    application: SelectableApplication,
    settings: ApplicationNotificationSettings,
    defaults: RemoteOperationPermissions,
    override: ApplicationOperationOverride?,
    onDirtyChange: (Boolean) -> Unit,
    onSave: (ApplicationNotificationSettings, ApplicationOperationOverride?) -> Boolean,
) {
    var showContent by rememberSaveable(application.packageName, settings.showContent) { mutableStateOf(settings.showContent) }
    var ongoing by rememberSaveable(application.packageName, settings.syncOngoing) { mutableStateOf(settings.syncOngoing) }
    val initialMode = override?.mode ?: ApplicationOperationMode.GLOBAL_DEFAULTS
    val initialCustom = override?.customPermissions ?: defaults
    var mode by rememberSaveable(application.packageName, initialMode) { mutableStateOf(initialMode) }
    var actions by rememberSaveable(application.packageName, initialCustom.actions) { mutableStateOf(initialCustom.actions) }
    var replies by rememberSaveable(application.packageName, initialCustom.replies) { mutableStateOf(initialCustom.replies) }
    var clearing by rememberSaveable(application.packageName, initialCustom.clearing) { mutableStateOf(initialCustom.clearing) }
    var failed by remember { mutableStateOf(false) }
    val custom = RemoteOperationPermissions(actions, replies, clearing)
    val notificationSettings = ApplicationNotificationSettings(showContent, ongoing)
    val draftOverride = if (mode == ApplicationOperationMode.GLOBAL_DEFAULTS) null else ApplicationOperationOverride(mode, custom)
    val effectivePermissions = RemoteOperationSettings(
        globalDefaults = defaults,
        applicationOverrides = draftOverride?.let { mapOf(application.packageName to it) }.orEmpty(),
    ).permissionsFor(application.packageName)
    val dirty = notificationSettings != settings || mode != initialMode || (mode == ApplicationOperationMode.CUSTOM && custom != initialCustom)
    SideEffect { onDirtyChange(dirty) }
    ProductList {
        item { ApplicationIdentity(application) }
        item { SectionHeading(R.string.notification_content) }
        item {
            PermissionSwitchRow(stringResource(R.string.show_notification_content), showContent) { showContent = it }
            Text(stringResource(R.string.hidden_content_help), style = MaterialTheme.typography.bodySmall)
        }
        item { PermissionSwitchRow(stringResource(R.string.sync_ongoing_notifications), ongoing) { ongoing = it } }
        item { SectionHeading(R.string.remote_operations) }
        items(ApplicationOperationMode.entries) { option ->
            Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).selectable(mode == option, role = Role.RadioButton, onClick = { mode = option }), verticalAlignment = Alignment.CenterVertically) {
                RadioButton(mode == option, onClick = null)
                Text(stringResource(when (option) {
                    ApplicationOperationMode.GLOBAL_DEFAULTS -> R.string.use_global_defaults
                    ApplicationOperationMode.ALLOW_ALL -> R.string.allow_all_operations
                    ApplicationOperationMode.VIEW_ONLY -> R.string.view_only
                    ApplicationOperationMode.CUSTOM -> R.string.custom_permissions
                }))
            }
        }
        if (mode == ApplicationOperationMode.CUSTOM) item {
            OperationSwitches(custom) { actions = it.actions; replies = it.replies; clearing = it.clearing }
        } else item {
            Text(stringResource(R.string.effective_operations,
                stringResource(if (effectivePermissions.actions) R.string.allowed else R.string.not_allowed),
                stringResource(if (effectivePermissions.replies) R.string.allowed else R.string.not_allowed),
                stringResource(if (effectivePermissions.clearing) R.string.allowed else R.string.not_allowed)))
        }
        item {
            if (failed) Text(stringResource(R.string.settings_save_failed), color = MaterialTheme.colorScheme.error)
            Button(onClick = {
                failed = !onSave(notificationSettings, draftOverride)
            }, enabled = dirty, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.save)) }
        }
    }
}

@Composable
private fun OperationSwitches(value: RemoteOperationPermissions, onChange: (RemoteOperationPermissions) -> Unit) {
    PermissionSwitchRow(stringResource(R.string.allow_actions), value.actions) { onChange(value.copy(actions = it)) }
    PermissionSwitchRow(stringResource(R.string.allow_replies), value.replies) { onChange(value.copy(replies = it)) }
    PermissionSwitchRow(stringResource(R.string.allow_clearing), value.clearing) { onChange(value.copy(clearing = it)) }
}

@Composable
private fun PermissionSwitchRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(checked, role = Role.Switch, onValueChange = onCheckedChange), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(checked, onCheckedChange = null)
    }
}

@Composable
private fun PermissionsScreen(
    notificationAccess: Boolean,
    statusNotifications: Boolean,
    batteryExempt: Boolean,
    onOpenAccess: () -> Unit,
    onOpenStatus: () -> Unit,
    onOpenBattery: () -> Unit,
) {
    ProductList {
        item { Text(stringResource(R.string.permissions_recovery_hint)) }
        item { SectionHeading(R.string.required_for_sync) }
        item {
            PermissionStatus(R.string.notification_access_title, notificationAccess, R.string.notification_access_body, onOpenAccess)
        }
        item { PermissionStatus(R.string.status_notification_title, statusNotifications, R.string.status_notification_body, onOpenStatus) }
        item { SectionHeading(R.string.background_recommendations) }
        item {
            Text(stringResource(if (batteryExempt) R.string.battery_usage_unrestricted else R.string.battery_usage_system_managed))
            Text(stringResource(R.string.battery_recommendation_body), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = onOpenBattery) { Text(stringResource(R.string.review_battery_settings)) }
        }
    }
}

@Composable
private fun PermissionStatus(title: Int, granted: Boolean, body: Int, onOpen: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(if (granted) R.string.allowed else R.string.needs_attention))
            Text(stringResource(body))
            OutlinedButton(onClick = onOpen) { Text(stringResource(R.string.open_system_settings)) }
        }
    }
}

@Composable
private fun connectionLabel(state: AndroidTransportState): String = stringResource(when (state) {
    AndroidTransportState.ONLINE -> R.string.connected
    AndroidTransportState.OFFLINE -> R.string.connection_interrupted
    AndroidTransportState.NOT_CONFIGURED -> R.string.not_configured
    AndroidTransportState.SECURITY_ERROR -> R.string.needs_attention
    else -> R.string.connecting
})
