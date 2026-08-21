package dev.notificationmirroring.android

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.notificationmirroring.notification.ActionExecutionStatus
import dev.notificationmirroring.notification.LocalNotificationController
import dev.notificationmirroring.notification.NotificationActionDescriptor
import dev.notificationmirroring.notification.NotificationSnapshot

class MainActivity : ComponentActivity() {
    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            DebugNotificationPublisher.post(this)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                NotificationCapabilityScreen(
                    transportCoordinator =
                    (application as NotificationMirroringApplication).transportCoordinator,
                    onOpenNotificationAccess = {
                        startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                    },
                    onPostDebugNotification = ::postDebugNotification,
                )
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
            DebugNotificationPublisher.post(this)
        }
    }
}

@Composable
private fun NotificationCapabilityScreen(
    transportCoordinator: AndroidTransportCoordinator,
    onOpenNotificationAccess: () -> Unit,
    onPostDebugNotification: () -> Unit,
) {
    val notifications by LocalNotificationController.notifications.collectAsState()
    val debugActionResult by DebugActionState.lastResult.collectAsState()
    val regularActionCount by DebugActionState.regularActionCount.collectAsState()
    val transportState by transportCoordinator.state.collectAsState()
    var serverOrigin by remember { mutableStateOf("") }
    var pairingCode by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("Android") }
    var rotationCode by remember { mutableStateOf("") }
    var registrationMessage by remember { mutableStateOf<String?>(null) }
    val credentialRotationStarted = stringResource(R.string.credential_rotation_started)
    val credentialRotationAccepted = stringResource(R.string.credential_rotation_accepted)
    val credentialRotationUnconfirmed = stringResource(R.string.credential_rotation_unconfirmed)
    val registrationStarted = stringResource(R.string.registration_started)
    val registrationSucceeded = stringResource(R.string.registration_succeeded)
    val registrationFailed = stringResource(R.string.registration_failed)

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Text(
                stringResource(R.string.transport_boundary),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        item {
            TransportRegistrationCard(
                state = transportState,
                serverOrigin = serverOrigin,
                onServerOriginChanged = { serverOrigin = it },
                pairingCode = pairingCode,
                onPairingCodeChanged = { pairingCode = it.take(32) },
                deviceName = deviceName,
                onDeviceNameChanged = { deviceName = it.take(100) },
                rotationCode = rotationCode,
                onRotationCodeChanged = { rotationCode = it.take(32) },
                message = registrationMessage,
                onReconnect = transportCoordinator::connect,
                onRotate = {
                    val oneTimeCode = rotationCode
                    rotationCode = ""
                    registrationMessage = credentialRotationStarted
                    transportCoordinator.rotateCredential(oneTimeCode) { requestConfirmed ->
                        registrationMessage = if (requestConfirmed) {
                            credentialRotationAccepted
                        } else {
                            credentialRotationUnconfirmed
                        }
                    }
                },
                onRegister = {
                    val oneTimeCode = pairingCode
                    pairingCode = ""
                    registrationMessage = registrationStarted
                    transportCoordinator.register(
                        serverOrigin = serverOrigin,
                        pairingCode = oneTimeCode,
                        deviceName = deviceName,
                    ) { succeeded ->
                        registrationMessage = if (succeeded) {
                            registrationSucceeded
                        } else {
                            registrationFailed
                        }
                    }
                },
            )
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onOpenNotificationAccess) {
                    Text(stringResource(R.string.open_notification_access))
                }
                Button(onClick = onPostDebugNotification) {
                    Text(stringResource(R.string.post_test_notification))
                }
            }
        }
        item {
            Text(
                stringResource(R.string.debug_receiver, debugActionResult),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                stringResource(R.string.synthetic_side_effect_count, regularActionCount),
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = {
                    val snapshot = transportCoordinator.syntheticResultOutboxSnapshot()
                    DebugActionState.update(
                        "Result outbox: reservations=${snapshot.reservations}, " +
                            "completed=${snapshot.completedResults}, due=${snapshot.dueResults}, " +
                            "dormant=${snapshot.dormantResults}, " +
                            "acknowledged=${snapshot.acknowledgedResults}, " +
                            "accepted sends=${snapshot.acceptedSendAttempts}",
                    )
                },
            ) {
                Text(stringResource(R.string.refresh_outbox_status))
            }
        }
        item { Text(stringResource(R.string.active_notifications, notifications.size)) }
        if (notifications.isEmpty()) {
            item { Text(stringResource(R.string.notification_test_empty)) }
        } else {
            items(notifications, key = { it.key }) { snapshot ->
                NotificationCard(snapshot)
            }
        }
    }
}

@Composable
private fun TransportRegistrationCard(
    state: AndroidTransportState,
    serverOrigin: String,
    onServerOriginChanged: (String) -> Unit,
    pairingCode: String,
    onPairingCodeChanged: (String) -> Unit,
    deviceName: String,
    onDeviceNameChanged: (String) -> Unit,
    rotationCode: String,
    onRotationCodeChanged: (String) -> Unit,
    message: String?,
    onReconnect: () -> Unit,
    onRotate: () -> Unit,
    onRegister: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(stringResource(R.string.private_server), style = MaterialTheme.typography.titleMedium)
            Text(
                stringResource(R.string.transport_status, transportStateLabel(state)),
                style = MaterialTheme.typography.bodySmall,
            )
            if (state == AndroidTransportState.NOT_CONFIGURED) {
                OutlinedTextField(
                    value = serverOrigin,
                    onValueChange = onServerOriginChanged,
                    label = { Text(stringResource(R.string.server_origin)) },
                    placeholder = { Text(stringResource(R.string.server_origin_placeholder)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = pairingCode,
                    onValueChange = onPairingCodeChanged,
                    label = { Text(stringResource(R.string.one_time_pairing_code)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = onDeviceNameChanged,
                    label = { Text(stringResource(R.string.device_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = onRegister,
                    enabled = serverOrigin.isNotBlank() && pairingCode.length == 32 &&
                        deviceName.isNotBlank(),
                ) {
                    Text(stringResource(R.string.register_android_device))
                }
            }
            if (state != AndroidTransportState.NOT_CONFIGURED &&
                state != AndroidTransportState.REGISTERING
            ) {
                Text(
                    stringResource(R.string.credential_rotation_boundary),
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = rotationCode,
                    onValueChange = onRotationCodeChanged,
                    label = { Text(stringResource(R.string.one_time_rotation_code)) },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = onRotate,
                    enabled = rotationCode.length == 32 && state != AndroidTransportState.ROTATING,
                ) {
                    Text(stringResource(R.string.start_credential_rotation))
                }
            }
            if (state == AndroidTransportState.OFFLINE) {
                Button(onClick = onReconnect) { Text(stringResource(R.string.retry_connection)) }
            }
            if (state == AndroidTransportState.SECURITY_ERROR) {
                Text(
                    stringResource(R.string.stored_state_security_error),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun transportStateLabel(state: AndroidTransportState): String = when (state) {
    AndroidTransportState.NOT_CONFIGURED -> stringResource(R.string.transport_not_configured)
    AndroidTransportState.REGISTERING -> stringResource(R.string.transport_registering)
    AndroidTransportState.ROTATING -> stringResource(R.string.transport_rotating)
    AndroidTransportState.CONNECTING -> stringResource(R.string.transport_connecting)
    AndroidTransportState.ONLINE -> stringResource(R.string.transport_online)
    AndroidTransportState.OFFLINE -> stringResource(R.string.transport_offline)
    AndroidTransportState.SECURITY_ERROR -> stringResource(R.string.transport_security_error)
}

@Composable
private fun NotificationCard(snapshot: NotificationSnapshot) {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(snapshot.appName, style = MaterialTheme.typography.titleMedium)
            Text(snapshot.title ?: "(no title)")
            snapshot.expandedText.orEmpty().ifBlank { snapshot.text.orEmpty() }
                .takeIf(String::isNotBlank)
                ?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            Text(
                "${snapshot.packageName} · revision ${snapshot.revision}" +
                    if (snapshot.isOngoing) " · ongoing" else "",
                style = MaterialTheme.typography.bodySmall,
            )
            snapshot.actions.forEach { action ->
                if (snapshot.packageName == context.packageName && !action.requiresTextInput) {
                    SyntheticRelayActionControl(snapshot, action)
                }
                ActionControl(action)
            }
        }
    }
}

@Composable
private fun SyntheticRelayActionControl(
    snapshot: NotificationSnapshot,
    action: NotificationActionDescriptor,
) {
    val context = LocalContext.current
    var message by remember(snapshot.revision, action.token.actionId.hex) { mutableStateOf<String?>(null) }
    Button(
        onClick = {
            try {
                val target = SyntheticActionTargetExporter.export(context, snapshot, action)
                context.getSystemService(ClipboardManager::class.java).setPrimaryClip(
                    ClipData.newPlainText("Synthetic relay action target", target),
                )
                message = "Synthetic target copied for Chrome Options"
            } catch (_: Throwable) {
                message = "Synthetic target unavailable; verify registration"
            }
        },
    ) {
        Text("Copy synthetic relay target")
    }
    message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
}

@Composable
private fun ActionControl(action: NotificationActionDescriptor) {
    val context = LocalContext.current
    val replies = remember { mutableStateMapOf<String, String>() }
    val results = remember { mutableStateMapOf<String, ActionExecutionStatus>() }
    val key = "${action.token.notificationKey}:${action.token.notificationRevision}:${action.token.actionId.hex}"
    val reply = replies[key].orEmpty()

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        if (action.requiresTextInput) {
            OutlinedTextField(
                value = reply,
                onValueChange = { replies[key] = it.take(4_000) },
                label = { Text(action.title) },
                singleLine = false,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(
                enabled = !action.requiresTextInput || reply.isNotBlank(),
                onClick = {
                    val result = LocalNotificationController.invoke(
                        context = context,
                        token = action.token,
                        replyText = reply.takeIf { action.requiresTextInput },
                    )
                    results[key] = result.status
                    if (result.status == ActionExecutionStatus.SUCCEEDED) {
                        replies.remove(key)
                    }
                },
            ) {
                Text(if (action.requiresTextInput) "Send" else action.title)
            }
            results[key]?.let { Text(it.name, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
