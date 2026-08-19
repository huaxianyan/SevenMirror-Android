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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import java.text.DateFormat
import java.util.Date

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
                    trustPairingController =
                    (application as NotificationMirroringApplication).trustPairingController,
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
    trustPairingController: AndroidTrustPairingController,
    onOpenNotificationAccess: () -> Unit,
    onPostDebugNotification: () -> Unit,
) {
    val notifications by LocalNotificationController.notifications.collectAsState()
    val debugActionResult by DebugActionState.lastResult.collectAsState()
    val regularActionCount by DebugActionState.regularActionCount.collectAsState()
    val transportState by transportCoordinator.state.collectAsState()
    val identityTransitionStatus by transportCoordinator.identityTransitionStatus.collectAsState()
    val pairingState by trustPairingController.state.collectAsState()
    var serverOrigin by remember { mutableStateOf("") }
    var pairingCode by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("Android") }
    var rotationCode by remember { mutableStateOf("") }
    var registrationMessage by remember { mutableStateOf<String?>(null) }
    var confirmIdentityTransition by remember { mutableStateOf(false) }
    var peerPendingRemoval by remember {
        mutableStateOf<AndroidIdentityTransitionPeerStatus?>(null)
    }
    val transitionPeerRemoved = stringResource(R.string.transition_peer_removed)
    val transitionPeerRemovalFailed = stringResource(R.string.transition_peer_removal_failed)
    val identityTransitionPreparing = stringResource(R.string.identity_transition_preparing)
    val identityTransitionStarted = stringResource(R.string.identity_transition_started)
    val identityTransitionFailed = stringResource(R.string.identity_transition_failed)
    val credentialRotationStarted = stringResource(R.string.credential_rotation_started)
    val credentialRotationAccepted = stringResource(R.string.credential_rotation_accepted)
    val credentialRotationUnconfirmed = stringResource(R.string.credential_rotation_unconfirmed)
    val registrationStarted = stringResource(R.string.registration_started)
    val registrationSucceeded = stringResource(R.string.registration_succeeded)
    val registrationFailed = stringResource(R.string.registration_failed)

    peerPendingRemoval?.let { peer ->
        AlertDialog(
            onDismissRequest = { peerPendingRemoval = null },
            title = { Text(stringResource(R.string.remove_transition_peer_title)) },
            text = {
                Text(stringResource(R.string.remove_transition_peer_message, peer.deviceRef))
            },
            confirmButton = {
                TextButton(onClick = {
                    peerPendingRemoval = null
                    transportCoordinator.removeIdentityTransitionPeer(peer.deviceId) { succeeded, _ ->
                        registrationMessage = if (succeeded) {
                            transitionPeerRemoved
                        } else {
                            transitionPeerRemovalFailed
                        }
                    }
                }) { Text(stringResource(R.string.remove_peer)) }
            },
            dismissButton = {
                TextButton(onClick = { peerPendingRemoval = null }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

    if (confirmIdentityTransition) {
        AlertDialog(
            onDismissRequest = { confirmIdentityTransition = false },
            title = { Text(stringResource(R.string.rotate_identity_title)) },
            text = { Text(stringResource(R.string.rotate_identity_message)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmIdentityTransition = false
                    registrationMessage = identityTransitionPreparing
                    transportCoordinator.startIdentityTransition { succeeded, _ ->
                        registrationMessage = if (succeeded) {
                            identityTransitionStarted
                        } else {
                            identityTransitionFailed
                        }
                    }
                }) { Text(stringResource(R.string.start_transition)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmIdentityTransition = false }) {
                    Text(stringResource(R.string.cancel))
                }
            },
        )
    }

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
                identityTransitionActive = identityTransitionStatus != null,
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
                onRotateIdentity = { confirmIdentityTransition = true },
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
                        if (succeeded) trustPairingController.refresh()
                        registrationMessage = if (succeeded) {
                            registrationSucceeded
                        } else {
                            registrationFailed
                        }
                    }
                },
            )
        }
        identityTransitionStatus?.let { transition ->
            item {
                IdentityTransitionStatusCard(
                    status = transition,
                    onRefresh = transportCoordinator::refreshIdentityTransitionStatus,
                    onRemovePeer = { peerPendingRemoval = it },
                )
            }
        }
        item {
            TrustPairingCard(
                state = pairingState,
                onCreateOffer = trustPairingController::createOffer,
                onImportPayload = trustPairingController::importPayload,
                onConfirm = trustPairingController::confirmSafetyCode,
                onCancel = trustPairingController::cancel,
                onRefresh = trustPairingController::refresh,
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
                NotificationCard(snapshot, trustPairingController)
            }
        }
    }
}

@Composable
private fun TransportRegistrationCard(
    state: AndroidTransportState,
    identityTransitionActive: Boolean,
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
    onRotateIdentity: () -> Unit,
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
                Text(
                    stringResource(R.string.identity_transition_boundary),
                    style = MaterialTheme.typography.bodySmall,
                )
                Button(
                    onClick = onRotateIdentity,
                    enabled = state == AndroidTransportState.ONLINE && !identityTransitionActive,
                ) {
                    Text(stringResource(R.string.rotate_identity))
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
private fun transitionPhaseLabel(phase: String): String = when (phase) {
    "AWAITING_ACKS" -> stringResource(R.string.transition_phase_awaiting_acks)
    "RECOVERY_AUTHORIZED" -> stringResource(R.string.transition_phase_recovery_authorized)
    "PROMOTION_COMPLETED" -> stringResource(R.string.transition_phase_promotion_completed)
    "BLOCKED" -> stringResource(R.string.transition_phase_blocked)
    else -> stringResource(R.string.transport_security_error)
}

@Composable
private fun transitionPeerPhaseLabel(phase: String): String = when (phase) {
    "AWAITING_ACK" -> stringResource(R.string.transition_peer_awaiting_ack)
    "COMMIT_QUEUED" -> stringResource(R.string.transition_peer_commit_queued)
    else -> stringResource(R.string.transport_security_error)
}

@Composable
private fun IdentityTransitionStatusCard(
    status: AndroidIdentityTransitionStatus,
    onRefresh: () -> Unit,
    onRemovePeer: (AndroidIdentityTransitionPeerStatus) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.identity_transition_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                stringResource(R.string.transition_phase, transitionPhaseLabel(status.phase)),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                stringResource(
                    R.string.transition_deadline,
                    DateFormat.getDateTimeInstance().format(Date(status.expiresAtUnixMs)),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            if (status.peers.isEmpty()) {
                Text(
                    stringResource(R.string.transition_no_peers),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            status.peers.forEach { peer ->
                Text(
                    stringResource(
                        R.string.transition_peer_status,
                        peer.deviceRef,
                        peer.keyRef,
                        transitionPeerPhaseLabel(peer.phase),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                )
                Button(onClick = { onRemovePeer(peer) }) {
                    Text(stringResource(R.string.remove_transition_peer, peer.deviceRef))
                }
            }
            Button(onClick = onRefresh) {
                Text(stringResource(R.string.refresh_transition_status))
            }
        }
    }
}

@Composable
private fun TrustPairingCard(
    state: AndroidTrustPairingState,
    onCreateOffer: () -> Unit,
    onImportPayload: (String) -> Unit,
    onConfirm: (String) -> Unit,
    onCancel: () -> Unit,
    onRefresh: () -> Unit,
) {
    val context = LocalContext.current
    var importedPayload by remember { mutableStateOf("") }
    var safetyConfirmed by remember(state) { mutableStateOf(false) }
    val trustOfferClipboardLabel = stringResource(R.string.clipboard_trust_offer)
    val trustApprovalClipboardLabel = stringResource(R.string.clipboard_trust_approval)
    fun copyPayload(label: String, value: String) {
        context.getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.trusted_device_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                when (state) {
                    is AndroidTrustPairingState.OfferCreated ->
                        stringResource(R.string.pairing_step_approval)
                    is AndroidTrustPairingState.CompareSafetyCode ->
                        stringResource(R.string.pairing_step_safety_code)
                    else -> stringResource(R.string.pairing_step_offer)
                },
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                stringResource(R.string.pairing_boundary),
                style = MaterialTheme.typography.bodySmall,
            )
            when (state) {
                AndroidTrustPairingState.Loading -> Text(stringResource(R.string.pairing_loading))
                AndroidTrustPairingState.NotConfigured -> {
                    Text(stringResource(R.string.pairing_register_first))
                }
                AndroidTrustPairingState.Idle,
                AndroidTrustPairingState.Approved,
                is AndroidTrustPairingState.Error,
                -> {
                    if (state == AndroidTrustPairingState.Approved) {
                        Text(stringResource(R.string.pairing_peer_approved))
                    }
                    if (state is AndroidTrustPairingState.Error) {
                        Text(
                            stringResource(R.string.pairing_state_error),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Button(onClick = onCreateOffer) {
                        Text(stringResource(R.string.create_trust_offer))
                    }
                    PairingPayloadImport(
                        value = importedPayload,
                        onValueChange = { importedPayload = it.take(512) },
                        onImport = {
                            val payload = importedPayload
                            importedPayload = ""
                            onImportPayload(payload)
                        },
                    )
                    if (state is AndroidTrustPairingState.Error) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = onRefresh) {
                                Text(stringResource(R.string.restore_session))
                            }
                            Button(onClick = onCancel) {
                                Text(stringResource(R.string.cancel_session))
                            }
                        }
                    }
                }
                is AndroidTrustPairingState.OfferCreated -> {
                    OutlinedTextField(
                        value = state.offerPayload,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text(stringResource(R.string.offer_payload_label)) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = {
                        copyPayload(trustOfferClipboardLabel, state.offerPayload)
                    }) {
                        Text(stringResource(R.string.copy_offer_payload))
                    }
                    PairingPayloadImport(
                        value = importedPayload,
                        onValueChange = { importedPayload = it.take(512) },
                        onImport = {
                            val payload = importedPayload
                            importedPayload = ""
                            onImportPayload(payload)
                        },
                    )
                    Button(onClick = onCancel) {
                        Text(stringResource(R.string.cancel_pairing))
                    }
                }
                is AndroidTrustPairingState.CompareSafetyCode -> {
                    state.approvalPayload?.let { payload ->
                        OutlinedTextField(
                            value = payload,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text(stringResource(R.string.approval_payload_label)) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Button(onClick = {
                            copyPayload(trustApprovalClipboardLabel, payload)
                        }) {
                            Text(stringResource(R.string.copy_approval_payload))
                        }
                    }
                    Text(
                        stringResource(R.string.safety_code),
                        style = MaterialTheme.typography.labelLarge,
                    )
                    Text(state.safetyCode, style = MaterialTheme.typography.headlineSmall)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = safetyConfirmed,
                            onCheckedChange = { safetyConfirmed = it },
                        )
                        Text(stringResource(R.string.safety_code_confirmed))
                    }
                    Button(
                        enabled = safetyConfirmed,
                        onClick = { onConfirm(state.safetyCode) },
                    ) {
                        Text(stringResource(R.string.approve_peer))
                    }
                    Button(onClick = onCancel) {
                        Text(stringResource(R.string.reject_and_cancel))
                    }
                }
            }
        }
    }
}

@Composable
private fun PairingPayloadImport(
    value: String,
    onValueChange: (String) -> Unit,
    onImport: () -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.received_pairing_payload)) },
        placeholder = { Text(stringResource(R.string.pairing_payload_placeholder)) },
        modifier = Modifier.fillMaxWidth(),
    )
    Button(enabled = value.isNotBlank(), onClick = onImport) {
        Text(stringResource(R.string.import_pairing_payload))
    }
}

@Composable
private fun NotificationCard(
    snapshot: NotificationSnapshot,
    trustPairingController: AndroidTrustPairingController,
) {
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
                    SyntheticRelayActionControl(snapshot, action, trustPairingController)
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
    trustPairingController: AndroidTrustPairingController,
) {
    val context = LocalContext.current
    var message by remember(snapshot.revision, action.token.actionId.hex) { mutableStateOf<String?>(null) }
    Button(
        onClick = {
            try {
                val target = trustPairingController.syntheticActionTarget(snapshot, action)
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
