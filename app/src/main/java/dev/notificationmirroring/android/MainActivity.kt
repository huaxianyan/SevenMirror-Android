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
import androidx.compose.material3.Checkbox
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
    val pairingState by trustPairingController.state.collectAsState()
    var serverOrigin by remember { mutableStateOf("") }
    var pairingCode by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf("Android") }
    var rotationCode by remember { mutableStateOf("") }
    var registrationMessage by remember { mutableStateOf<String?>(null) }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Notification Mirroring", style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Text(
                "Transport registration uses synthetic data only. Real notification sync remains disabled.",
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
                    registrationMessage = "Credential rotation started; current remains until pending SNO1"
                    transportCoordinator.rotateCredential(oneTimeCode) { requestConfirmed ->
                        registrationMessage = if (requestConfirmed) {
                            "Rotation request accepted; pending authentication must receive SNO1"
                        } else {
                            "Rotation was not confirmed; durable attempted state, if created, will probe pending then current"
                        }
                    }
                },
                onRegister = {
                    val oneTimeCode = pairingCode
                    pairingCode = ""
                    registrationMessage = "Registration started"
                    transportCoordinator.register(
                        serverOrigin = serverOrigin,
                        pairingCode = oneTimeCode,
                        deviceName = deviceName,
                    ) { succeeded ->
                        if (succeeded) trustPairingController.refresh()
                        registrationMessage = if (succeeded) {
                            "Registered; waiting for authenticated connection"
                        } else {
                            "Registration failed; verify server, code, and device name"
                        }
                    }
                },
            )
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
                    Text("Open notification access")
                }
                Button(onClick = onPostDebugNotification) {
                    Text("Post local action test notification")
                }
            }
        }
        item {
            Text("Debug receiver: $debugActionResult", style = MaterialTheme.typography.bodySmall)
            Text("Synthetic regular side-effect count: $regularActionCount", style = MaterialTheme.typography.bodySmall)
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
                Text("Refresh synthetic outbox status")
            }
        }
        item { Text("Active notifications: ${notifications.size}") }
        if (notifications.isEmpty()) {
            item { Text("Grant access and generate a notification to test extraction and actions.") }
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
            Text("Private server", style = MaterialTheme.typography.titleMedium)
            Text("Transport: ${state.name}", style = MaterialTheme.typography.bodySmall)
            if (state == AndroidTransportState.NOT_CONFIGURED) {
                OutlinedTextField(
                    value = serverOrigin,
                    onValueChange = onServerOriginChanged,
                    label = { Text("Server origin") },
                    placeholder = { Text("https://notify.example") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = pairingCode,
                    onValueChange = onPairingCodeChanged,
                    label = { Text("One-time pairing code") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = onDeviceNameChanged,
                    label = { Text("Device name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = onRegister,
                    enabled = serverOrigin.isNotBlank() && pairingCode.length == 32 &&
                        deviceName.isNotBlank(),
                ) {
                    Text("Register this Android device")
                }
            }
            if (state != AndroidTransportState.NOT_CONFIGURED &&
                state != AndroidTransportState.REGISTERING
            ) {
                Text(
                    "Rotation keeps current until pending receives authenticated SNO1. Interrupted retries reuse exact pending.",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = rotationCode,
                    onValueChange = onRotationCodeChanged,
                    label = { Text("One-time credential rotation code") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = onRotate,
                    enabled = rotationCode.length == 32 && state != AndroidTransportState.ROTATING,
                ) {
                    Text("Start recoverable credential rotation")
                }
            }
            if (state == AndroidTransportState.OFFLINE) {
                Button(onClick = onReconnect) { Text("Retry connection") }
            }
            if (state == AndroidTransportState.SECURITY_ERROR) {
                Text(
                    "Stored identity or credential state failed security validation; no replacement was created.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
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
    fun copyPayload(label: String, value: String) {
        context.getSystemService(ClipboardManager::class.java)
            .setPrimaryClip(ClipData.newPlainText(label, value))
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Trusted E2EE device", style = MaterialTheme.typography.titleMedium)
            Text(
                when (state) {
                    is AndroidTrustPairingState.OfferCreated ->
                        "Step 2 — Send this offer, then import the approval response"
                    is AndroidTrustPairingState.CompareSafetyCode ->
                        "Step 3 — Compare the complete safety code and approve independently"
                    else -> "Step 1 — Create or import an offer"
                },
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                "Synthetic testing only. The first payload is an offer; importing it creates a different approval response that must be sent back. Compare the complete safety code on both devices.",
                style = MaterialTheme.typography.bodySmall,
            )
            when (state) {
                AndroidTrustPairingState.Loading -> Text("Loading pairing state…")
                AndroidTrustPairingState.NotConfigured -> Text("Register this Android device first.")
                AndroidTrustPairingState.Idle,
                AndroidTrustPairingState.Approved,
                is AndroidTrustPairingState.Error,
                -> {
                    if (state == AndroidTrustPairingState.Approved) {
                        Text("Peer approved locally. The other device must confirm independently.")
                    }
                    if (state is AndroidTrustPairingState.Error) {
                        Text(state.message, style = MaterialTheme.typography.bodySmall)
                    }
                    Button(onClick = onCreateOffer) { Text("Create trust offer") }
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
                            Button(onClick = onRefresh) { Text("Restore session") }
                            Button(onClick = onCancel) { Text("Cancel session") }
                        }
                    }
                }
                is AndroidTrustPairingState.OfferCreated -> {
                    OutlinedTextField(
                        value = state.offerPayload,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Offer — send this once to the other device") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = { copyPayload("Trust offer", state.offerPayload) }) {
                        Text("Copy offer payload")
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
                    Button(onClick = onCancel) { Text("Cancel pairing") }
                }
                is AndroidTrustPairingState.CompareSafetyCode -> {
                    state.approvalPayload?.let { payload ->
                        OutlinedTextField(
                            value = payload,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("Approval response — send this back to the offer creator") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Button(onClick = { copyPayload("Trust approval", payload) }) {
                            Text("Copy approval payload")
                        }
                    }
                    Text("Safety code", style = MaterialTheme.typography.labelLarge)
                    Text(state.safetyCode, style = MaterialTheme.typography.headlineSmall)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = safetyConfirmed,
                            onCheckedChange = { safetyConfirmed = it },
                        )
                        Text("I compared the complete code on both devices and it matches")
                    }
                    Button(
                        enabled = safetyConfirmed,
                        onClick = { onConfirm(state.safetyCode) },
                    ) {
                        Text("Approve this peer")
                    }
                    Button(onClick = onCancel) { Text("Reject and cancel") }
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
        label = { Text("Payload received from the other device") },
        placeholder = { Text("sntrust1:…") },
        modifier = Modifier.fillMaxWidth(),
    )
    Button(enabled = value.isNotBlank(), onClick = onImport) {
        Text("Import received payload")
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
