package dev.notificationmirroring.android

import android.Manifest
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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
    onOpenNotificationAccess: () -> Unit,
    onPostDebugNotification: () -> Unit,
) {
    val notifications by LocalNotificationController.notifications.collectAsState()
    val debugActionResult by DebugActionState.lastResult.collectAsState()

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Notification Mirroring", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Phase 0 local capability test. Notification content never leaves this process.",
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onOpenNotificationAccess) {
                Text("Open notification access")
            }
            Button(onClick = onPostDebugNotification) {
                Text("Post local action test notification")
            }
        }
        Text("Debug receiver: $debugActionResult", style = MaterialTheme.typography.bodySmall)
        Text("Active notifications: ${notifications.size}")
        if (notifications.isEmpty()) {
            Text("Grant access and generate a notification to test extraction and actions.")
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxSize(),
            ) {
                items(notifications, key = { it.key }) { snapshot ->
                    NotificationCard(snapshot)
                }
            }
        }
    }
}

@Composable
private fun NotificationCard(snapshot: NotificationSnapshot) {
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
            snapshot.actions.forEach { action -> ActionControl(action) }
        }
    }
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
