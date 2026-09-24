package com.neko7ina.sevenmirror

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper
import com.neko7ina.sevenmirror.crypto.AndroidActionResultOutbox
import com.neko7ina.sevenmirror.crypto.AndroidHpkeIdentityStore
import com.neko7ina.sevenmirror.crypto.AndroidOperationLedger
import com.neko7ina.sevenmirror.crypto.AndroidReplayLedger
import com.neko7ina.sevenmirror.crypto.AndroidWorkspaceMembershipStore
import com.neko7ina.sevenmirror.crypto.ActionResultOutboxDrainer
import com.neko7ina.sevenmirror.crypto.AuthenticatedHpke
import com.neko7ina.sevenmirror.crypto.NotificationEnvelopeSender
import com.neko7ina.sevenmirror.crypto.WorkspaceDeviceSummary
import com.neko7ina.sevenmirror.notification.ActiveNotificationSnapshot
import com.neko7ina.sevenmirror.notification.AndroidActionInvokeDispatcher
import com.neko7ina.sevenmirror.notification.AuthenticatedInboundReceipt
import com.neko7ina.sevenmirror.notification.LocalNotificationController
import com.neko7ina.sevenmirror.notification.NotificationActionDescriptor
import com.neko7ina.sevenmirror.notification.NotificationMedia
import com.neko7ina.sevenmirror.notification.NotificationMediaMimeType
import com.neko7ina.sevenmirror.notification.NotificationSnapshot
import com.neko7ina.sevenmirror.notification.RemoteOperationAuthorizer
import com.neko7ina.sevenmirror.protocol.EncryptedPayloadCodecV1
import com.neko7ina.sevenmirror.protocol.generated.v1.NotificationActionDescriptor as ProtocolNotificationActionDescriptor
import com.neko7ina.sevenmirror.protocol.generated.v1.NotificationMedia as ProtocolNotificationMedia
import com.neko7ina.sevenmirror.protocol.generated.v1.NotificationMediaMimeType as ProtocolNotificationMediaMimeType
import com.neko7ina.sevenmirror.transport.AndroidMembershipRegistration
import com.neko7ina.sevenmirror.transport.AndroidTransportCredentialStore
import com.neko7ina.sevenmirror.transport.AndroidPendingMembershipStore
import com.neko7ina.sevenmirror.transport.AndroidRelayDeliveryCursorStore
import com.neko7ina.sevenmirror.transport.AuthenticatedWebSocketFactory
import com.neko7ina.sevenmirror.transport.BoundedReconnectBackoff
import com.neko7ina.sevenmirror.transport.CredentialCandidateSource
import com.neko7ina.sevenmirror.transport.MembershipTransportPromotionCoordinator
import com.neko7ina.sevenmirror.transport.RelayDeliveryCodecV1
import com.neko7ina.sevenmirror.transport.RelayServerMessageV1
import com.neko7ina.sevenmirror.transport.TransportCredentialRotationClient
import com.neko7ina.sevenmirror.transport.TransportCredentialUnreadableException
import com.neko7ina.sevenmirror.transport.WorkspaceMembershipClient
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

private const val MEMBERSHIP_REFRESH_INTERVAL_MS = 60_000L

private fun NotificationActionDescriptor.toProtocolOrNull(): ProtocolNotificationActionDescriptor? {
    if (title.toByteArray(Charsets.UTF_8).size !in 1..EncryptedPayloadCodecV1.MAX_NOTIFICATION_ACTION_TITLE_BYTES) return null
    return ProtocolNotificationActionDescriptor.newBuilder()
        .setActionId(com.google.protobuf.ByteString.copyFrom(token.actionId.toByteArray()))
        .setTitle(title)
        .setRequiresTextInput(requiresTextInput)
        .setAllowsFreeFormInput(allowsFreeFormInput)
        .build()
}

private fun NotificationSnapshot.protocolActions(): List<ProtocolNotificationActionDescriptor> = actions
    .asSequence()
    .mapNotNull(NotificationActionDescriptor::toProtocolOrNull)
    .take(EncryptedPayloadCodecV1.MAX_NOTIFICATION_ACTIONS)
    .toList()

private fun NotificationMedia.toProtocol(): ProtocolNotificationMedia =
    ProtocolNotificationMedia.newBuilder()
        .setContentSha256(com.google.protobuf.ByteString.copyFrom(contentSha256))
        .setMimeType(
            when (mimeType) {
                NotificationMediaMimeType.PNG ->
                    ProtocolNotificationMediaMimeType.NOTIFICATION_MEDIA_MIME_TYPE_PNG
            },
        )
        .setWidth(width)
        .setHeight(height)
        .setEncodedBytes(com.google.protobuf.ByteString.copyFrom(bytes))
        .build()

enum class AndroidTransportState {
    INITIALIZING,
    NOT_CONFIGURED,
    SUBMITTING_REGISTRATION,
    REGISTERING,
    ROTATING,
    CONNECTING,
    ONLINE,
    OFFLINE,
    SECURITY_ERROR,
}

enum class AndroidSecurityRecovery {
    NONE,
    CERTIFIED_DEVICE_REMOVAL,
    UNREADABLE_LOCAL_CREDENTIAL,
}

internal fun securityRecoveryForLocalMembership(
    localDeviceActive: Boolean?,
): AndroidSecurityRecovery = if (localDeviceActive == false) {
    AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL
} else {
    AndroidSecurityRecovery.NONE
}

/**
 * Recovery for stored credential material that this device can no longer read or decrypt.
 *
 * The Android Keystore wrapping key lives outside the application data directory, so it is not part
 * of any data backup and cannot be restored. Once the credential can no longer be decrypted the
 * device can never revalidate itself, and it cannot contact the server to observe a removal either.
 * Registering the device again is the only exit.
 */
internal fun securityRecoveryForUnreadableCredential(): AndroidSecurityRecovery =
    AndroidSecurityRecovery.UNREADABLE_LOCAL_CREDENTIAL

/**
 * Recovery for a failed credential read.
 *
 * Only [TransportCredentialUnreadableException] proves the wrapping key is gone or the ciphertext
 * no longer authenticates, which re-enrollment alone can resolve. Everything else, in particular a
 * Keystore or Binder call that is merely unavailable right now, must stay retryable: the recovery
 * page offers no retry, so classifying one such failure as permanent strands a healthy device.
 */
internal fun securityRecoveryForCredentialReadFailure(error: Throwable): AndroidSecurityRecovery =
    if (error is TransportCredentialUnreadableException) {
        securityRecoveryForUnreadableCredential()
    } else {
        AndroidSecurityRecovery.NONE
    }

/** Process-lifetime transport owner with serialized, fail-closed encrypted action dispatch. */
class AndroidTransportCoordinator(context: Context) {
    private val applicationContext = context.applicationContext
    private val identityStore = AndroidHpkeIdentityStore(applicationContext)
    private val credentialStore = AndroidTransportCredentialStore(applicationContext)
    private val pendingMembershipStore = AndroidPendingMembershipStore(applicationContext)
    private val relayDeliveryCursorStore = AndroidRelayDeliveryCursorStore(applicationContext)
    private val workspaceMembershipStore = AndroidWorkspaceMembershipStore(applicationContext)
    private val recipientSelection = AndroidRecipientSelection(applicationContext, workspaceMembershipStore)
    private val replayLedger = AndroidReplayLedger(applicationContext)
    private val operationLedger = AndroidOperationLedger(applicationContext)
    private val resultOutbox = AndroidActionResultOutbox(applicationContext)
    private val productPreferences = AndroidProductPreferences(applicationContext)
    private val httpClient = OkHttpClient()
    private val rotationClient = TransportCredentialRotationClient(httpClient, credentialStore)
    private val membershipClient = WorkspaceMembershipClient(
        httpClient,
        workspaceMembershipStore,
        pendingMembershipStore,
    )
    private val membershipPromotionCoordinator = MembershipTransportPromotionCoordinator(
        pendingMembershipStore,
        workspaceMembershipStore,
        credentialStore,
    )
    private val connectivityManager =
        applicationContext.getSystemService(ConnectivityManager::class.java)
    private val executor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "notification-transport").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val generation = AtomicLong()
    // Accessed only while holding this coordinator's monitor.
    private val connectionOwners = mutableSetOf<Any>()
    private val reconnectBackoff = BoundedReconnectBackoff()
    private val mutableState = MutableStateFlow(AndroidTransportState.INITIALIZING)
    private val mutableEnrollmentPending = MutableStateFlow(false)
    private val mutableWorkspaceDevices = MutableStateFlow<List<WorkspaceDeviceSummary>>(emptyList())
    private val mutableRecipientSettings = MutableStateFlow(RecipientSettingsState("", false, emptyList()))
    private val mutableSynchronizationPaused = MutableStateFlow(productPreferences.isSynchronizationPaused())
    private val mutableServerOrigin = MutableStateFlow<String?>(null)
    private val mutableSecurityRecovery = MutableStateFlow(AndroidSecurityRecovery.NONE)
    private val diagnostics = TransportDiagnostics(state = { mutableState.value })

    private var webSocket: WebSocket? = null
    // Route the current socket, or the in-flight connection attempt, is bound to. Null means no
    // route is recorded, or the attempt is bound to no default network at all. Read and written
    // only on the serialized executor, the same as the rest of the connection state below.
    private var connectionRoute: NetworkRoute? = null
    private var reconnectFuture: ScheduledFuture<*>? = null
    private var resultDrainFuture: ScheduledFuture<*>? = null
    private var membershipRefreshFuture: ScheduledFuture<*>? = null
    private var terminalGeneration = Long.MIN_VALUE
    private var preferCurrentFallback = false

    val state: StateFlow<AndroidTransportState> = mutableState.asStateFlow()
    val enrollmentPending: StateFlow<Boolean> = mutableEnrollmentPending.asStateFlow()
    val workspaceDevices: StateFlow<List<WorkspaceDeviceSummary>> =
        mutableWorkspaceDevices.asStateFlow()
    internal val recipientSettings: StateFlow<RecipientSettingsState> = mutableRecipientSettings.asStateFlow()
    internal val synchronizationPaused: StateFlow<Boolean> = mutableSynchronizationPaused.asStateFlow()
    val serverOrigin: StateFlow<String?> = mutableServerOrigin.asStateFlow()
    val securityRecovery: StateFlow<AndroidSecurityRecovery> =
        mutableSecurityRecovery.asStateFlow()

    fun resultOutboxSnapshot(): AndroidActionResultOutbox.Snapshot =
        resultOutbox.snapshot(System.currentTimeMillis())

    internal fun setSynchronizationPaused(paused: Boolean) {
        productPreferences.saveSynchronizationPaused(paused)
        mutableSynchronizationPaused.value = paused
        if (!paused) {
            executor.execute {
                if (!productPreferences.isSynchronizationPaused()) {
                    LocalNotificationController.currentActiveSnapshot(applicationContext)
                        ?.let(::sendSnapshot)
                }
            }
        }
    }

    internal fun saveReceivingDevices(deviceKeys: Set<String>) {
        val settings = mutableRecipientSettings.value
        recipientSelection.save(settings, deviceKeys)
        mutableRecipientSettings.value = settings.copy(
            configured = true,
            devices = settings.devices.map { it.copy(selected = it.key in deviceKeys) },
        )
    }

    fun mirrorNotification(snapshot: NotificationSnapshot) {
        if (productPreferences.isSynchronizationPaused()) return
        executor.execute {
            if (productPreferences.isSynchronizationPaused()) return@execute
            sendNotification { sender, nowUnixMs ->
                sender.createUpsert(
                    notificationId = snapshot.key,
                    revision = snapshot.revision,
                    sourceApplicationId = snapshot.packageName,
                    sourceApplicationName = snapshot.appName,
                    title = snapshot.title,
                    body = snapshot.expandedText ?: snapshot.text,
                    appIcon = snapshot.appIcon?.toProtocol(),
                    avatar = snapshot.avatar?.toProtocol(),
                    containsContentImage = snapshot.containsContentImage,
                    actions = snapshot.protocolActions(),
                    nowUnixMs = nowUnixMs,
                )
            }
        }
    }

    fun removeNotification(notificationId: String, revision: Long) {
        if (productPreferences.isSynchronizationPaused()) return
        executor.execute {
            if (productPreferences.isSynchronizationPaused()) return@execute
            sendNotification { sender, nowUnixMs ->
                sender.createRemoved(notificationId, revision, nowUnixMs)
            }
        }
    }

    fun mirrorSnapshot(snapshot: ActiveNotificationSnapshot) {
        if (productPreferences.isSynchronizationPaused()) return
        executor.execute {
            if (!productPreferences.isSynchronizationPaused()) sendSnapshot(snapshot)
        }
    }

    init {
        connectivityManager.registerDefaultNetworkCallback(
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    diagnostics.record(
                        CoordinatorDiagnosticEvent.NETWORK_AVAILABLE,
                        generation.get(),
                        networkHandle = network.networkHandle,
                    )
                    executor.execute { considerNetworkRoute(currentNetworkRoute()) }
                }

                override fun onLost(network: Network) {
                    diagnostics.record(
                        CoordinatorDiagnosticEvent.NETWORK_LOST,
                        generation.get(),
                        networkHandle = network.networkHandle,
                    )
                    executor.execute { considerNetworkRoute(currentNetworkRoute()) }
                }

                override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                    diagnostics.record(
                        CoordinatorDiagnosticEvent.NETWORK_CAPABILITIES_CHANGED,
                        generation.get(),
                        networkHandle = network.networkHandle,
                        wifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                        cellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                        vpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                        validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                    )
                    // A route can be replaced without a network arriving or departing, so this
                    // callback decides a retirement too. See considerNetworkRoute.
                    executor.execute { considerNetworkRoute(currentNetworkRoute()) }
                }
            },
        )
    }

    /** Each visible Activity or running foreground Service holds its own connection ownership. */
    @Synchronized
    fun acquireConnection(owner: Any) {
        val wasEmpty = connectionOwners.isEmpty()
        connectionOwners.add(owner)
        if (wasEmpty) {
            retryConnection()
            return
        }
        // The background service holds a long-lived ownership, so `wasEmpty` stays false while a
        // visible Activity comes and goes. A failure that parked the transport would then survive
        // every reopen and be cleared only by killing the process, which is exactly what a device
        // observed on 2026-09-21 did for 18 hours. Re-entering the foreground re-arms a failure
        // that nothing has proven to be permanent; the two proven states stay terminal.
        if (mutableState.value == AndroidTransportState.SECURITY_ERROR &&
            mutableSecurityRecovery.value == AndroidSecurityRecovery.NONE
        ) {
            retryConnection()
        }
    }

    @Synchronized
    fun releaseConnection(owner: Any) {
        if (connectionOwners.remove(owner) && connectionOwners.isEmpty()) disconnect()
    }

    @Synchronized
    private fun hasConnectionOwner(): Boolean = connectionOwners.isNotEmpty()

    /** UI and network retries can use an existing demand, never create a new owner. */
    @Synchronized
    fun retryConnection() {
        if (connectionOwners.isEmpty()) return
        val requestedGeneration = generation.incrementAndGet()
        diagnostics.record(CoordinatorDiagnosticEvent.CONNECTION_REQUESTED, requestedGeneration)
        executor.execute {
            cancelReconnect()
            reconnectBackoff.reset()
            connectInternal(requestedGeneration)
        }
    }

    /**
     * A socket's route belongs to whatever the default network was when its TCP connection was
     * opened. Android does not close it when that route changes: the socket stays open on a path
     * that no longer carries traffic, and neither the socket nor the platform reports it for tens
     * of seconds. The controlled Wi-Fi recovery trace waited 72.25 s after the transport moved back
     * to Wi-Fi, while reconnecting once the change is seen takes under a second.
     *
     * Decide on the route's identity rather than on the socket. That identity is the default
     * network's handle together with its transports, because a handle alone is not enough when a
     * VPN owns the default network: the VPN keeps one handle while the transport underneath it
     * changes. The same trace showed exactly that, one VPN handle across a Wi-Fi to cellular
     * switch while its transports flipped from WIFI|VPN to CELLULAR|VPN.
     *
     * Signal strength, bandwidth estimates, metering and validation are deliberately not part of
     * the identity. They change on an unchanged route, and treating them as route changes would
     * retire a healthy connection.
     */
    private fun considerNetworkRoute(route: NetworkRoute?) {
        if (!hasConnectionOwner()) return
        val current = mutableState.value
        if (current != AndroidTransportState.ONLINE &&
            current != AndroidTransportState.CONNECTING &&
            current != AndroidTransportState.OFFLINE
        ) return
        if (route == connectionRoute) return
        connectionRoute = route
        if (current == AndroidTransportState.OFFLINE) {
            // Nothing is bound to the route that went away, so a route that exists is simply a
            // reason to try again. Adopting it keeps a repeat callback from asking twice.
            if (route != null) retryConnection()
            return
        }
        diagnostics.record(
            CoordinatorDiagnosticEvent.CONNECTION_NETWORK_REPLACED,
            generation.get(),
            networkHandle = route?.handle,
            wifi = route?.hasTransport(TRANSPORT_WIFI),
            cellular = route?.hasTransport(TRANSPORT_CELLULAR),
            vpn = route?.hasTransport(TRANSPORT_VPN),
        )
        // Retiring through the ordinary request path keeps everything an existing reconnect
        // already guarantees: the generation is superseded, a pending reconnect is canceled, the
        // backoff restarts for the new route, the connection-owner requirement still applies, and
        // the superseded socket is closed.
        retryConnection()
    }

    /** The route a new connection would use right now, or null when no default network is up. */
    private fun currentNetworkRoute(): NetworkRoute? {
        val network = connectivityManager.activeNetwork ?: return null
        val capabilities = connectivityManager.getNetworkCapabilities(network)
        return NetworkRoute(network.networkHandle, capabilities?.let(::transportMask) ?: 0)
    }

    private fun transportMask(capabilities: NetworkCapabilities): Int {
        var mask = 0
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) mask = mask or TRANSPORT_WIFI
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) mask = mask or TRANSPORT_CELLULAR
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) mask = mask or TRANSPORT_ETHERNET
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) mask = mask or TRANSPORT_BLUETOOTH
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) mask = mask or TRANSPORT_VPN
        return mask
    }

    private fun disconnect() {
        generation.incrementAndGet()
        executor.execute {
            cancelReconnect()
            cancelMembershipRefresh()
            webSocket?.close(1000, "connection owners released")
            webSocket = null
            connectionRoute = null
            if (mutableState.value != AndroidTransportState.NOT_CONFIGURED &&
                mutableState.value != AndroidTransportState.SECURITY_ERROR
            ) {
                mutableState.value = AndroidTransportState.OFFLINE
            }
        }
    }

    fun register(
        serverOrigin: String,
        pairingCode: String,
        deviceName: String,
        completed: (Boolean) -> Unit,
    ) {
        val requestedGeneration = generation.incrementAndGet()
        mutableState.value = AndroidTransportState.SUBMITTING_REGISTRATION
        executor.execute {
            cancelReconnect()
            reconnectBackoff.reset()
            var success = false
            try {
                webSocket?.close(1000, "replaced by registration")
                webSocket = null
                check(credentialStore.load() == null) {
                    "A transport credential already exists"
                }
                val identity = identityStore.loadOrCreate()
                try {
                    membershipClient.begin(
                        AndroidMembershipRegistration(
                            serverOrigin = serverOrigin,
                            pairingCode = pairingCode,
                            deviceName = deviceName,
                            identity = identity,
                        ),
                    ).authToken.fill(0)
                    success = true
                } finally {
                    identity.publicKey.fill(0)
                    identity.privateKey.fill(0)
                }
                connectInternal(requestedGeneration)
            } catch (_: Throwable) {
                val recoverable = runCatching { pendingMembershipStore.load() }.getOrNull()
                if (recoverable != null) {
                    recoverable.pending.authToken.fill(0)
                    recoverable.canonicalProof?.fill(0)
                    success = true
                    if (generation.get() == requestedGeneration) connectInternal(requestedGeneration)
                } else if (generation.get() == requestedGeneration) {
                    mutableState.value = stateAfterRegistrationFailure()
                }
            } finally {
                mainHandler.post { completed(success) }
            }
        }
    }

    /**
     * User-initiated exit from a security error. The local workspace credential is discarded and
     * enrollment restarts, which still requires a server-issued joining code and administrator
     * approval, so it grants no local privilege. It is offered for every security-error recovery
     * because none of them can be repaired on this device alone.
     */
    fun reEnrollAfterRecovery() {
        val requestedGeneration = generation.incrementAndGet()
        val wasSecurityError = mutableState.value == AndroidTransportState.SECURITY_ERROR
        mutableState.value = AndroidTransportState.INITIALIZING
        executor.execute {
            cancelReconnect()
            cancelMembershipRefresh()
            webSocket?.close(1000, "device re-enrollment")
            webSocket = null
            try {
                check(wasSecurityError) { "Re-enrollment requires a security error on this device" }
                productPreferences.beginCertifiedReEnrollmentReset()
                completeCertifiedReEnrollmentReset()
                connectInternal(requestedGeneration)
            } catch (error: Throwable) {
                enterSecurityError(requestedGeneration, error, AndroidSecurityRecovery.NONE)
            }
        }
    }

    fun rotateCredential(rotationCode: String, completed: (Boolean) -> Unit) {
        val requestedGeneration = generation.incrementAndGet()
        mutableState.value = AndroidTransportState.ROTATING
        executor.execute {
            cancelReconnect()
            reconnectBackoff.reset()
            webSocket?.close(1000, "replaced by credential rotation")
            webSocket = null
            var requestConfirmed = false
            try {
                rotationClient.rotate(rotationCode)
                requestConfirmed = true
            } catch (_: Throwable) {
                // An interrupted request may already have committed server-side. Durable attempted
                // state is resolved by pending authentication, never by assuming request failure.
            }
            try {
                credentialStore.loadRotation()?.let { rotation ->
                    rotation.current.authToken.fill(0)
                    rotation.pendingAuthToken.fill(0)
                }
            } catch (error: Throwable) {
                // Only material this device can never decrypt deserves the recovery page. Anything
                // else is left to the connection this rotation was about to rebuild, so a Keystore
                // or Binder call that is merely unavailable right now does not park a healthy
                // device.
                val recovery = securityRecoveryForCredentialReadFailure(error)
                if (recovery != AndroidSecurityRecovery.NONE) {
                    enterSecurityError(requestedGeneration, error, recovery)
                }
            }
            if (mutableState.value != AndroidTransportState.SECURITY_ERROR &&
                generation.get() == requestedGeneration
            ) {
                // Malformed/preparation failures safely restore current; attempted state probes
                // pending first. Neither path invents a replacement credential.
                connectInternal(requestedGeneration)
            }
            mainHandler.post { completed(requestConfirmed) }
        }
    }

    private fun connectInternal(requestedGeneration: Long) {
        if (!hasConnectionOwner() || generation.get() != requestedGeneration) return
        diagnostics.record(CoordinatorDiagnosticEvent.CONNECTION_ATTEMPT, requestedGeneration)
        if (productPreferences.isCertifiedReEnrollmentResetPending()) {
            try {
                completeCertifiedReEnrollmentReset()
            } catch (error: Throwable) {
                enterSecurityError(requestedGeneration, error, AndroidSecurityRecovery.NONE)
                return
            }
        }
        mutableSecurityRecovery.value = AndroidSecurityRecovery.NONE
        terminalGeneration = Long.MIN_VALUE
        webSocket?.close(1000, "replaced by new connection")
        webSocket = null
        cancelMembershipRefresh()
        val membershipReady = try {
            diagnostics.measure(CoordinatorDiagnosticEvent.PENDING_MEMBERSHIP_RECOVERY, requestedGeneration) {
                recoverPendingMembership()
            }
        } catch (_: IOException) {
            mutableState.value = AndroidTransportState.OFFLINE
            scheduleReconnect(requestedGeneration)
            return
        } catch (error: Throwable) {
            enterSecurityError(requestedGeneration, error, AndroidSecurityRecovery.NONE)
            return
        }
        if (!membershipReady) {
            mutableState.value = AndroidTransportState.REGISTERING
            scheduleReconnect(requestedGeneration)
            return
        }
        val candidate = try {
            credentialStore.loadConnectionCandidate(preferCurrentFallback)
        } catch (error: Throwable) {
            // Only damage that no retry can repair may park the device. The recovery page offers
            // no retry at all, so classifying a temporary Keystore or Binder failure as permanent
            // leaves a healthy device unusable until its process dies.
            handleLocalFailure(requestedGeneration, error, securityRecoveryForCredentialReadFailure(error))
            return
        }
        if (candidate == null) {
            reconnectBackoff.reset()
            mutableWorkspaceDevices.value = emptyList()
            mutableServerOrigin.value = null
            mutableState.value = AndroidTransportState.NOT_CONFIGURED
            return
        }
        val credential = candidate.credential
        val credentialSource = candidate.source
        mutableServerOrigin.value = credential.serverOrigin
        try {
            publishWorkspaceDevices(credential.workspaceId, credential.deviceId)
            val refreshed = diagnostics.measure(CoordinatorDiagnosticEvent.MEMBERSHIP_REFRESH, requestedGeneration) {
                membershipClient.refreshActive(credential)
            }
            check(refreshed == null ||
                refreshed.serverState == "approved" && refreshed.transportEligible
            ) { "Local device is not active in the durable workspace roster" }
            publishWorkspaceDevices(credential.workspaceId, credential.deviceId)
        } catch (_: IOException) {
            credential.authToken.fill(0)
            mutableState.value = AndroidTransportState.OFFLINE
            scheduleReconnect(requestedGeneration)
            return
        } catch (error: Throwable) {
            enterSecurityError(
                requestedGeneration,
                error,
                certifiedRemovalRecovery(
                    credential.workspaceId,
                    credential.deviceId,
                ),
            )
            credential.authToken.fill(0)
            return
        }
        try {
            val identity = checkNotNull(identityStore.loadExisting()) {
                "Transport credential exists without its bound E2EE identity"
            }
            val handlers = try {
                val keyId = MessageDigest.getInstance("SHA-256").digest(identity.publicKey)
                check(constantTimeEquals(keyId, credential.identityKeyId)) {
                    "Transport credential E2EE identity binding does not match"
                }
                val actionDispatcher = AndroidActionInvokeDispatcher(
                    context = applicationContext,
                    workspaceId = credential.workspaceId,
                    recipientDeviceId = credential.deviceId,
                    recipientIdentity = identity,
                    actionPeers = workspaceMembershipStore,
                    notificationRecipients = workspaceMembershipStore,
                    isSynchronizationActive = {
                        !productPreferences.isSynchronizationPaused()
                    },
                    isNotificationRecipientSelected = { peerDeviceId ->
                        recipientSelection.isSelected(
                            credential.workspaceId,
                            credential.deviceId,
                            peerDeviceId,
                        )
                    },
                    operationAuthorizer = RemoteOperationAuthorizer(
                        productPreferences::isRemoteOperationAllowed,
                    ),
                    replayLedger = replayLedger,
                    operationLedger = operationLedger,
                    resultOutbox = resultOutbox,
                )
                ConnectionHandlers(
                    actionDispatcher = actionDispatcher,
                    resultDrainer = ActionResultOutboxDrainer(
                        workspaceId = credential.workspaceId,
                        senderDeviceId = credential.deviceId,
                        senderIdentity = identity,
                        actionPeers = workspaceMembershipStore,
                        outbox = resultOutbox,
                    ),
                )
            } finally {
                identity.publicKey.fill(0)
                identity.privateKey.fill(0)
            }
            if (generation.get() != requestedGeneration) {
                handlers.clearIdentities()
                return
            }
            // Bind this attempt to the route its TCP connection will use. Recorded after the
            // routing work above, so an attempt that failed before reaching the socket does not
            // claim a route it never used.
            connectionRoute = currentNetworkRoute()
            mutableState.value = AndroidTransportState.CONNECTING
            val receivedSno1 = AtomicBoolean(false)
            // Bind observations to this attempt, including callbacks arriving after replacement.
            val socket = AuthenticatedWebSocketFactory(httpClient) { event, error ->
                if (error == null) {
                    diagnostics.record(event, requestedGeneration)
                } else {
                    diagnostics.recordFailure(event, requestedGeneration, error)
                }
            }.open(
                credential,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        receivedSno1.set(true)
                        executor.execute {
                            if (generation.get() != requestedGeneration) {
                                webSocket.close(1000, "superseded connection")
                                return@execute
                            }
                            try {
                                if (credentialSource == CredentialCandidateSource.PENDING) {
                                    credentialStore.promotePending().authToken.fill(0)
                                }
                                preferCurrentFallback = false
                                val resumeCursor = relayDeliveryCursorStore.load(
                                    credential.workspaceId,
                                    credential.deviceId,
                                ).committedDeliveryId
                                val resume = RelayDeliveryCodecV1.encodeResume(resumeCursor)
                                val resumeAccepted = try {
                                    webSocket.send(ByteString.of(*resume))
                                } finally {
                                    resume.fill(0)
                                }
                                if (!resumeAccepted) {
                                    webSocket.cancel()
                                    enqueueTermination(requestedGeneration, webSocket)
                                    return@execute
                                }
                                reconnectBackoff.reset()
                                mutableState.value = AndroidTransportState.ONLINE
                                diagnostics.record(CoordinatorDiagnosticEvent.CONNECTION_READY, requestedGeneration)
                                scheduleMembershipRefresh(requestedGeneration, webSocket)
                                cancelResultDrain()
                                drainResults(requestedGeneration, webSocket, handlers.resultDrainer)
                                LocalNotificationController.currentActiveSnapshot(applicationContext)
                                    ?.takeUnless { productPreferences.isSynchronizationPaused() }
                                    ?.let { snapshot ->
                                        val accepted = diagnostics.measure(
                                            CoordinatorDiagnosticEvent.STARTUP_SNAPSHOT,
                                            requestedGeneration,
                                        ) { sendSnapshot(snapshot) }
                                        diagnostics.record(
                                            CoordinatorDiagnosticEvent.STARTUP_SNAPSHOT_SUBMITTED,
                                            requestedGeneration,
                                            accepted = accepted,
                                        )
                                    }
                            } catch (error: Throwable) {
                                terminalGeneration = requestedGeneration
                                cancelResultDrain()
                                if (this@AndroidTransportCoordinator.webSocket === webSocket) {
                                    this@AndroidTransportCoordinator.webSocket = null
                                }
                                enterSecurityError(requestedGeneration, error, AndroidSecurityRecovery.NONE)
                                webSocket.close(1008, "connection initialization failed")
                            }
                        }
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        enqueueInboundRejection(requestedGeneration, webSocket)
                    }

                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        val frame = bytes.toByteArray()
                        executor.execute {
                            if (generation.get() != requestedGeneration ||
                                this@AndroidTransportCoordinator.webSocket !== webSocket
                            ) {
                                frame.fill(0)
                                return@execute
                            }
                            try {
                                val nowUnixMs = System.currentTimeMillis()
                                when (val message = RelayDeliveryCodecV1.decodeServerMessage(frame)) {
                                    is RelayServerMessageV1.OnlineEnvelope -> {
                                        val receipt = handlers.actionDispatcher.receiveAnyOnce(
                                            message.envelope,
                                            nowUnixMs,
                                        )
                                        respondToSnapshotRequest(receipt)
                                    }
                                    is RelayServerMessageV1.Delivery -> {
                                        val cursor = relayDeliveryCursorStore.load(
                                            credential.workspaceId,
                                            credential.deviceId,
                                        )
                                        check(cursor.snapshotRequiredHighWater == null) {
                                            "Relay delivery requires snapshot reconciliation"
                                        }
                                        check(message.deliveryId == Math.addExact(
                                            cursor.committedDeliveryId,
                                            1L,
                                        )) { "Relay deliveries are not contiguous" }
                                        val receipt = handlers.actionDispatcher.receiveAnyOnce(
                                            message.envelope,
                                            nowUnixMs,
                                            allowSnapshotRequestReplayDuplicate = true,
                                        )
                                        respondToSnapshotRequest(receipt)
                                        // Dispatch returns only after the exact action result, ACK,
                                        // or complete online snapshot response is accepted locally.
                                        // Cursor commit therefore comes last.
                                        val committed = relayDeliveryCursorStore.commitDelivery(
                                            credential.workspaceId,
                                            credential.deviceId,
                                            message.deliveryId,
                                        )
                                        val acknowledgement =
                                            RelayDeliveryCodecV1.encodeAcknowledgement(
                                                committed.committedDeliveryId,
                                            )
                                        val accepted = try {
                                            webSocket.send(ByteString.of(*acknowledgement))
                                        } finally {
                                            acknowledgement.fill(0)
                                        }
                                        if (!accepted) {
                                            webSocket.cancel()
                                            enqueueTermination(requestedGeneration, webSocket)
                                            return@execute
                                        }
                                    }
                                    is RelayServerMessageV1.CaughtUp -> {
                                        val cursor = relayDeliveryCursorStore.load(
                                            credential.workspaceId,
                                            credential.deviceId,
                                        )
                                        check(cursor.snapshotRequiredHighWater == null &&
                                            message.highWater == cursor.committedDeliveryId
                                        ) { "Relay caught-up marker does not match committed cursor" }
                                    }
                                    is RelayServerMessageV1.SnapshotRequired -> {
                                        relayDeliveryCursorStore.requireSnapshot(
                                            credential.workspaceId,
                                            credential.deviceId,
                                            message.highWater,
                                        )
                                    }
                                }
                                cancelResultDrain()
                                drainResults(
                                    requestedGeneration,
                                    webSocket,
                                    handlers.resultDrainer,
                                )
                            } catch (_: Throwable) {
                                rejectInbound(requestedGeneration, webSocket)
                            } finally {
                                frame.fill(0)
                            }
                        }
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        enqueueTermination(
                            requestedGeneration,
                            webSocket,
                            credentialSource,
                            receivedSno1.get(),
                            handlers,
                        )
                    }

                    override fun onFailure(
                        webSocket: WebSocket,
                        error: Throwable,
                        response: Response?,
                    ) {
                        enqueueTermination(
                            requestedGeneration,
                            webSocket,
                            credentialSource,
                            receivedSno1.get(),
                            handlers,
                        )
                    }
                },
            )
            if (generation.get() != requestedGeneration) {
                handlers.clearIdentities()
                socket.close(1000, "superseded connection")
                return
            }
            webSocket = socket
        } catch (error: Throwable) {
            if (generation.get() == requestedGeneration) {
                if (error is IOException) {
                    // The endpoint could not be reached, which is exactly what the reconnect path
                    // exists for. Parking here would strand a device whose credentials are fine.
                    diagnostics.recordFailure(
                        CoordinatorDiagnosticEvent.LOCAL_FAILURE_RETRY,
                        requestedGeneration,
                        error,
                    )
                    mutableState.value = AndroidTransportState.OFFLINE
                    scheduleReconnect(requestedGeneration)
                } else {
                    // A local credential or identity failure cannot be repaired by retrying on its
                    // own, so it parks here and is re-armed when the application is opened again.
                    enterSecurityError(requestedGeneration, error, AndroidSecurityRecovery.NONE)
                }
            }
        } finally {
            credential.authToken.fill(0)
        }
    }

    private fun sendNotification(
        createFrames: (NotificationEnvelopeSender, Long) -> List<ByteArray>?,
    ) = sendNotifications(createFrames = createFrames)

    private fun sendSnapshot(
        snapshot: ActiveNotificationSnapshot,
        recoveryRequestId: ByteArray? = null,
        recipientDeviceId: ByteArray? = null,
        durable: Boolean = true,
    ): Boolean = sendNotifications(durable) { sender, nowUnixMs ->
        val byId = snapshot.notifications.associateBy(NotificationSnapshot::key)
        val frames = mutableListOf<ByteArray>()
        for (id in NotificationEnvelopeSender.canonicalNotificationIds(byId.keys)) {
            val notification = requireNotNull(byId[id])
            val notificationFrames = sender.createUpsert(
                notificationId = notification.key,
                revision = notification.revision,
                sourceApplicationId = notification.packageName,
                sourceApplicationName = notification.appName,
                title = notification.title,
                body = notification.expandedText ?: notification.text,
                appIcon = notification.appIcon?.toProtocol(),
                avatar = notification.avatar?.toProtocol(),
                containsContentImage = notification.containsContentImage,
                actions = notification.protocolActions(),
                nowUnixMs = nowUnixMs,
                recipientDeviceId = recipientDeviceId,
            )
            if (notificationFrames == null) {
                frames.forEach { it.fill(0) }
                return@sendNotifications null
            }
            frames += notificationFrames
        }
        val manifestFrames = sender.createSnapshotManifest(
            snapshot.highWaterRevision,
            snapshot.notifications.associate { it.key to it.revision },
            nowUnixMs,
            recoveryRequestId,
            recipientDeviceId,
        )
        if (manifestFrames == null) {
            frames.forEach { it.fill(0) }
            return@sendNotifications null
        }
        frames + manifestFrames
    }

    private fun respondToSnapshotRequest(receipt: AuthenticatedInboundReceipt) {
        if (receipt !is AuthenticatedInboundReceipt.SnapshotRequest) return
        val snapshot = checkNotNull(LocalNotificationController.currentActiveSnapshot(applicationContext)) {
            "Notification snapshot is not ready"
        }
        check(sendSnapshot(
            snapshot = snapshot,
            recoveryRequestId = receipt.recoveryRequestId,
            recipientDeviceId = receipt.requesterDeviceId,
            durable = false,
        )) { "Snapshot recovery response was not accepted locally" }
    }

    private fun sendNotifications(
        durable: Boolean = true,
        createFrames: (NotificationEnvelopeSender, Long) -> List<ByteArray>?,
    ): Boolean {
        if (productPreferences.isSynchronizationPaused()) return false
        if (mutableState.value != AndroidTransportState.ONLINE) return false
        val socket = webSocket ?: return false
        var sender: NotificationEnvelopeSender? = null
        var identity: AuthenticatedHpke.KeyPair? = null
        val credential = try {
            credentialStore.load()
        } catch (_: Throwable) {
            rejectInbound(generation.get(), socket)
            return false
        } ?: return false
        try {
            val loadedIdentity = checkNotNull(identityStore.loadExisting()) {
                "Transport credential exists without its bound E2EE identity"
            }
            identity = loadedIdentity
            check(
                MessageDigest.isEqual(
                    MessageDigest.getInstance("SHA-256").digest(loadedIdentity.publicKey),
                    credential.identityKeyId,
                ),
            ) { "Transport credential E2EE identity binding does not match" }
            sender = NotificationEnvelopeSender(
                workspaceId = credential.workspaceId,
                senderDeviceId = credential.deviceId,
                senderIdentity = loadedIdentity,
                recipients = recipientSelection,
                allocateSequence = resultOutbox::allocateSequence,
            )
            val frames = createFrames(sender, System.currentTimeMillis()) ?: return false
            try {
                for (frame in frames) {
                    val outbound = if (durable) {
                        RelayDeliveryCodecV1.encodeDurableSubmission(frame)
                    } else {
                        frame
                    }
                    val accepted = try {
                        socket.send(ByteString.of(*outbound))
                    } finally {
                        if (outbound !== frame) outbound.fill(0)
                    }
                    if (!accepted) {
                        socket.cancel()
                        enqueueTermination(generation.get(), socket)
                        return false
                    }
                }
                return true
            } finally {
                frames.forEach { it.fill(0) }
            }
        } catch (_: Throwable) {
            rejectInbound(generation.get(), socket)
            return false
        } finally {
            sender?.clearIdentity()
            identity?.privateKey?.fill(0)
            identity?.publicKey?.fill(0)
            credential.authToken.fill(0)
        }
    }

    private fun enqueueInboundRejection(requestedGeneration: Long, socket: WebSocket) {
        executor.execute { rejectInbound(requestedGeneration, socket) }
    }

    private fun rejectInbound(requestedGeneration: Long, socket: WebSocket) {
        if (generation.get() != requestedGeneration || terminalGeneration == requestedGeneration) {
            return
        }
        terminalGeneration = requestedGeneration
        cancelResultDrain()
        if (webSocket === socket) webSocket = null
        // Parking is deliberate here rather than a retry: a frame this device cannot verify means
        // the socket's trust is gone, and stopping keeps that visible instead of hiding it behind
        // an endless reconnect. The cause is still unclassified, so the state never reaches the
        // recovery page and the main screen keeps offering a reconnect.
        mutableSecurityRecovery.value = AndroidSecurityRecovery.NONE
        mutableState.value = AndroidTransportState.SECURITY_ERROR
        socket.close(1008, "encrypted envelope rejected")
    }

    private fun enqueueTermination(
        requestedGeneration: Long,
        socket: WebSocket,
        credentialSource: CredentialCandidateSource = CredentialCandidateSource.CURRENT,
        receivedSno1: Boolean = true,
        handlers: ConnectionHandlers? = null,
    ) {
        diagnostics.record(CoordinatorDiagnosticEvent.TERMINATION_QUEUED, requestedGeneration)
        executor.execute {
            handlers?.clearIdentities()
            if (generation.get() != requestedGeneration ||
                terminalGeneration == requestedGeneration
            ) {
                return@execute
            }
            terminalGeneration = requestedGeneration
            if (!receivedSno1) {
                preferCurrentFallback = credentialSource == CredentialCandidateSource.PENDING
            }
            cancelResultDrain()
            cancelMembershipRefresh()
            if (webSocket === socket) webSocket = null
            mutableState.value = AndroidTransportState.OFFLINE
            diagnostics.record(CoordinatorDiagnosticEvent.CONNECTION_TERMINATED, requestedGeneration)
            scheduleReconnect(requestedGeneration)
        }
    }

    private fun drainResults(
        requestedGeneration: Long,
        socket: WebSocket,
        drainer: ActionResultOutboxDrainer,
    ) {
        if (generation.get() != requestedGeneration || webSocket !== socket) return
        val result = try {
            drainer.drainDue(System.currentTimeMillis()) { frame ->
                val durable = RelayDeliveryCodecV1.encodeDurableSubmission(frame)
                try {
                    socket.send(ByteString.of(*durable))
                } finally {
                    durable.fill(0)
                }
            }
        } catch (_: Throwable) {
            rejectInbound(requestedGeneration, socket)
            return
        }
        if (result.attemptedEntries > result.acceptedSends) {
            socket.cancel()
            enqueueTermination(requestedGeneration, socket)
            return
        }
        val nextWakeDelayMs = result.nextWakeDelayMs
        if (nextWakeDelayMs != null && resultDrainFuture == null) {
            resultDrainFuture = executor.schedule(
                {
                    resultDrainFuture = null
                    drainResults(requestedGeneration, socket, drainer)
                },
                nextWakeDelayMs,
                TimeUnit.MILLISECONDS,
            )
        }
    }

    private fun scheduleMembershipRefresh(requestedGeneration: Long, socket: WebSocket) {
        if (generation.get() != requestedGeneration || webSocket !== socket ||
            membershipRefreshFuture != null
        ) return
        membershipRefreshFuture = executor.schedule(
            {
                membershipRefreshFuture = null
                if (generation.get() != requestedGeneration || webSocket !== socket ||
                    mutableState.value != AndroidTransportState.ONLINE
                ) return@schedule
                val credential = try {
                    credentialStore.load()
                } catch (error: Throwable) {
                    terminalGeneration = requestedGeneration
                    if (webSocket === socket) webSocket = null
                    handleLocalFailure(requestedGeneration, error, securityRecoveryForCredentialReadFailure(error))
                    socket.close(1008, "membership trust refresh failed")
                    return@schedule
                }
                if (credential == null) {
                    terminalGeneration = requestedGeneration
                    if (webSocket === socket) webSocket = null
                    // The credential disappeared while a connection was up, which no retry of this
                    // socket can fix. Rebuilding the connection re-reads it and lands on the join
                    // flow if it is really gone, so nothing here is worth parking for.
                    enterSecurityError(
                        requestedGeneration,
                        IllegalStateException("Membership trust refresh lost the local credential"),
                        AndroidSecurityRecovery.NONE,
                    )
                    socket.close(1008, "membership trust refresh failed")
                    return@schedule
                }
                try {
                    val refreshed = diagnostics.measure(
                        CoordinatorDiagnosticEvent.MEMBERSHIP_REFRESH,
                        requestedGeneration,
                    ) { membershipClient.refreshActive(credential) }
                    if (refreshed == null) return@schedule
                    check(refreshed.serverState == "approved" && refreshed.transportEligible) {
                        "Local device is not active in the durable workspace roster"
                    }
                    publishWorkspaceDevices(credential.workspaceId, credential.deviceId)
                } catch (_: IOException) {
                    scheduleMembershipRefresh(requestedGeneration, socket)
                    return@schedule
                } catch (error: Throwable) {
                    terminalGeneration = requestedGeneration
                    if (webSocket === socket) webSocket = null
                    enterSecurityError(
                        requestedGeneration,
                        error,
                        certifiedRemovalRecovery(
                            credential.workspaceId,
                            credential.deviceId,
                        ),
                    )
                    socket.close(1008, "membership trust refresh failed")
                    return@schedule
                } finally {
                    credential.authToken.fill(0)
                }
                scheduleMembershipRefresh(requestedGeneration, socket)
            },
            MEMBERSHIP_REFRESH_INTERVAL_MS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelMembershipRefresh() {
        membershipRefreshFuture?.cancel(false)
        membershipRefreshFuture = null
    }

    private fun publishWorkspaceDevices(workspaceId: ByteArray, localDeviceId: ByteArray) {
        val nowUnixMs = System.currentTimeMillis()
        mutableWorkspaceDevices.value = workspaceMembershipStore.listAuthorizedDevices(
            workspaceId,
            localDeviceId,
            nowUnixMs,
        )
        mutableRecipientSettings.value = recipientSelection.settings(
            workspaceId,
            localDeviceId,
            nowUnixMs,
        )
    }

    /**
     * Reacts to a failure without inventing a terminal state for it: [recovery] of
     * [AndroidSecurityRecovery.NONE] means nothing has proven the failure permanent, so the
     * connection is re-armed instead of parked. It is also where [enterSecurityError] sends an
     * unclassified cause, so every way out of a failure that is not a missing enrollment ends here.
     */
    private fun handleLocalFailure(
        requestedGeneration: Long,
        error: Throwable,
        recovery: AndroidSecurityRecovery,
    ) {
        if (recovery == AndroidSecurityRecovery.NONE) {
            diagnostics.recordFailure(
                CoordinatorDiagnosticEvent.LOCAL_FAILURE_RETRY,
                requestedGeneration,
                error,
            )
            mutableState.value = AndroidTransportState.OFFLINE
            scheduleReconnect(requestedGeneration)
            return
        }
        enterSecurityError(requestedGeneration, error, recovery)
    }

    /**
     * Parks the transport on the recovery page, recording which failure did it.
     *
     * Only a cause this device cannot repair alone parks here, and the page it leads to is built
     * around that: it offers no retry at all. An unclassified failure would therefore strand a
     * healthy device until its process dies, so it is re-armed instead. Reaching the recovery page
     * always means the enrollment itself is gone, which is what makes it distinct from an
     * interrupted connection rather than another way of showing one.
     */
    private fun enterSecurityError(
        requestedGeneration: Long,
        error: Throwable,
        recovery: AndroidSecurityRecovery,
    ) {
        if (recovery == AndroidSecurityRecovery.NONE) {
            handleLocalFailure(requestedGeneration, error, recovery)
            return
        }
        diagnostics.recordFailure(
            CoordinatorDiagnosticEvent.SECURITY_ERROR_ENTERED,
            requestedGeneration,
            error,
            recovery,
        )
        mutableSecurityRecovery.value = recovery
        mutableState.value = AndroidTransportState.SECURITY_ERROR
    }

    private fun certifiedRemovalRecovery(
        workspaceId: ByteArray,
        deviceId: ByteArray,
    ): AndroidSecurityRecovery = runCatching {
        securityRecoveryForLocalMembership(
            workspaceMembershipStore.load(workspaceId, deviceId)?.localDeviceActive,
        )
    }.getOrDefault(AndroidSecurityRecovery.NONE)

    private fun completeCertifiedReEnrollmentReset() {
        resultOutbox.clear()
        operationLedger.clear()
        replayLedger.clear()
        relayDeliveryCursorStore.clear()
        pendingMembershipStore.clear()
        credentialStore.clear()
        identityStore.clear()
        workspaceMembershipStore.clear()
        recipientSelection.clear()
        productPreferences.finishCertifiedReEnrollmentReset()
        mutableEnrollmentPending.value = false
        mutableWorkspaceDevices.value = emptyList()
        mutableRecipientSettings.value = RecipientSettingsState("", false, emptyList())
        mutableServerOrigin.value = null
        mutableSecurityRecovery.value = AndroidSecurityRecovery.NONE
    }

    private fun recoverPendingMembership(): Boolean {
        val observed = pendingMembershipStore.load()
        if (observed == null) {
            mutableEnrollmentPending.value = false
            return true
        }
        mutableEnrollmentPending.value = true
        observed.pending.authToken.fill(0)
        observed.canonicalProof?.fill(0)
        val identity = checkNotNull(identityStore.loadExisting()) {
            "Pending membership enrollment has no local identity"
        }
        try {
            val refreshed = membershipClient.resume(identity)
            if (refreshed.serverState != "approved") return false
            check(refreshed.transportEligible) {
                "Approved local device is not active in the durable workspace roster"
            }
            membershipPromotionCoordinator.promoteApproved().authToken.fill(0)
            mutableEnrollmentPending.value = false
            return true
        } finally {
            identity.publicKey.fill(0)
            identity.privateKey.fill(0)
        }
    }

    private fun scheduleReconnect(requestedGeneration: Long) {
        if (!hasConnectionOwner() || generation.get() != requestedGeneration || reconnectFuture != null) return
        val delayMs = reconnectBackoff.nextDelayMs()
        diagnostics.record(CoordinatorDiagnosticEvent.RECONNECT_SCHEDULED, requestedGeneration, delayMs = delayMs)
        reconnectFuture = executor.schedule(
            {
                reconnectFuture = null
                if (generation.get() != requestedGeneration) return@schedule
                diagnostics.record(CoordinatorDiagnosticEvent.RECONNECT_TIMER_FIRED, requestedGeneration)
                val nextGeneration = generation.incrementAndGet()
                connectInternal(nextGeneration)
            },
            delayMs,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelReconnect() {
        reconnectFuture?.cancel(false)
        reconnectFuture = null
        cancelResultDrain()
    }

    private fun cancelResultDrain() {
        resultDrainFuture?.cancel(false)
        resultDrainFuture = null
    }

    private data class ConnectionHandlers(
        val actionDispatcher: AndroidActionInvokeDispatcher,
        val resultDrainer: ActionResultOutboxDrainer,
    ) {
        fun clearIdentities() {
            actionDispatcher.clearIdentity()
            resultDrainer.clearIdentity()
        }
    }

    private fun stateAfterRegistrationFailure(): AndroidTransportState = try {
        val stored = credentialStore.load()
        try {
            if (stored == null) AndroidTransportState.NOT_CONFIGURED else AndroidTransportState.OFFLINE
        } finally {
            stored?.authToken?.fill(0)
        }
    } catch (error: Throwable) {
        // Recorded so a stuck device can be diagnosed, and classified as unclassified on purpose:
        // nothing here has proven the stored credential permanently unreadable, and only an
        // unclassified security error re-arms instead of parking, so a failed registration attempt
        // never leaves the device on the recovery page.
        diagnostics.recordFailure(
            CoordinatorDiagnosticEvent.SECURITY_ERROR_ENTERED,
            generation.get(),
            error,
            AndroidSecurityRecovery.NONE,
        )
        mutableSecurityRecovery.value = AndroidSecurityRecovery.NONE
        AndroidTransportState.SECURITY_ERROR
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        left.indices.forEach { difference = difference or (left[it].toInt() xor right[it].toInt()) }
        return difference == 0
    }
}
