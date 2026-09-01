package dev.notificationmirroring.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Handler
import android.os.Looper
import dev.notificationmirroring.crypto.AndroidActionResultOutbox
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidOperationLedger
import dev.notificationmirroring.crypto.AndroidReplayLedger
import dev.notificationmirroring.crypto.AndroidWorkspaceMembershipStore
import dev.notificationmirroring.crypto.ActionResultOutboxDrainer
import dev.notificationmirroring.crypto.AuthenticatedHpke
import dev.notificationmirroring.crypto.NotificationEnvelopeSender
import dev.notificationmirroring.crypto.WorkspaceDeviceSummary
import dev.notificationmirroring.notification.ActiveNotificationSnapshot
import dev.notificationmirroring.notification.AndroidActionInvokeDispatcher
import dev.notificationmirroring.notification.AuthenticatedInboundReceipt
import dev.notificationmirroring.notification.LocalNotificationController
import dev.notificationmirroring.notification.NotificationActionDescriptor
import dev.notificationmirroring.notification.NotificationMedia
import dev.notificationmirroring.notification.NotificationMediaMimeType
import dev.notificationmirroring.notification.NotificationSnapshot
import dev.notificationmirroring.notification.RemoteOperationAuthorizer
import dev.notificationmirroring.protocol.EncryptedPayloadCodecV1
import dev.notificationmirroring.protocol.generated.v1.NotificationActionDescriptor as ProtocolNotificationActionDescriptor
import dev.notificationmirroring.protocol.generated.v1.NotificationMedia as ProtocolNotificationMedia
import dev.notificationmirroring.protocol.generated.v1.NotificationMediaMimeType as ProtocolNotificationMediaMimeType
import dev.notificationmirroring.transport.AndroidMembershipRegistration
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.AndroidPendingMembershipStore
import dev.notificationmirroring.transport.AndroidRelayDeliveryCursorStore
import dev.notificationmirroring.transport.AuthenticatedWebSocketFactory
import dev.notificationmirroring.transport.BoundedReconnectBackoff
import dev.notificationmirroring.transport.CredentialCandidateSource
import dev.notificationmirroring.transport.MembershipTransportPromotionCoordinator
import dev.notificationmirroring.transport.RelayDeliveryCodecV1
import dev.notificationmirroring.transport.RelayServerMessageV1
import dev.notificationmirroring.transport.TransportCredentialRotationClient
import dev.notificationmirroring.transport.WorkspaceMembershipClient
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
}

internal fun securityRecoveryForLocalMembership(
    localDeviceActive: Boolean?,
): AndroidSecurityRecovery = if (localDeviceActive == false) {
    AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL
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
    private val webSocketFactory = AuthenticatedWebSocketFactory(httpClient)
    private val executor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "notification-transport").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val generation = AtomicLong()
    private val reconnectBackoff = BoundedReconnectBackoff()
    private val mutableState = MutableStateFlow(AndroidTransportState.INITIALIZING)
    private val mutableEnrollmentPending = MutableStateFlow(false)
    private val mutableWorkspaceDevices = MutableStateFlow<List<WorkspaceDeviceSummary>>(emptyList())
    private val mutableServerOrigin = MutableStateFlow<String?>(null)
    private val mutableSecurityRecovery = MutableStateFlow(AndroidSecurityRecovery.NONE)

    private var webSocket: WebSocket? = null
    private var reconnectFuture: ScheduledFuture<*>? = null
    private var resultDrainFuture: ScheduledFuture<*>? = null
    private var membershipRefreshFuture: ScheduledFuture<*>? = null
    private var terminalGeneration = Long.MIN_VALUE
    private var preferCurrentFallback = false

    val state: StateFlow<AndroidTransportState> = mutableState.asStateFlow()
    val enrollmentPending: StateFlow<Boolean> = mutableEnrollmentPending.asStateFlow()
    val workspaceDevices: StateFlow<List<WorkspaceDeviceSummary>> =
        mutableWorkspaceDevices.asStateFlow()
    val serverOrigin: StateFlow<String?> = mutableServerOrigin.asStateFlow()
    val securityRecovery: StateFlow<AndroidSecurityRecovery> =
        mutableSecurityRecovery.asStateFlow()

    fun syntheticResultOutboxSnapshot(): AndroidActionResultOutbox.Snapshot =
        resultOutbox.snapshot(System.currentTimeMillis())

    fun mirrorSyntheticNotification(snapshot: NotificationSnapshot) {
        executor.execute {
            sendSyntheticNotification { sender, nowUnixMs ->
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

    fun removeSyntheticNotification(notificationId: String, revision: Long) {
        executor.execute {
            sendSyntheticNotification { sender, nowUnixMs ->
                sender.createRemoved(notificationId, revision, nowUnixMs)
            }
        }
    }

    fun mirrorSyntheticSnapshot(snapshot: ActiveNotificationSnapshot) {
        executor.execute { sendSyntheticSnapshot(snapshot) }
    }

    init {
        applicationContext.getSystemService(ConnectivityManager::class.java)
            .registerDefaultNetworkCallback(
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        if (mutableState.value == AndroidTransportState.OFFLINE) connect()
                    }
                },
            )
    }

    /** Explicit and network-available requests connect immediately and reset stale backoff state. */
    fun connect() {
        val requestedGeneration = generation.incrementAndGet()
        executor.execute {
            cancelReconnect()
            reconnectBackoff.reset()
            connectInternal(requestedGeneration)
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

    fun reEnrollAfterCertifiedRemoval() {
        val requestedGeneration = generation.incrementAndGet()
        mutableState.value = AndroidTransportState.INITIALIZING
        executor.execute {
            cancelReconnect()
            cancelMembershipRefresh()
            webSocket?.close(1000, "device re-enrollment")
            webSocket = null
            try {
                check(mutableSecurityRecovery.value == AndroidSecurityRecovery.CERTIFIED_DEVICE_REMOVAL) {
                    "Re-enrollment requires a certified device removal"
                }
                productPreferences.beginCertifiedReEnrollmentReset()
                completeCertifiedReEnrollmentReset()
                connectInternal(requestedGeneration)
            } catch (_: Throwable) {
                mutableState.value = AndroidTransportState.SECURITY_ERROR
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
            } catch (_: Throwable) {
                mutableState.value = AndroidTransportState.SECURITY_ERROR
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
        if (generation.get() != requestedGeneration) return
        if (productPreferences.isCertifiedReEnrollmentResetPending()) {
            try {
                completeCertifiedReEnrollmentReset()
            } catch (_: Throwable) {
                mutableState.value = AndroidTransportState.SECURITY_ERROR
                return
            }
        }
        mutableSecurityRecovery.value = AndroidSecurityRecovery.NONE
        terminalGeneration = Long.MIN_VALUE
        webSocket?.close(1000, "replaced by new connection")
        webSocket = null
        cancelMembershipRefresh()
        val membershipReady = try {
            recoverPendingMembership()
        } catch (_: IOException) {
            mutableState.value = AndroidTransportState.OFFLINE
            scheduleReconnect(requestedGeneration)
            return
        } catch (_: Throwable) {
            mutableState.value = AndroidTransportState.SECURITY_ERROR
            return
        }
        if (!membershipReady) {
            mutableState.value = AndroidTransportState.REGISTERING
            scheduleReconnect(requestedGeneration)
            return
        }
        val candidate = try {
            credentialStore.loadConnectionCandidate(preferCurrentFallback)
        } catch (_: Throwable) {
            mutableState.value = AndroidTransportState.SECURITY_ERROR
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
            val refreshed = membershipClient.refreshActive(credential)
            check(refreshed == null ||
                refreshed.serverState == "approved" && refreshed.transportEligible
            ) { "Local device is not active in the durable workspace roster" }
            publishWorkspaceDevices(credential.workspaceId, credential.deviceId)
        } catch (_: IOException) {
            credential.authToken.fill(0)
            mutableState.value = AndroidTransportState.OFFLINE
            scheduleReconnect(requestedGeneration)
            return
        } catch (_: Throwable) {
            mutableSecurityRecovery.value = certifiedRemovalRecovery(
                credential.workspaceId,
                credential.deviceId,
            )
            credential.authToken.fill(0)
            mutableState.value = AndroidTransportState.SECURITY_ERROR
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
            mutableState.value = AndroidTransportState.CONNECTING
            val receivedSno1 = AtomicBoolean(false)
            val socket = webSocketFactory.open(
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
                                scheduleMembershipRefresh(requestedGeneration, webSocket)
                                cancelResultDrain()
                                drainResults(requestedGeneration, webSocket, handlers.resultDrainer)
                                LocalNotificationController.currentActiveSnapshot(applicationContext)
                                    ?.let { snapshot -> sendSyntheticSnapshot(snapshot) }
                            } catch (_: Throwable) {
                                terminalGeneration = requestedGeneration
                                cancelResultDrain()
                                if (this@AndroidTransportCoordinator.webSocket === webSocket) {
                                    this@AndroidTransportCoordinator.webSocket = null
                                }
                                mutableState.value = AndroidTransportState.SECURITY_ERROR
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
        } catch (_: Throwable) {
            if (generation.get() == requestedGeneration) {
                // Local credential/identity/endpoint failures require explicit recovery.
                mutableState.value = AndroidTransportState.SECURITY_ERROR
            }
        } finally {
            credential.authToken.fill(0)
        }
    }

    private fun sendSyntheticNotification(
        createFrames: (NotificationEnvelopeSender, Long) -> List<ByteArray>?,
    ) = sendSyntheticNotifications(createFrames = createFrames)

    private fun sendSyntheticSnapshot(
        snapshot: ActiveNotificationSnapshot,
        recoveryRequestId: ByteArray? = null,
        recipientDeviceId: ByteArray? = null,
        durable: Boolean = true,
    ): Boolean = sendSyntheticNotifications(durable) { sender, nowUnixMs ->
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
                return@sendSyntheticNotifications null
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
            return@sendSyntheticNotifications null
        }
        frames + manifestFrames
    }

    private fun respondToSnapshotRequest(receipt: AuthenticatedInboundReceipt) {
        if (receipt !is AuthenticatedInboundReceipt.SnapshotRequest) return
        val snapshot = checkNotNull(LocalNotificationController.currentActiveSnapshot(applicationContext)) {
            "Notification snapshot is not ready"
        }
        check(sendSyntheticSnapshot(
            snapshot = snapshot,
            recoveryRequestId = receipt.recoveryRequestId,
            recipientDeviceId = receipt.requesterDeviceId,
            durable = false,
        )) { "Snapshot recovery response was not accepted locally" }
    }

    private fun sendSyntheticNotifications(
        durable: Boolean = true,
        createFrames: (NotificationEnvelopeSender, Long) -> List<ByteArray>?,
    ): Boolean {
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
                recipients = workspaceMembershipStore,
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
                } catch (_: Throwable) {
                    null
                }
                if (credential == null) {
                    terminalGeneration = requestedGeneration
                    if (webSocket === socket) webSocket = null
                    mutableState.value = AndroidTransportState.SECURITY_ERROR
                    socket.close(1008, "membership trust refresh failed")
                    return@schedule
                }
                try {
                    val refreshed = membershipClient.refreshActive(credential)
                    if (refreshed == null) return@schedule
                    check(refreshed.serverState == "approved" && refreshed.transportEligible) {
                        "Local device is not active in the durable workspace roster"
                    }
                    publishWorkspaceDevices(credential.workspaceId, credential.deviceId)
                } catch (_: IOException) {
                    scheduleMembershipRefresh(requestedGeneration, socket)
                    return@schedule
                } catch (_: Throwable) {
                    terminalGeneration = requestedGeneration
                    if (webSocket === socket) webSocket = null
                    mutableSecurityRecovery.value = certifiedRemovalRecovery(
                        credential.workspaceId,
                        credential.deviceId,
                    )
                    mutableState.value = AndroidTransportState.SECURITY_ERROR
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
        mutableWorkspaceDevices.value = workspaceMembershipStore.listAuthorizedDevices(
            workspaceId,
            localDeviceId,
            System.currentTimeMillis(),
        )
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
        productPreferences.finishCertifiedReEnrollmentReset()
        mutableEnrollmentPending.value = false
        mutableWorkspaceDevices.value = emptyList()
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
        if (generation.get() != requestedGeneration || reconnectFuture != null) return
        val delayMs = reconnectBackoff.nextDelayMs()
        reconnectFuture = executor.schedule(
            {
                reconnectFuture = null
                if (generation.get() != requestedGeneration) return@schedule
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
    } catch (_: Throwable) {
        AndroidTransportState.SECURITY_ERROR
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        left.indices.forEach { difference = difference or (left[it].toInt() xor right[it].toInt()) }
        return difference == 0
    }
}
