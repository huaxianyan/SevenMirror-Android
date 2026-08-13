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
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.ActionResultOutboxDrainer
import dev.notificationmirroring.notification.AndroidActionInvokeDispatcher
import dev.notificationmirroring.transport.AndroidDeviceRegistration
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.AuthenticatedWebSocketFactory
import dev.notificationmirroring.transport.BoundedReconnectBackoff
import dev.notificationmirroring.transport.DeviceRegistrationClient
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

enum class AndroidTransportState {
    NOT_CONFIGURED,
    REGISTERING,
    CONNECTING,
    ONLINE,
    OFFLINE,
    SECURITY_ERROR,
}

/** Process-lifetime transport owner with serialized, fail-closed encrypted action dispatch. */
class AndroidTransportCoordinator(context: Context) {
    private val applicationContext = context.applicationContext
    private val identityStore = AndroidHpkeIdentityStore(applicationContext)
    private val credentialStore = AndroidTransportCredentialStore(applicationContext)
    private val trustedPeerStore = AndroidTrustedPeerStore(applicationContext)
    private val replayLedger = AndroidReplayLedger(applicationContext)
    private val operationLedger = AndroidOperationLedger(applicationContext)
    private val resultOutbox = AndroidActionResultOutbox(applicationContext)
    private val httpClient = OkHttpClient()
    private val registrationClient = DeviceRegistrationClient(httpClient, credentialStore)
    private val webSocketFactory = AuthenticatedWebSocketFactory(httpClient)
    private val executor = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "notification-transport").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val generation = AtomicLong()
    private val reconnectBackoff = BoundedReconnectBackoff()
    private val mutableState = MutableStateFlow(AndroidTransportState.NOT_CONFIGURED)

    private var webSocket: WebSocket? = null
    private var reconnectFuture: ScheduledFuture<*>? = null
    private var resultDrainFuture: ScheduledFuture<*>? = null
    private var terminalGeneration = Long.MIN_VALUE

    val state: StateFlow<AndroidTransportState> = mutableState.asStateFlow()

    fun syntheticResultOutboxSnapshot(): AndroidActionResultOutbox.Snapshot =
        resultOutbox.snapshot(System.currentTimeMillis())

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
        mutableState.value = AndroidTransportState.REGISTERING
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
                val identityKeyId = MessageDigest.getInstance("SHA-256").digest(identity.publicKey)
                val credential = try {
                    registrationClient.register(
                        AndroidDeviceRegistration(
                            serverOrigin = serverOrigin,
                            pairingCode = pairingCode,
                            deviceName = deviceName,
                            e2eePublicKey = identity.publicKey,
                            identityKeyId = identityKeyId,
                        ),
                    )
                } finally {
                    identity.publicKey.fill(0)
                    identity.privateKey.fill(0)
                }
                credential.authToken.fill(0)
                success = true
                connectInternal(requestedGeneration)
            } catch (_: Throwable) {
                if (generation.get() == requestedGeneration) {
                    mutableState.value = stateAfterRegistrationFailure()
                }
            } finally {
                mainHandler.post { completed(success) }
            }
        }
    }

    private fun connectInternal(requestedGeneration: Long) {
        if (generation.get() != requestedGeneration) return
        terminalGeneration = Long.MIN_VALUE
        webSocket?.close(1000, "replaced by new connection")
        webSocket = null
        val credential = try {
            credentialStore.load()
        } catch (_: Throwable) {
            mutableState.value = AndroidTransportState.SECURITY_ERROR
            return
        }
        if (credential == null) {
            reconnectBackoff.reset()
            mutableState.value = AndroidTransportState.NOT_CONFIGURED
            return
        }
        try {
            val identity = checkNotNull(identityStore.loadExisting()) {
                "Transport credential exists without its bound E2EE identity"
            }
            val (dispatcher, resultDrainer) = try {
                val keyId = MessageDigest.getInstance("SHA-256").digest(identity.publicKey)
                check(constantTimeEquals(keyId, credential.identityKeyId)) {
                    "Transport credential E2EE identity binding does not match"
                }
                Pair(
                    AndroidActionInvokeDispatcher(
                        context = applicationContext,
                        workspaceId = credential.workspaceId,
                        recipientDeviceId = credential.deviceId,
                        recipientIdentity = identity,
                        trustedPeers = trustedPeerStore,
                        replayLedger = replayLedger,
                        operationLedger = operationLedger,
                        resultOutbox = resultOutbox,
                    ),
                    ActionResultOutboxDrainer(
                        workspaceId = credential.workspaceId,
                        senderDeviceId = credential.deviceId,
                        senderIdentity = identity,
                        trustedPeers = trustedPeerStore,
                        outbox = resultOutbox,
                    ),
                )
            } finally {
                identity.publicKey.fill(0)
                identity.privateKey.fill(0)
            }
            if (generation.get() != requestedGeneration) return
            mutableState.value = AndroidTransportState.CONNECTING
            val socket = webSocketFactory.open(
                credential,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        executor.execute {
                            if (generation.get() == requestedGeneration) {
                                reconnectBackoff.reset()
                                mutableState.value = AndroidTransportState.ONLINE
                                cancelResultDrain()
                                drainResults(requestedGeneration, webSocket, resultDrainer)
                            } else {
                                webSocket.close(1000, "superseded connection")
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
                                dispatcher.receiveOnce(frame, System.currentTimeMillis())
                                // Execution returns only after the exact result is durable.
                                cancelResultDrain()
                                drainResults(requestedGeneration, webSocket, resultDrainer)
                            } catch (_: Throwable) {
                                rejectInbound(requestedGeneration, webSocket)
                            } finally {
                                frame.fill(0)
                            }
                        }
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        enqueueTermination(requestedGeneration, webSocket)
                    }

                    override fun onFailure(
                        webSocket: WebSocket,
                        error: Throwable,
                        response: Response?,
                    ) {
                        enqueueTermination(requestedGeneration, webSocket)
                    }
                },
            )
            if (generation.get() != requestedGeneration) {
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

    private fun enqueueTermination(requestedGeneration: Long, socket: WebSocket) {
        executor.execute {
            if (generation.get() != requestedGeneration ||
                terminalGeneration == requestedGeneration
            ) {
                return@execute
            }
            terminalGeneration = requestedGeneration
            cancelResultDrain()
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
                socket.send(ByteString.of(*frame))
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
