package dev.notificationmirroring.android

import android.content.Context
import android.os.Handler
import android.os.Looper
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.transport.AndroidDeviceRegistration
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import dev.notificationmirroring.transport.AuthenticatedWebSocketFactory
import dev.notificationmirroring.transport.DeviceRegistrationClient
import java.security.MessageDigest
import java.util.concurrent.Executors
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

/** Process-lifetime transport owner. Business envelopes remain fail-closed until dispatch is wired. */
class AndroidTransportCoordinator(context: Context) {
    private val identityStore = AndroidHpkeIdentityStore(context)
    private val credentialStore = AndroidTransportCredentialStore(context)
    private val httpClient = OkHttpClient()
    private val registrationClient = DeviceRegistrationClient(httpClient, credentialStore)
    private val webSocketFactory = AuthenticatedWebSocketFactory(httpClient)
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "notification-transport").apply { isDaemon = true }
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val generation = AtomicLong()
    private val mutableState = MutableStateFlow(AndroidTransportState.NOT_CONFIGURED)

    @Volatile
    private var webSocket: WebSocket? = null

    val state: StateFlow<AndroidTransportState> = mutableState.asStateFlow()

    fun connect() {
        val requestedGeneration = generation.incrementAndGet()
        executor.execute { connectInternal(requestedGeneration) }
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
                    mutableState.value = try {
                        if (credentialStore.load() == null) {
                            AndroidTransportState.NOT_CONFIGURED
                        } else {
                            AndroidTransportState.OFFLINE
                        }
                    } catch (_: Throwable) {
                        AndroidTransportState.SECURITY_ERROR
                    }
                }
            } finally {
                mainHandler.post { completed(success) }
            }
        }
    }

    private fun connectInternal(requestedGeneration: Long) {
        if (generation.get() != requestedGeneration) return
        webSocket?.close(1000, "replaced by new connection")
        webSocket = null
        var credential = try {
            credentialStore.load()
        } catch (_: Throwable) {
            mutableState.value = AndroidTransportState.SECURITY_ERROR
            return
        }
        if (credential == null) {
            mutableState.value = AndroidTransportState.NOT_CONFIGURED
            return
        }
        try {
            val identity = checkNotNull(identityStore.loadExisting()) {
                "Transport credential exists without its bound E2EE identity"
            }
            val keyId = try {
                MessageDigest.getInstance("SHA-256").digest(identity.publicKey)
            } finally {
                identity.publicKey.fill(0)
                identity.privateKey.fill(0)
            }
            check(constantTimeEquals(keyId, credential.identityKeyId)) {
                "Transport credential E2EE identity binding does not match"
            }
            if (generation.get() != requestedGeneration) return
            mutableState.value = AndroidTransportState.CONNECTING
            val socket = webSocketFactory.open(
                credential,
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        if (generation.get() == requestedGeneration) {
                            mutableState.value = AndroidTransportState.ONLINE
                        } else {
                            webSocket.close(1000, "superseded connection")
                        }
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        webSocket.close(1008, "relay messages must be binary")
                    }

                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        // Never silently discard an authenticated business envelope.
                        webSocket.close(1008, "encrypted envelope handler unavailable")
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        markOffline(requestedGeneration)
                    }

                    override fun onFailure(webSocket: WebSocket, error: Throwable, response: Response?) {
                        markOffline(requestedGeneration)
                    }
                },
            )
            credential.authToken.fill(0)
            credential = null
            if (generation.get() != requestedGeneration) {
                socket.close(1000, "superseded connection")
                return
            }
            webSocket = socket
        } catch (_: Throwable) {
            credential?.authToken?.fill(0)
            if (generation.get() == requestedGeneration) {
                mutableState.value = AndroidTransportState.SECURITY_ERROR
            }
        }
    }

    private fun markOffline(requestedGeneration: Long) {
        if (generation.get() == requestedGeneration) {
            mutableState.value = AndroidTransportState.OFFLINE
        }
    }

    private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean {
        if (left.size != right.size) return false
        var difference = 0
        left.indices.forEach { difference = difference or (left[it].toInt() xor right[it].toInt()) }
        return difference == 0
    }
}
