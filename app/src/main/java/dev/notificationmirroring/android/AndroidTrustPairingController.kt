package dev.notificationmirroring.android

import android.content.Context
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import dev.notificationmirroring.crypto.AndroidTrustPairingSessionStore
import dev.notificationmirroring.crypto.AndroidTrustedPeerStore
import dev.notificationmirroring.crypto.LocalTrustIdentity
import dev.notificationmirroring.crypto.TrustPairingCoordinator
import dev.notificationmirroring.crypto.TrustPairingView
import dev.notificationmirroring.transport.AndroidTransportCredentialStore
import java.security.MessageDigest
import java.util.concurrent.Executors
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

sealed interface AndroidTrustPairingState {
    data object Loading : AndroidTrustPairingState
    data object NotConfigured : AndroidTrustPairingState
    data object Idle : AndroidTrustPairingState
    data class OfferCreated(val offerPayload: String, val expiresAtUnixMs: Long) :
        AndroidTrustPairingState
    data class CompareSafetyCode(
        val role: String,
        val safetyCode: String,
        val approvalPayload: String?,
        val expiresAtUnixMs: Long,
    ) : AndroidTrustPairingState
    data object Approved : AndroidTrustPairingState
    data class Error(val message: String) : AndroidTrustPairingState
}

/** UI adapter that binds pairing only to the existing transport credential and HPKE identity. */
class AndroidTrustPairingController(context: Context) {
    private val appContext = context.applicationContext
    private val credentials = AndroidTransportCredentialStore(appContext)
    private val identities = AndroidHpkeIdentityStore(appContext)
    private val sessions = AndroidTrustPairingSessionStore(appContext)
    private val peers = AndroidTrustedPeerStore(appContext)
    private val coordinator = TrustPairingCoordinator(sessions, peers)
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "trust-pairing").apply { isDaemon = true }
    }
    private val mutableState = MutableStateFlow<AndroidTrustPairingState>(AndroidTrustPairingState.Loading)

    val state: StateFlow<AndroidTrustPairingState> = mutableState.asStateFlow()

    fun refresh() = execute {
        val local = loadLocalIdentity() ?: run {
            mutableState.value = AndroidTrustPairingState.NotConfigured
            return@execute
        }
        mutableState.value = coordinator.resume(local)?.toState() ?: AndroidTrustPairingState.Idle
    }

    fun createOffer() = withLocal { local ->
        mutableState.value = coordinator.createOffer(local).toState()
    }

    fun importPayload(payload: String) = withLocal { local ->
        require(payload.length in 1..512) { "Pairing payload length is invalid" }
        val active = sessions.load()
        val view = if (active?.role == dev.notificationmirroring.crypto.TrustPairingRole.OFFERER &&
            active.approvalBytes == null
        ) {
            coordinator.acceptApproval(payload, local)
        } else {
            check(active == null) {
                "Cancel the active pairing before importing another offer"
            }
            coordinator.acceptOffer(payload, local)
        }
        mutableState.value = view.toState()
    }

    fun confirmSafetyCode(safetyCode: String) = withLocal { local ->
        coordinator.confirmSafetyCode(safetyCode, local)
        mutableState.value = AndroidTrustPairingState.Approved
    }

    fun cancel() = execute {
        coordinator.cancel()
        mutableState.value = if (loadLocalIdentity() == null) {
            AndroidTrustPairingState.NotConfigured
        } else {
            AndroidTrustPairingState.Idle
        }
    }

    private fun withLocal(block: (LocalTrustIdentity) -> Unit) = execute {
        val local = loadLocalIdentity()
        checkNotNull(local) { "Register this device before approving E2EE peers" }
        block(local)
    }

    private fun execute(block: () -> Unit) {
        executor.execute {
            try {
                block()
            } catch (_: Throwable) {
                mutableState.value = AndroidTrustPairingState.Error(
                    "Pairing failed closed. Verify the payload, expiry, workspace, and safety code.",
                )
            }
        }
    }

    private fun loadLocalIdentity(): LocalTrustIdentity? {
        val credential = credentials.load() ?: return null
        try {
            val identity = identities.loadExisting()
                ?: error("HPKE identity is missing; refusing pairing")
            try {
                val keyId = MessageDigest.getInstance("SHA-256").digest(identity.publicKey)
                check(MessageDigest.isEqual(keyId, credential.identityKeyId)) {
                    "Transport credential and HPKE identity do not match"
                }
                return LocalTrustIdentity(
                    workspaceId = credential.workspaceId.copyOf(),
                    deviceId = credential.deviceId.copyOf(),
                    publicKey = identity.publicKey.copyOf(),
                )
            } finally {
                identity.publicKey.fill(0)
                identity.privateKey.fill(0)
            }
        } finally {
            credential.authToken.fill(0)
        }
    }

    private fun TrustPairingView.toState(): AndroidTrustPairingState = when (this) {
        is TrustPairingView.OfferCreated -> AndroidTrustPairingState.OfferCreated(
            offerPayload = offerQr,
            expiresAtUnixMs = expiresAtUnixMs,
        )
        is TrustPairingView.CompareSafetyCode -> AndroidTrustPairingState.CompareSafetyCode(
            role = role.name,
            safetyCode = safetyCode,
            approvalPayload = approvalQr,
            expiresAtUnixMs = expiresAtUnixMs,
        )
    }

    init {
        refresh()
    }
}
