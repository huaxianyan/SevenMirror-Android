package dev.notificationmirroring.transport

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.notificationmirroring.crypto.AndroidHpkeIdentityStore
import java.io.File
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSensitiveDataCanaryInstrumentedTest {
    @Test
    fun keystoreWrappedSecretsStayOutOfAppFilesErrorsAndOwnLogcat() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val suffix = System.nanoTime().toString()
        val credentialStore = AndroidTransportCredentialStore(context, "security-canary-$suffix")
        val pendingMembershipStore = AndroidPendingMembershipStore(context, "security-canary-$suffix")
        val identityStore = AndroidHpkeIdentityStore(context, "security-canary-$suffix")
        val currentToken = "sevenmirror-current-token-000001".encodeToByteArray()
        val pendingToken = "sevenmirror-pending-token-000001".encodeToByteArray()
        var identityPrivateKey: ByteArray? = null
        var preparedRotation: StoredCredentialRotation? = null
        var pendingMembership: StoredPendingAndroidMembership? = null

        credentialStore.clear()
        pendingMembershipStore.clear()
        identityStore.clear()
        try {
            val identity = identityStore.loadOrCreate()
            identityPrivateKey = identity.privateKey
            val credential = StoredTransportCredential(
                serverOrigin = "https://canary.example",
                workspaceId = ByteArray(16) { 0x21 },
                deviceId = ByteArray(16) { 0x32 },
                authToken = currentToken,
                identityKeyId = ByteArray(32) { 0x43 },
            )
            credentialStore.saveNew(credential)
            preparedRotation = credentialStore.prepareRotation(pendingToken)

            val enrollment = PendingAndroidMembership(
                serverOrigin = credential.serverOrigin,
                workspaceId = credential.workspaceId,
                deviceId = credential.deviceId,
                authToken = currentToken,
                identityKeyId = credential.identityKeyId,
            )
            pendingMembership = pendingMembershipStore.prepareRegistration(
                enrollment,
                authorityPublicKey = ByteArray(32) { 0x54 },
                challengeEnc = ByteArray(65) { 0x65 },
                challengeCiphertext = ByteArray(48) { 0x76 },
            )

            val replacementError = runCatching {
                credentialStore.saveNew(credential.copy(authToken = pendingToken))
            }.exceptionOrNull()
            assertTrue(replacementError is IllegalStateException)

            val forbidden = linkedMapOf(
                "current transport token" to secretVariants(currentToken),
                "pending transport token" to secretVariants(pendingToken),
                "HPKE private scalar" to secretVariants(identity.privateKey),
            )
            assertContainsNoSecrets(
                "replacement error",
                replacementError?.message.orEmpty().encodeToByteArray(),
                forbidden,
            )
            listOf(
                context.filesDir,
                context.cacheDir,
                context.noBackupFilesDir,
                File(context.applicationInfo.dataDir, "shared_prefs"),
                File(context.applicationInfo.dataDir, "databases"),
            ).filter(File::exists).forEach { stateRoot ->
                stateRoot.walkTopDown().filter(File::isFile).forEach { file ->
                    assertContainsNoSecrets(
                        "app-private state file ${file.name}",
                        file.readBytes(),
                        forbidden,
                    )
                }
            }
            assertContainsNoSecrets("own-process logcat", readOwnProcessLogcat(), forbidden)
        } finally {
            preparedRotation?.current?.authToken?.fill(0)
            preparedRotation?.pendingAuthToken?.fill(0)
            pendingMembership?.pending?.authToken?.fill(0)
            pendingMembership?.canonicalProof?.fill(0)
            identityPrivateKey?.fill(0)
            currentToken.fill(0)
            pendingToken.fill(0)
            credentialStore.clear()
            pendingMembershipStore.clear()
            identityStore.clear()
        }
    }

    private fun readOwnProcessLogcat(): ByteArray {
        val process = ProcessBuilder(
            "logcat",
            "-d",
            "-v",
            "raw",
            "--pid=${android.os.Process.myPid()}",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.readBytes()
        assertTrue("logcat did not exit", process.waitFor(5, TimeUnit.SECONDS))
        assertTrue("logcat exited with ${process.exitValue()}", process.exitValue() == 0)
        return output
    }

    private fun secretVariants(secret: ByteArray): List<ByteArray> = listOf(
        secret.copyOf(),
        Base64.encodeToString(secret, Base64.NO_WRAP).encodeToByteArray(),
        Base64.encodeToString(secret, Base64.NO_WRAP or Base64.URL_SAFE)
            .trimEnd('=')
            .encodeToByteArray(),
    )

    private fun assertContainsNoSecrets(
        description: String,
        content: ByteArray,
        forbidden: Map<String, List<ByteArray>>,
    ) {
        forbidden.forEach { (label, variants) ->
            assertFalse(
                "$label appeared in $description",
                variants.any { variant -> content.containsSubsequence(variant) },
            )
        }
    }

    private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        for (start in 0..size - candidate.size) {
            var matches = true
            for (offset in candidate.indices) {
                if (this[start + offset] != candidate[offset]) {
                    matches = false
                    break
                }
            }
            if (matches) return true
        }
        return false
    }
}
