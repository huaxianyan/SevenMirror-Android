package com.neko7ina.sevenmirror

import java.io.File
import java.io.FileOutputStream

/**
 * App-private ring holding the same transport diagnostic lines that go to logcat.
 *
 * Field failures cannot be diagnosed from logcat alone: the main buffer is roughly 256 KiB, so it
 * evicts hours of history, and Release builds never write logcat at all. This ring keeps the recent
 * timeline in the application's own files directory instead, so an operator can still read it after
 * the fact with `adb exec-out run-as <package> cat files/transport-diagnostics.log` (Debug) or an
 * equivalent privileged read (Release).
 *
 * The accepted content is exactly what [TransportDiagnostics] accepts: code-defined event and state
 * names plus numeric or boolean fields. It never holds notification content or identifiers, endpoint
 * URLs, addresses, SSIDs, membership identifiers, tokens, keys, or exception messages, and nothing
 * is uploaded anywhere.
 *
 * Once the file exceeds [maxBytes] the oldest lines are dropped, keeping about [KEEP_NUMERATOR] of
 * the budget so the next trim is not immediate. Diagnostic I/O is best-effort by design: a failure
 * is swallowed rather than allowed to reach the transport.
 */
internal class TransportDiagnosticsRing(
    private val file: File,
    private val maxBytes: Long = DEFAULT_MAX_BYTES,
) {
    init {
        require(maxBytes > 0) { "maxBytes must be positive" }
    }

    @Synchronized
    fun append(line: String) {
        try {
            val encoded = (line + "\n").toByteArray(Charsets.UTF_8)
            file.parentFile?.mkdirs()
            FileOutputStream(file, true).use { it.write(encoded) }
            if (file.length() > maxBytes) trim()
        } catch (_: Exception) {
            // Best-effort: a diagnostic must never affect the transport.
        }
    }

    @Synchronized
    fun read(): String = try {
        if (file.isFile) file.readText() else ""
    } catch (_: Exception) {
        ""
    }

    private fun trim() {
        val bytes = file.readBytes()
        val size = bytes.size.toLong()
        var start = (size - keepBytes).coerceAtLeast(0)
        // Never keep a partially cut line: advance to the first complete line in the window.
        while (start < size && bytes[start.toInt()] != '\n'.code.toByte()) start += 1
        if (start < size) start += 1
        val kept = bytes.copyOfRange(start.toInt(), bytes.size)
        val staged = File(file.parentFile, file.name + ".trim")
        staged.writeBytes(kept)
        if (!staged.renameTo(file)) {
            file.writeBytes(kept)
            staged.delete()
        }
    }

    private val keepBytes: Long
        get() = maxBytes * KEEP_NUMERATOR / KEEP_DENOMINATOR

    companion object {
        const val FILE_NAME = "transport-diagnostics.log"
        const val DEFAULT_MAX_BYTES: Long = 256L * 1024
        private const val KEEP_NUMERATOR = 3L
        private const val KEEP_DENOMINATOR = 4L
    }
}
