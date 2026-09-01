package dev.notificationmirroring.notification

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Rect
import android.graphics.drawable.Drawable
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.math.max
import kotlin.math.roundToInt

internal object NotificationMediaNormalizer {
    fun normalize(drawable: Drawable?): NotificationMedia? {
        if (drawable == null) return null
        try {
            val sourceWidth = drawable.intrinsicWidth.takeIf { it > 0 } ?: NotificationMedia.MAX_DIMENSION
            val sourceHeight = drawable.intrinsicHeight.takeIf { it > 0 } ?: NotificationMedia.MAX_DIMENSION
            val initialScale = minOf(
                1.0,
                NotificationMedia.MAX_DIMENSION.toDouble() / max(sourceWidth, sourceHeight),
            )
            var width = max(1, (sourceWidth * initialScale).roundToInt())
            var height = max(1, (sourceHeight * initialScale).roundToInt())

            while (true) {
                val bytes = renderPng(drawable, width, height)
                if (bytes.size <= NotificationMedia.MAX_ENCODED_BYTES) {
                    return NotificationMedia(
                        contentSha256 = MessageDigest.getInstance("SHA-256").digest(bytes),
                        mimeType = NotificationMediaMimeType.PNG,
                        width = width,
                        height = height,
                        bytes = bytes,
                    )
                }
                if (width == 1 && height == 1) return null
                width = max(1, width * 3 / 4)
                height = max(1, height * 3 / 4)
            }
        } catch (_: RuntimeException) {
            return null
        } catch (_: OutOfMemoryError) {
            return null
        }
    }

    private fun renderPng(drawable: Drawable, width: Int, height: Int): ByteArray {
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        return try {
            val previousBounds = Rect(drawable.bounds)
            drawable.setBounds(0, 0, width, height)
            try {
                drawable.draw(Canvas(bitmap))
            } finally {
                drawable.bounds = previousBounds
            }
            ByteArrayOutputStream().use { output ->
                check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output))
                output.toByteArray()
            }
        } finally {
            bitmap.recycle()
        }
    }
}
