package dev.notificationmirroring.notification

import android.app.Notification
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.ColorFilter
import android.graphics.PixelFormat
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Process
import android.os.UserHandle
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationMediaNormalizerInstrumentedTest {
    @Test
    fun largeDrawableBecomesBoundedHashedPng() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val bitmap = Bitmap.createBitmap(1024, 512, Bitmap.Config.ARGB_8888).apply {
            eraseColor(Color.rgb(20, 80, 140))
        }
        try {
            val media = NotificationMediaNormalizer.normalize(BitmapDrawable(context.resources, bitmap))
            assertNotNull(media)
            requireNotNull(media)
            assertEquals(NotificationMediaMimeType.PNG, media.mimeType)
            assertEquals(256, media.width)
            assertEquals(128, media.height)
            assertTrue(media.bytes.size <= NotificationMedia.MAX_ENCODED_BYTES)
            assertArrayEquals(
                byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
                media.bytes.copyOfRange(0, 8),
            )
            assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(media.bytes), media.contentSha256)
        } finally {
            bitmap.recycle()
        }
    }

    @Test
    fun brokenDrawableDoesNotBlockTextProcessing() {
        val broken = object : Drawable() {
            override fun draw(canvas: Canvas) = throw IllegalStateException("broken test drawable")
            override fun setAlpha(alpha: Int) = Unit
            override fun setColorFilter(colorFilter: ColorFilter?) = Unit
            @Deprecated("Deprecated in Android")
            override fun getOpacity(): Int = PixelFormat.TRANSPARENT
            override fun getIntrinsicWidth(): Int = 32
            override fun getIntrinsicHeight(): Int = 32
        }
        assertNull(NotificationMediaNormalizer.normalize(broken))
    }

    @Test
    fun contentImageBecomesPlaceholderWhileIconAndAvatarRemainBounded() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val picture = Bitmap.createBitmap(800, 600, Bitmap.Config.ARGB_8888).apply {
            eraseColor(Color.MAGENTA)
        }
        val avatar = Bitmap.createBitmap(400, 400, Bitmap.Config.ARGB_8888).apply {
            eraseColor(Color.CYAN)
        }
        try {
            val notification = Notification.Builder(context, "test")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Photo message")
                .setContentText("Look")
                .setLargeIcon(avatar)
                .setStyle(Notification.BigPictureStyle().bigPicture(picture))
                .build()
            val snapshot = NotificationExtractor.extract(
                context,
                statusBarNotification(context, notification),
                revision = 1,
                isSilent = false,
                actionIds = emptyList(),
            )
            assertTrue(snapshot.containsContentImage)
            assertEquals("Look\n[图片]", snapshot.text)
            assertNotNull(snapshot.appIcon)
            assertNotNull(snapshot.avatar)
            assertTrue(requireNotNull(snapshot.appIcon).bytes.size <= NotificationMedia.MAX_ENCODED_BYTES)
            assertTrue(requireNotNull(snapshot.avatar).width <= NotificationMedia.MAX_DIMENSION)
        } finally {
            picture.recycle()
            avatar.recycle()
        }
    }

    private fun statusBarNotification(context: Context, notification: Notification): StatusBarNotification {
        val constructor = StatusBarNotification::class.java.constructors.first { it.parameterTypes.size == 10 }
        val arguments: Array<Any?> = if (constructor.parameterTypes[6] == Int::class.javaPrimitiveType) {
            arrayOf(
                context.packageName,
                context.packageName,
                91,
                "media",
                Process.myUid(),
                Process.myPid(),
                0,
                notification,
                UserHandle.getUserHandleForUid(Process.myUid()),
                System.currentTimeMillis(),
            )
        } else {
            arrayOf(
                context.packageName,
                context.packageName,
                91,
                "media",
                Process.myUid(),
                Process.myPid(),
                notification,
                UserHandle.getUserHandleForUid(Process.myUid()),
                null,
                System.currentTimeMillis(),
            )
        }
        return constructor.newInstance(*arguments) as StatusBarNotification
    }
}
