package dev.notificationmirroring.notification

import android.content.Context

/** Persists the source-wide notification revision high-water mark across process recreation. */
internal class AndroidNotificationRevisionStore(
    context: Context,
    storeName: String = "default",
) {
    private val safeName = storeName.also {
        require(it.length in 1..64 && it.matches(Regex("[A-Za-z0-9_.-]+"))) {
            "storeName must be 1-64 URL-safe characters"
        }
    }
    private val preferences = context.applicationContext.getSharedPreferences(
        "syncnotifications-notification-revision-$safeName",
        Context.MODE_PRIVATE,
    )

    @Synchronized
    fun allocate(): Long {
        val current = preferences.getLong(CURRENT_REVISION, 0L)
        check(current >= 0L) { "Stored notification revision is corrupt" }
        val next = Math.addExact(current, 1L)
        check(preferences.edit().putLong(CURRENT_REVISION, next).commit()) {
            "Unable to persist notification revision"
        }
        return next
    }

    @Synchronized
    fun current(): Long {
        val current = preferences.getLong(CURRENT_REVISION, 0L)
        check(current >= 0L) { "Stored notification revision is corrupt" }
        return current
    }

    @Synchronized
    fun clear() {
        check(preferences.edit().clear().commit()) {
            "Unable to clear notification revision test state"
        }
    }

    private companion object {
        const val CURRENT_REVISION = "current_revision"
    }
}
