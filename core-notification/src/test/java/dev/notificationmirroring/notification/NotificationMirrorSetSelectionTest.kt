package dev.notificationmirroring.notification

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotificationMirrorSetSelectionTest {
    @Test
    fun `newest notifications remain available when more than 200 are active`() {
        val selection = selectNotificationMirrorSet(
            (1L..202L).map { index -> snapshot("notification-$index", index) },
        )

        assertEquals(200, selection.snapshots.size)
        assertEquals(2, selection.omittedByLimit)
        assertEquals("notification-202", selection.snapshots.first().key)
        assertFalse(selection.snapshots.any { it.key == "notification-1" || it.key == "notification-2" })
    }

    @Test
    fun `group child replaces its duplicate summary`() {
        val summary = snapshot("summary", 20, groupKey = "messages", isGroupSummary = true)
        val child = snapshot("child", 10, groupKey = "messages")
        val otherAppSummary = snapshot(
            "other-summary",
            30,
            packageName = "com.example.other",
            groupKey = "messages",
            isGroupSummary = true,
        )

        val selection = selectNotificationMirrorSet(listOf(summary, child, otherAppSummary))

        assertEquals(listOf("other-summary", "child"), selection.snapshots.map(NotificationSnapshot::key))
        assertTrue(selection.omittedByLimit == 0)
    }

    private fun snapshot(
        key: String,
        postedAtMillis: Long,
        packageName: String = "com.example.messages",
        groupKey: String? = null,
        isGroupSummary: Boolean = false,
    ): NotificationSnapshot = NotificationSnapshot(
        key = key,
        revision = postedAtMillis + 1,
        packageName = packageName,
        appName = "Messages",
        title = key,
        text = null,
        expandedText = null,
        appIcon = null,
        avatar = null,
        containsContentImage = false,
        postedAtMillis = postedAtMillis,
        isClearable = true,
        isOngoing = false,
        isSilent = false,
        groupKey = groupKey,
        isGroupSummary = isGroupSummary,
        actions = emptyList(),
    )
}
