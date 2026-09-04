package dev.sevenmirror.notificationfixture

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var resultView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = getString(R.string.app_name)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24.dp, 32.dp, 24.dp, 32.dp)
            addView(TextView(context).apply {
                text = getString(R.string.screen_title)
                textSize = 24f
            }, matchWidth())
            addView(TextView(context).apply {
                text = getString(R.string.screen_description)
                textSize = 16f
                setPadding(0, 12.dp, 0, 20.dp)
            }, matchWidth())
        }

        resultView = TextView(this).apply {
            textSize = 16f
            setPadding(0, 0, 0, 16.dp)
        }
        content.addView(resultView, matchWidth())
        content.addAction(R.string.post_notification) { FixtureNotifications.post(this) }
        content.addAction(R.string.repeat_notification) {
            FixtureNotifications.repeatWithoutVisibleChanges(this)
        }
        content.addAction(R.string.update_notification) { FixtureNotifications.update(this) }
        content.addAction(R.string.remove_notification) { FixtureNotifications.remove(this) }
        content.addAction(R.string.post_group) { FixtureNotifications.postGroup(this) }
        content.addAction(R.string.remove_group_children) {
            FixtureNotifications.removeGroupChildren(this)
        }
        content.addAction(R.string.post_silent) { FixtureNotifications.postSilent(this) }
        content.addAction(R.string.post_ongoing) { FixtureNotifications.postOngoing(this) }
        content.addAction(R.string.clear_all) { FixtureNotifications.clearAll(this) }

        setContentView(ScrollView(this).apply { addView(content) })
        requestNotificationPermissionIfNeeded()
        renderResult()
    }

    override fun onResume() {
        super.onResume()
        if (::resultView.isInitialized) renderResult()
    }

    private fun LinearLayout.addAction(label: Int, action: () -> Unit) {
        addView(Button(context).apply {
            setText(label)
            isAllCaps = false
            setOnClickListener {
                if (canPostNotifications()) {
                    action()
                    renderResult()
                } else {
                    requestNotificationPermissionIfNeeded()
                    resultView.text = getString(R.string.permission_required)
                }
            }
        }, matchWidth().apply { topMargin = 8.dp })
    }

    private fun renderResult() {
        resultView.text = getString(
            R.string.last_result,
            FixtureNotifications.lastResult(this),
        )
    }

    private fun canPostNotifications(): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun requestNotificationPermissionIfNeeded() {
        if (!canPostNotifications() && Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
        }
    }

    private fun matchWidth() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT,
    )

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()

    companion object {
        private const val NOTIFICATION_PERMISSION_REQUEST = 1
    }
}
