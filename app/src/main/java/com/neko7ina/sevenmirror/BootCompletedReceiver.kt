package com.neko7ina.sevenmirror

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Brings the persistent connection back after a full device restart.
 *
 * A restart is the one case no other entry point covers: until the user opens SevenMirror nothing
 * else runs, so the service has to be started from here. The gate is the same explicit decision the
 * onboarding step records, so an install that never finished that step is left alone instead of
 * being started from a preference the user never chose.
 *
 * Only the unlocked `BOOT_COMPLETED` is handled and the receiver is not direct-boot aware, so the
 * preference store and the notification permission are both readable by the time it runs. The
 * broadcast is not a protected one, so any app can send it; doing so only asks SevenMirror to apply
 * its own saved decision, which grants the sender nothing.
 */
class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        BackgroundConnectionService.reconcileAfterBoot(context)
    }
}
