package com.neko7ina.sevenmirror

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing

/**
 * Single definition of the product interaction timing.
 *
 * Page transitions, revealed content and list changes all read their duration from here, so the
 * screens keep one rhythm instead of every call site picking its own numbers.
 *
 * Reduced motion is deliberately not handled here. Compose reads the platform duration scale, so
 * turning on "remove animations" in the system accessibility settings collapses every value below
 * to a single frame without extra branching.
 */
internal object AndroidMotion {
    /** Feedback on a control the user just touched, for example a switch row. */
    const val FEEDBACK_MILLIS = 120

    /** Content that appears or disappears inside a screen, for example the custom option group. */
    const val CONTENT_MILLIS = 200

    /** A whole page or onboarding step entering and leaving. */
    const val PAGE_MILLIS = 260

    /** Sideways travel of a pushed or popped page, as a fraction of the container width. */
    const val PAGE_TRAVEL_FRACTION = 0.18f

    /** Vertical travel of an onboarding step entering, as a fraction of the container height. */
    const val STEP_TRAVEL_FRACTION = 0.03f

    val enterEasing: Easing = CubicBezierEasing(0.2f, 0f, 0f, 1f)
    val exitEasing: Easing = CubicBezierEasing(0.4f, 0f, 1f, 1f)
}
