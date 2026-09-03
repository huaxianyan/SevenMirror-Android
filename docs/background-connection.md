# Android background connection

SevenMirror keeps its authenticated WebSocket available with a user-controlled foreground service after application selection is explicitly confirmed.

## Foreground service declaration

The service declares Android's `specialUse` foreground-service type. `remoteMessaging` is intentionally not used: SevenMirror mirrors notifications selected by the user and is not limited to transferring text messages. The manifest subtype states the concrete purpose: end-to-end encrypted notification mirroring to user-authorized devices.

The service uses a low-importance, silent notification channel. Its notification reports transport readiness without exposing server addresses, device IDs, notification content, protocol state, or raw errors. The notification opens SevenMirror and provides a user action to pause synchronization.

On Android 13 and later, SevenMirror asks for notification permission before starting persistent background synchronization. If permission is denied, the persistent service does not start; the user can still retry the transport from the foreground UI while the app is open. Settings shows the unmet requirement and lets the user request permission again.

## Lifetime and recovery

- The service is `START_STICKY` and reconnects through the existing bounded transport backoff.
- Default-network availability retries an offline connection only while connection ownership is enabled.
- Stopping the background connection persistently disables service restart, closes the WebSocket, and cancels reconnect and membership-refresh work. Opening the app may still establish a foreground UI connection.
- Saving the first explicit application selection enables background connection by default. A later user pause is retained across application-selection edits and process recreation.
- SevenMirror does not request direct exemption from battery optimization. It reports whether Android currently grants unrestricted battery usage and opens system battery settings for an explicit user decision.
- This slice does not start the foreground service from `BOOT_COMPLETED`; after a full device restart, the user must open SevenMirror once. Adding boot startup requires separate platform and distribution-policy validation.

## Notification-access loss

When Android disconnects the notification listener, the local controller publishes a fresh empty snapshot barrier before discarding its process-local notification and action registry. This prevents recipient devices from indefinitely retaining notifications that SevenMirror can no longer authoritatively observe. A later listener reconnect rebuilds the active set with fresh revisions.
