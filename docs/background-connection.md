# Android background connection

SevenMirror keeps its authenticated WebSocket available with a user-controlled foreground service after application selection is explicitly confirmed.

## Foreground service declaration

The service declares Android's `specialUse` foreground-service type. `remoteMessaging` is intentionally not used: SevenMirror mirrors notifications selected by the user and is not limited to transferring text messages. The manifest subtype states the concrete purpose: end-to-end encrypted notification mirroring to user-authorized devices.

The service uses a low-importance, silent notification channel. Its notification reports transport readiness without exposing server addresses, device IDs, notification content, protocol state, or raw errors. The notification opens SevenMirror and provides a user action to pause synchronization.

On Android 13 and later, SevenMirror asks for notification permission before starting persistent background synchronization. If permission is denied, the persistent service does not start; the user can still retry the transport from the foreground UI while the app is open. Settings shows the unmet requirement and lets the user request permission again.

## Lifetime and recovery

- The service is `START_STICKY` and reconnects through the existing bounded transport backoff.
- The coordinator owns one set of active connection owners. Each Activity acquires its own ownership in `onStart` and releases it in `onStop`; the foreground service acquires ownership after validating its start request and releases it in `onDestroy`.
- Default-network availability retries an offline connection only while at least one owner remains. It cannot create ownership.
- A connection belongs to the route its TCP connection was opened on. Android does not close the socket when that route changes, so the coordinator compares the route's identity instead of waiting for the socket to fail, and retires the connection as soon as the identity moves. The controlled Wi-Fi recovery trace this change addresses waited 72.25 s for the old socket to fail after the transport returned to Wi-Fi, while reconnecting once the change is seen takes under a second.
- A route's identity is the default network's handle together with its transports. The handle alone is not enough: a VPN that owns the default network keeps one handle while the transport beneath it changes, which is what the trace showed, one VPN handle with transports flipping from `WIFI|VPN` to `CELLULAR|VPN`. Signal strength, bandwidth estimates, metering and validation are not part of the identity, so an ordinary capability update on an unchanged route does not retire a healthy connection.
- An unchanged route can still stop carrying data if the peer or the path between them goes silent. The relay socket arms a 30 s client-side ping interval, so OkHttp fails such a socket within one interval instead of leaving it open while the coordinator still reports `ONLINE` and queued notifications wait only in the send buffer. Nothing coordinator-side is needed for that: the failure follows the ordinary bounded reconnect and startup-snapshot path.
- Network callbacks are dispatched onto the serialized transport executor that also owns the connection. A replacement therefore obeys the same generation, owner and backoff rules as any other reconnect, and adopting the new route discards an accumulated retry delay rather than waiting it out.
- Stopping the background connection persistently disables service restart and releases service ownership. A visible Activity may still use a foreground UI connection. Once the last owner releases, the coordinator closes the WebSocket and cancels reconnect, result-drain, and membership-refresh work.
- With background synchronization enabled and the foreground service running, leaving the Activity or turning off the screen does not release service ownership. Activity recreation or repeated service start requests do not replace an already-owned connection.
- Saving the first explicit application selection enables background connection by default. A later user pause is retained across application-selection edits and process recreation.
- SevenMirror does not request direct exemption from battery optimization. It reports whether Android currently grants unrestricted battery usage and opens system battery settings for an explicit user decision.
- This slice does not start the foreground service from `BOOT_COMPLETED`; after a full device restart, the user must open SevenMirror once. Adding boot startup requires separate platform and distribution-policy validation.

## Notification-access loss

When Android disconnects the notification listener, the local controller publishes a fresh empty snapshot barrier before discarding its process-local notification and action registry. This prevents recipient devices from indefinitely retaining notifications that SevenMirror can no longer authoritatively observe. A later listener reconnect rebuilds the active set with fresh revisions.
