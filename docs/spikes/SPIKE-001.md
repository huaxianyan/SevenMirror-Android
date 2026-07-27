# SPIKE-001 — Android notification capabilities

Status: in progress

## Safety boundary

This spike is process-local. It does not log, persist, encrypt, or transmit notification content. No networking dependency exists in the Android project.

## Implemented

- `NotificationListenerService` initial active-notification reconciliation
- New/update/removal in-memory state
- Basic text, group, ongoing, silent and clearable metadata extraction
- Action descriptors without exposing or serializing `PendingIntent`
- Notification revision binding and stale-action rejection
- Regular `PendingIntent` invocation
- Free-form `RemoteInput` injection
- Cancelled and unsupported action result states
- Deterministic local test notification with a regular action and reply action
- Compose-only local capability screen

## Manual verification

1. Install a debug APK on Android 10 and a current Android version.
2. Grant notification access and notification posting permission.
3. Tap **Post local action test notification**.
4. Confirm the notification appears in the in-app local list.
5. Invoke **Mark handled** and confirm the receiver status changes and the notification disappears.
6. Post it again, enter reply text in the local list, and tap **Send**.
7. Confirm the exact text reaches `RemoteInput` and the notification disappears.
8. Update a notification, retain an old action token in a debugger/test, and verify it returns `STALE_NOTIFICATION_VERSION`.
9. Revoke notification access and verify local state clears after listener disconnection.

## Exit evidence still required

- Successful CI build and lint
- Physical/emulated Android 10 result
- Physical/emulated current Android result
- Tests against at least two third-party apps with `RemoteInput`
- Compatibility notes for unsupported multi-input or non-free-form actions
