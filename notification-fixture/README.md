# Third-party notification fixture

`notification-fixture` is a development-only Android application used for repeatable SevenMirror end-to-end acceptance. Its application ID is `dev.sevenmirror.notificationfixture`; it runs in a separate process and does not depend on any SevenMirror module.

Build and install it with:

```powershell
.\gradlew.bat :notification-fixture:assembleDebug
adb install -r notification-fixture\build\outputs\apk\debug\notification-fixture-debug.apk
```

The fixture can publish, repeat, update, and remove one notification; publish grouped, silent, and ongoing notifications; and expose ordinary-action and `RemoteInput` reply results in its own UI. The normal notification includes deterministic app icon, avatar, and picture content.

## Screen-off notification sequence

The delayed-sequence button schedules a publish, update, and removal through a non-exported alarm receiver. Each next step is requested 30 seconds after the previous step actually runs. Turn off the screen and leave SevenMirror background synchronization enabled. Neither Activity must remain visible.

The fixture uses `AlarmManager.setAndAllowWhileIdle` with elapsed-realtime wakeup alarms, not exact alarms, a foreground service, or a battery exemption. Android can defer delivery and throttle alarms during Doze; the requested delay is not an execution guarantee. Device reboot or force-stop ends scheduled alarms; restart the sequence manually afterward. This is a controlled development stimulus, not a production background-scheduling implementation.

Private preferences `delayed_notification_fixture` record each actual operation time, elapsed realtime, screen interactivity, and device-idle state. The UI shows the history when reopened. Compare the actual operation time with browser receipt time; do not count alarm scheduling delay as mirroring delay. Non-interactive display state alone does not prove deep Doze. A new run replaces the previous history. Cancel remaining steps leaves existing notifications in place; clear all cancels remaining steps and removes fixture notifications. Both cleanup buttons remain usable when notification permission is denied.

The module is compiled by repository verification but is not included in the SevenMirror APK, release manifest, or published artifacts. Do not use it as a production notification source or protocol implementation.
