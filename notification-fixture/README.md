# Third-party notification fixture

`notification-fixture` is a development-only Android application used for repeatable SevenMirror end-to-end acceptance. Its application ID is `dev.sevenmirror.notificationfixture`; it runs in a separate process and does not depend on any SevenMirror module.

Build and install it with:

```powershell
.\gradlew.bat :notification-fixture:assembleDebug
adb install -r notification-fixture\build\outputs\apk\debug\notification-fixture-debug.apk
```

The fixture can publish, repeat, update, and remove one notification; publish grouped, silent, and ongoing notifications; and expose ordinary-action and `RemoteInput` reply results in its own UI. The normal notification includes deterministic app icon, avatar, and picture content.

The module is compiled by repository verification but is not included in the SevenMirror APK, release manifest, or published artifacts. Do not use it as a production notification source or protocol implementation.
