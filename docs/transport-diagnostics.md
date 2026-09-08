# Debug transport timeline

The `SevenMirrorTransport` logcat tag is enabled by default only in Debug builds.
Release defaults are covered by `TransportDiagnosticsReleaseTest`. This is an
operator diagnostic, not product UI or a telemetry upload channel.

## Recorded data

Each line contains `t_ms` (Android elapsed realtime, including sleep), `gen`
(process-local connection generation), a code-defined `event`, and the observed
coordinator `state`. Optional fields are numeric delay/network handles and
boolean network flags or outcomes. No endpoint URL, IP address, SSID, membership
identifier, notification identifier/content, token, key, or exception message is
accepted by the recording API. Treat even these timings and network handles as
local diagnostic metadata; do not publish captures without review.

Socket events reuse `TransportDiagnosticEvent` and its existing factory observer.
The observer is bound to each attempt, so a late callback retains the old `gen`.
The reported `state` is the coordinator state at recording time, not historical
state belonging to that old socket. A new factory shares the supplied OkHttp
client's connection pool/dispatcher and keeps the existing redirect restrictions.

## Interpreting a recovery

- `NETWORK_AVAILABLE`, `NETWORK_LOST`, `NETWORK_CAPABILITIES_CHANGED` are default
  network callbacks for this application. Capabilities are taken from the
  callback, not queried synchronously during `onAvailable`. These callbacks do
  not enumerate every physical network. In particular, VPN flags are not proof
  of an underlying route's exact transition time.
- `CONNECTION_REQUESTED` to `CONNECTION_ATTEMPT` with the same `gen` measures the
  wait before a requested attempt begins on the serialized executor. A request
  superseded by a newer generation may have no attempt.
- `PENDING_MEMBERSHIP_RECOVERY` and `MEMBERSHIP_REFRESH` have `phase=BEGIN/END`.
  These intervals include synchronous membership work (HTTP, validation and
  local store access), not just HTTP wire latency. `completed=false` means an
  exception left the operation; its content is intentionally omitted.
- `SOCKET_OPEN`, `AUTH_FRAME_SENT`, `AUTHENTICATED`, `SOCKET_FAILURE`, and
  `SOCKET_CLOSED` are observed before the coordinator's queued callback work.
  `AUTHENTICATED` to `CONNECTION_READY` includes that queue wait and connection
  initialization, including delivery resume. It is not pure authentication time.
- `TERMINATION_QUEUED` to `CONNECTION_TERMINATED` shows termination processing
  delay. Obsolete or already-terminal attempts do not produce a second applied
  termination event.
- `RECONNECT_SCHEDULED delay_ms=...` records the chosen backoff. The matching
  `RECONNECT_TIMER_FIRED` retains the old generation; the next actual attempt has
  a new generation. Extra elapsed time beyond the delay may include executor
  contention or system scheduling. Canceled retries have no timer-fired event.
- `STARTUP_SNAPSHOT` measures the reconnect/startup snapshot only. Its END means
  the operation returned, not that delivery succeeded. The separate
  `STARTUP_SNAPSHOT_SUBMITTED accepted=true` means local send acceptance, not a
  server ACK or browser display. A missing local active snapshot produces no
  snapshot event. Ordinary notification changes and explicit history-gap
  snapshot responses are not traced by this slice.

Use differences of `t_ms` within the same device boot, not uncalibrated timestamps
from another machine. Absence of a callback alone does not establish the cause
of an outage. This instrumentation does not change network retry eligibility,
heartbeat/timeouts, backoff, executor ownership, or membership behavior.

## Capture and acceptance

Use the installed Debug application's PID and filter only this tag, for example:

```text
adb logcat --pid=<app-pid> -v threadtime SevenMirrorTransport:D *:S
```

Quote `*:S` if required by the host shell. Save the filtered stream on the host,
not `/sdcard`. Do not clear unrelated system logs. Restart the capture if the
application process changes; generation numbers are not durable identities.

First check an ordinary foreground connection: membership intervals, socket
handshake, and connection-ready events must appear with a consistent generation.
Return to HOME afterward and retain the user's original paused/background and
application-selection settings. Reconnection timing still requires a separate,
explicitly authorized network experiment, correlated with actual default-route
observations and the controlled notification fixture. Do not read personal
notifications or change VPN/mobile-data settings as part of collecting logs.
