# Transport timeline

The coordinator records the transport timeline in both build types, and gives it
two sinks with different reachability:

- an app-private ring file in `filesDir/transport-diagnostics.log`, written in
  Debug and Release alike;
- the `SevenMirrorTransport` logcat tag, written in Debug only.

`TransportDiagnostics` itself still defaults to `enabled = BuildConfig.DEBUG` and
to logcat, so `TransportDiagnosticsReleaseTest` keeps pinning that default; the
coordinator overrides both because the ring is the only sink that survives a
field failure. This is an operator diagnostic, not product UI or a telemetry
upload channel, and nothing leaves the device.

## Recorded data

Each line contains `t_ms` (Android elapsed realtime, including sleep), `gen`
(process-local connection generation), a code-defined `event`, and the observed
coordinator `state`. Optional fields are numeric delay/network handles, boolean
network flags or outcomes, and a `failure=` label. Holding to the existing
boundary, that label is the ending exception's class name only: messages are
never recorded, because they can carry payload. No endpoint URL, IP address,
SSID, membership identifier, notification identifier/content, token, or key is
accepted by the recording API. Treat even these timings and network handles as
local diagnostic metadata; do not publish captures without review.

Socket events reuse `TransportDiagnosticEvent` and its existing factory observer.
The observer is bound to each attempt, so a late callback retains the old `gen`.
The reported `state` is the coordinator state at recording time, not historical
state belonging to that old socket. `SOCKET_FAILURE` carries the ending
exception's class name, which is what separates a socket that went silent from
one the peer refused or reset; the other socket events carry none. A new factory
shares the supplied OkHttp client's connection pool/dispatcher, keeps the
existing redirect restrictions, and arms a client-side ping interval so a socket
whose peer stopped producing data fails within one interval instead of waiting on
the server's own ping timing to notice.

## The ring file

logcat alone cannot answer a field question: its main buffer is roughly 256 KiB,
so it evicts hours of history, and Release builds never write it at all. The ring
is what makes an outage diagnosable after the fact, so it is the primary artifact
and logcat is the convenience one.

The ring holds the same lines, byte for byte, that logcat would receive. It
appends each line as UTF-8, and once the file passes 256 KiB it drops the oldest
lines until about three quarters of the budget remains, always at a line boundary
so a reader never sees a torn record. Trimming stages a sibling `.trim` file and
renames it over the target, falling back to an in-place rewrite if the rename is
refused. All of it is best-effort: a failed write or trim is swallowed, because
instrumentation must never change transport behavior.

The ring is bounded but not small, and it outlives the process, so treat it the
same way as a logcat capture: read it during an explicitly authorized session,
and review it before sharing. Read it with

```text
adb exec-out run-as <package> cat files/transport-diagnostics.log
```

`run-as` only works for a debuggable application, so reading the ring of an
installed Release build needs an equivalent privileged read. Prefer `exec-out`
over `shell cat`: a pty would rewrite `\n` to `\r\n`.

## Interpreting a recovery

- `NETWORK_AVAILABLE`, `NETWORK_LOST`, `NETWORK_CAPABILITIES_CHANGED` are default
  network callbacks for this application. These callbacks do not enumerate every
  physical network, and a VPN that owns the default network keeps its handle while
  the transport underneath it changes. The route identity used for retirement is
  therefore a handle plus its transports; see `background-connection.md`.
- `CONNECTION_NETWORK_REPLACED` is recorded when the route a live connection is
  bound to no longer matches the current one, and the connection is retired for
  that reason. It can be the only event reporting a transition: when a VPN owns the
  default network the handle never changes, and the preceding
  `NETWORK_CAPABILITIES_CHANGED` carries the `network`, `wifi`, `cellular` and
  `vpn` fields that show it. The `network` field is absent when no default network
  remains. Detection time is the gap from the callback reporting the change to this
  event; the gap from here to the following `CONNECTION_READY` is an ordinary
  reconnect and is not part of it.
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
  The `failure=<class name>` on `SOCKET_FAILURE` names the exception that ended
  the socket: a timeout there means the peer stopped producing data, not that the
  peer or the network refused the connection.
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
- `SECURITY_ERROR_ENTERED recovery=...` and `LOCAL_FAILURE_RETRY` are the two ways a
  failure is handled: the first parks the transport on the recovery page and records
  which recovery it was classified as, the second re-arms the connection through the
  bounded backoff. Both carry the class of the ending exception, which is what keeps
  the entry that refused a frame identifiable after the frame itself is gone.
  `SECURITY_ERROR_ENTERED` with `recovery=NONE` means the cause was never classified
  as permanent.
- `CONNECTION_REARMED` is the periodic check noticing that a connection owner has a
  retryable state with no reconnect scheduled, and re-arming it. It is expected to be
  absent: every other path schedules its own retry. Its presence means one declined
  to, and the `CONNECTION_REQUESTED` that follows it belongs to that re-arm.

Use differences of `t_ms` within the same device boot, not uncalibrated timestamps
from another machine. Absence of a callback alone does not establish the cause
of an outage. The recording API itself adds no retry eligibility, heartbeat,
backoff, executor ownership, or membership behavior of its own; the ping interval
belongs to the socket factory, which is transport policy rather than
instrumentation. Default network identity does retire a stale connection, but
that rule lives in the coordinator and is described in `background-connection.md`,
not in this instrumentation. The same holds for the periodic re-arm check and for
which failures are retried rather than parked.

## Capture and acceptance

The ring needs no capture to be set up: it is already there when the failure
happens. Read it after the fact with the `adb exec-out` command above. It holds
the most recent window only, and its `t_ms` values are on the same
Android elapsed-realtime clock as logcat, so a line can be correlated with a
logcat capture from the same boot.

For a live Debug capture, use the installed Debug application's PID and filter
only this tag, for example:

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
