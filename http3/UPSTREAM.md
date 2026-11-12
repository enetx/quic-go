# HTTP/3 upstream maintenance

HTTP/3 is part of the `github.com/enetx/quic-go` module and is imported as
`github.com/enetx/quic-go/http3`. The supported baseline is Go 1.27+.

- Source: [quic-go v0.65.0](https://github.com/quic-go/quic-go/tree/v0.65.0/http3).
- Upstream commit: `aa265c3fc6489e3bfa8071b333be95e0e887a51d`.
- Previous standalone fork: `ba6a50293c3c477f83648f3faa9e58adaa807206` (`v1.0.9`).

The former standalone source snapshot is retained in `archive/http3/` at the
workspace root. Use the shared
[update procedure](../UPSTREAM.md) and [source pins](../upstream.json) for future
updates. HTTP/3 has no separate `go.mod`.

## Audited behavior

Before updating, all production files, local tests and the standalone fork
history were compared against quic-go v0.60.0. The fork had selected later
connection and frame fixes. Its custom changes were in `client.go`, `conn.go`,
`frames.go`, `request_writer.go`, `server.go`, `transport.go`, and the former
`httpcommon` sorter.

Preserve these behaviors when updating:

- Use the fork's HTTP, tracing, test-server and HTTP/3 qlog packages.
- `Header-Order:` controls regular request header order. Listed fields precede
  unlisted fields; unlisted fields sort lexicographically. Multiple values retain
  their order. The stateless sorter exported by `enetx/http/headerorder` is shared
  with HTTP/1 and HTTP/2.
- `PHeader-Order:` controls pseudo-header order, including `:protocol` for Extended
  CONNECT. The default order is `:authority`, `:method`, `:path`, `:scheme`.
  CONNECT omits `:path` and `:scheme` where the protocol requires it.
- Both order keys are metadata and never reach the wire. Other invalid headers
  remain errors.
- `AdditionalSettings`, `Settings.Other` and `settingsFrame.Other` use
  `g.MapOrd[uint64, uint64]`. Unknown settings preserve insertion order and retain
  duplicate validation. Only qlog snapshots convert them to ordinary maps.
- Clients omit automatic `SETTINGS_MAX_FIELD_SECTION_SIZE` while enforcing
  `MaxResponseHeaderBytes` locally. Explicit profile settings remain supported.
- `settingsFrame.Append` emits `MaxFieldSectionSize` only when positive.
  Parsing an explicit peer-supplied zero remains valid. The client initializes
  this field to `-1`, so qlog agrees with its omission from the wire.
- The 0-RTT compatibility check treats zero as omitted, matching the encoder.
- Invalid-header-value errors retain the detailed diagnostics from the fork.

The former pooled sorter has been removed. The shared stateless sorter preserves
its observable order without cached mutable state or a global lock.

## Surf API usage

Optional `WireConfig` supplies reserved control/request frame factories and
independent initial `PRIORITY_UPDATE` emission from explicit Priority headers.
Control frames use one bounded writer; a blocked control stream cannot stall
request header preparation indefinitely. Local factory errors return immediately
without waiting for a peer response. Closed critical streams close the connection.
Qlog records the added frames without changing their bytes.

The shutdown integration tests wait for handler admission before initiating
graceful shutdown. Deadline tests assert minimum lifetime and bound completion
with a client timeout, instead of treating TLS startup and scheduler latency as
part of a 25ms shutdown timing tolerance. Preserve this synchronization when
merging upstream tests.

`QPACKConfig.SplitCookies` and `NeverIndex` control request field representations.
Nil configuration retains the official static encoder. Optional client encoding
uses the isolated `internal/qpack/encoder.go` with the official static table and
Huffman codec. No new QPACK or TLS dependency fork is required. All browser values,
random distributions and policy selection remain in Surf. The client adapter owns
ordered bounded instruction queues, negotiates peer capacity/blocking limits and
passes decoder feedback to the connection encoder. Headers and trailers share it.

`tests/http3/wire_config_test.go` covers independent GREASE/priority settings,
real stream IDs across requests, bounded queues, startup errors and critical-stream
closure. Private encoding tests cover all static N-bit forms, cookie order, trace
parity and request factory failures. Preserve these alongside QPACK startup tests.

Surf uses `Transport` with `TLSClientConfig`, `QUICConfig`, `AdditionalSettings`,
`MaxResponseHeaderBytes`, optional `QPACKConfig` and `Dial`, plus `RoundTrip`, `CloseIdleConnections` and
`Close`. Its tests also use `Server`, `Serve` and `Close`.

Surf does not use capsule or `HTTPStreamer` APIs. The old `ParseCapsule` API was
upstream behavior rather than a fork extension and has no compatibility wrapper.
The fork follows the current `NewCapsuleParser` / `CapsuleReader` API,
`HTTPStreamer.HTTPStream` signature and h3-events-14 qlog schema.

## Regression coverage

- `request_writer_order_test.go` and `fork_wire_test.go`: default and custom
  regular/pseudo-header order, CONNECT, Extended CONNECT, QPACK bytes with and
  without qlog, repeated requests, multiple values and omitted metadata.
- The HTTP module's `tests/headerorder/`: shared ordering, partial orders,
  lexicographic fallback, excluded metadata and independent calls.
- `frames_settings_test.go` and `fork_wire_test.go`: ordered settings on real
  client/server streams, explicit profiles, omitted/zero/positive header limits,
  peer-supplied zero, qlog snapshots, local limits and 0-RTT compatibility.
- Upstream HTTP/3 and qlog suites, with ordered-setting fixtures and detailed
  error expectations adapted to the fork.

- `../tests/qpack/` and `../tests/http3/qpack_test.go`: RFC 9204 dynamic
  receive tables, all field representations, blocking, eviction, feedback,
  cancellation/deadlines, bounded decoding and real client/server requests.
  Outgoing dynamic encoding adds independent wire vectors, both Base forms,
  bounded references, ACK/cancel/increment state, draining, rollback and fuzz cases.
- `../tests/http3/qpack_encoder_test.go`: real outgoing dynamic requests,
  parallel bodies/trailers, zero-capacity fallback and invalid decoder feedback.
- `../tests/http3/qpack_client_test.go`: configurable stream reservation order,
  eager/lazy type bytes, immediate/deferred capacity announcements, zero/omitted
  peer limits, backpressure, immutable snapshots and critical stream errors.

Run validation from the parent QUIC module, then from the sibling `surf` module
against the published version, or using a temporary Go workspace during development:

```sh
go test -race ./...
go vet ./...
```

## Request body and live priority controls

`WireConfig.RequestBodyBufferSize` and `RequestBodyBufferSizePolicy` select
request body reads; `MaxDataFrameSize` caps DATA payloads without controlling QUIC
packetization. Zero preserves native sizing/framing. Size validation runs before
HEADERS/QPACK state changes. `Stream.Write` retains unfinished-frame handling;
`TryWriteAll` queues all capped frames atomically or leaves its state unchanged.
Browser sizing policy stays in Surf.

`RequestBodyFirstReadSizePolicy` receives a private copy of the validated wire
fields and the effective buffer size before connection QPACK state changes.
It can limit the first nonempty read independently of subsequent reads. Empty
reads retain the limit; short reads are passed through without coalescing or
waiting for more producer data. Invalid results fail request preparation.
The upload reader is closed on stream cancellation even when response HEADERS
have already arrived, so a blocking streaming source can release its goroutine.

`WithPriorityUpdateHandler` publishes a concurrency-safe per-attempt updater after
HEADERS. `RequestStream.UpdatePriority` exposes it for low-level users. Updates
share the bounded connection control writer, suppress repeated values only after
successful queue admission, support a default-priority reset, and stop on response
completion, cancellation or connection closure. `CompactPriorityUpdates` controls
serialization only. Local `SetPriority` scheduling remains independent. Nil wire
configuration now installs the bounded writer to allow explicit live updates;
no extra control frames are emitted without a caller request.

`tests/http3/request_body_test.go` covers body reads, framing, unknown lengths and
policy failures. Private stream tests cover every partial header/payload deadline
and atomic retry. Priority tests cover real control frames, deduplication, reset,
cancellation and deterministic queue backpressure. Surf additionally verifies
browser-profile sizing, TLS 0-RTT with standard TLS, GOAWAY and changed SETTINGS
across fresh QPACK connections. No browser values or TLS fork are added here.

## Initial control-stream staging

`WireConfig.CoalesceInitialSettings` optionally creates the client from a per-dial
`OnApplicationReady` callback before the QUIC handshake channel is released. The
caller configuration is cloned and its callback is chained. `sync.Once` shares
exactly one client between this callback and `Dial` / `DialEarly` completion.
The constructor reserves its control/QPACK streams once and tries a nonblocking
SETTINGS+reserved-frame write. Insufficient flow-control credit hands the same
stream and bytes to an asynchronous writer; cancellation releases that writer.
Failures are published through the existing readiness channel. Nil/default wire
configuration retains asynchronous startup. Custom dialers and early-data
acceptance/rejection are covered alongside native startup tests.

HTTP/3 settings can share the client's first post-handshake flight; the option
cannot guarantee NIC batching, a fixed datagram size, identical handshake ACK
scheduling or shared congestion state with another implementation.

## Per-connection reserved SETTINGS

`WireConfig.SettingsGrease` generates one reserved SETTINGS identifier/value when
initial control bytes are prepared. It runs once per client connection, including
staged startup, rather than once per request or transport. The factory must be
concurrency safe, nonblocking and must not reenter the transport. Its identifier
must follow `0x1f * N + 0x21`; both fields must fit a QUIC varint. Invalid values,
collisions with configured settings and factory errors fail preparation before
writing the control prefix. Valid output is appended to a private ordered snapshot;
configured SETTINGS and QPACK state are unchanged. Nil retains native behavior.
The engine contains no browser random distribution or profile defaults.

Private validation and real HTTP/3 tests cover bounds, duplicates, errors, input
immutability, request reuse and fresh connections. Surf supplies Chromium's two
independent uint32 draws through its fluent `GreaseFactory` profile control.

## Response header observation

`WireConfig.OnResponseHeaders` observes parsed informational and final headers
before tracing or application delivery. Returning an error cancels the request.
The nil default preserves upstream behavior. Browser retry/backup policy belongs
in Surf, not this generic hook. The patch is limited to `wire_config.go` and the
response loop in `client.go`; `response_headers_test.go` exercises real QUIC
streams, ordering and cancellation. The adjacent trace call now propagates
`Got1xxResponse` errors as required by the existing httptrace contract.
