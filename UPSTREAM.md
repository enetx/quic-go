# QUIC and HTTP/3 maintenance

Baseline: official [quic-go v0.65.0](https://github.com/quic-go/quic-go/tree/v0.65.0),
commit `aa265c3fc6489e3bfa8071b333be95e0e887a51d`. Go 1.27+.
Pins are recorded in [upstream.json](upstream.json).

The module is `github.com/enetx/quic-go`. Imports are mechanically renamed so Surf
can depend on a published fork without requiring its users to add replacements.
The HTTP/3 package retains Surf's ordered SETTINGS and request headers, local
header limits and stream-priority adapters. HTTP types come from `enetx/http`.
The stateless header sorter is shared through `enetx/http/headerorder`; there is
no second implementation here.

## Ownership

The fork contains protocol controls, no browser names, presets or browser-valued
defaults. All profiles, template construction, GREASE policy and extension values
belong in Surf. No uTLS or QPACK fork was introduced, and QUIC does not depend on
uTLS. `tlsquic` is a small interface using standard-library TLS event types.
Surf implements the adapter using official `refraction-networking/utls`.
HTTPcloak was inspected as a design reference; its transport, TLS and QPACK
implementations were not imported.

`Config.ClientHandshake == nil` preserves upstream client behavior. Servers keep
the upstream TLS path. Controls are per configuration/connection, never globals.
Known parameter values stay coupled to the engine: stream credit configures the
actual receive controllers; UDP limits provision real receive buffers; ACK delay
sets the receive scheduler; CID and datagram limits configure their validators.
Raw additional parameters may only describe extensions outside engine ownership.
Advertising an extension does not implement it.

## Small hooks

| Extension | Own implementation | Existing source hooks |
| --- | --- | --- |
| Client controls, per-attempt factories, receive windows, datagram/CID/ACK limits, Initial ID/number | `client_handshake.go` | `interface.go`, `config.go`, `connection.go`, `transport.go` |
| UDP receive size (including the omitted protocol default) | `packet_receive_size*.go` | `sys_conn*.go`, `transport.go`, one receive-only pool branch in `buffer_pool.go` |
| ACK scheduling and active CID limits | `internal/ackhandler/receive_config.go`, client controls | one tracker field/alarm hook and the manager limit hook |
| Optional client receive ACK policy | `ack_policy.go`, `internal/ackhandler/ack_policy.go` | one Application Data tracker branch and client setup; native and server defaults retained |
| Dynamic QPACK receive tables and bounded feedback | `internal/qpack/`, `http3/qpack.go`, `read_stream_wait.go` | HTTP/3 stream/connection decoder adapters |
| Optional QPACK stream order, type timing and encoder capacity announcements | `http3/qpack_client.go` | one transport option, client setup, peer SETTINGS and request header/trailer hooks |
| Ordered/additional client parameters and external GREASE | `transportparams/` | one field and return adapter in `internal/wire/transport_parameters.go` |
| External TLS client | `tlsquic/` | client-only factory and error propagation in `internal/handshake/crypto_setup.go` |
| Initial SETTINGS before request writes | `http3/client_settings.go` | one readiness channel and two hooks in `http3/client.go`; packet-order regression |
| HTTP/3 ordering and priority | `http3/` custom files and existing small hooks | see `http3/UPSTREAM.md` |

A separate upstream bug fix in `crypto_stream.go` sorts absent SNI cuts after
real ECH cuts. ECH without SNI (IP origins) otherwise leaves HasData false and
stalls the handshake. A byte-reassembly regression covers this case.

Test-only adaptations: HTTP integration tests/examples use fork HTTP types and
ordered maps. `hkdf_test.go` uses fixed Expand-Label vectors instead of private
crypto/tls linknames rejected by Go 1.27. The config-field audit includes the new
optional field. Keep upstream tests with their source packages when private
access is required; public extension tests live under `tests/`.
Malformed QPACK peers wait for a request before injecting an error, avoiding a
legitimate pre-request transport retry. Stream cancellation completion waits
use the integration suite's time scale and retain all cancellation assertions.

## Audit and update

`python3 scripts/upstream.py audit` compares with the pinned Git source after
normalizing module/HTTP imports and gofmt. `audit --patch` shows the substantive
patch. New extension files are listed separately. This requires `gofmt` on PATH.
The script is a maintenance tool, not a runtime dependency.

Before updating, commit reviewed local changes. Fetch the new upstream tag and
create a separate Git worktree from the fork's HEAD. Merge the tag there with
`--no-commit --no-ff`; resolve the small hooks using the inventory above. Normalize
new upstream package imports to `github.com/enetx/quic-go`, and HTTP/3/integration
HTTP imports to `github.com/enetx/http`. Keep source links pointing upstream.
Update the pin only after reviewing and testing the merged candidate. Never merge
upstream changes directly over an uncommitted Surf working tree.

Validation:

```sh
go mod tidy
go test -race -count=1 ./...
go vet ./...
python3 scripts/upstream.py audit
```

Also run Surf's full race/coverage command and independent Initial-packet wire
tests against the candidate. Check that nil controls retain upstream behavior,
custom values reach the peer, session metadata survives resumption, invalid TLS
templates fail explicitly, and HTTP/1/2 fixtures remain unchanged.

## Module boundaries

Surf imports HTTP/3 from `github.com/enetx/quic-go/http3` and uses released
HTTP and QUIC modules. Local replacements are optional development overrides.
HTTP/3 source and tests live only in this module. The duplicate implementation
was removed from the HTTP module after migration and regression comparison.

Published versions depend on the released HTTP module with its exported sorter.
No local replacement is needed by module consumers. Release HTTP changes first
when QUIC needs a new shared HTTP API, then release QUIC and update Surf.

The fork owns `.github/workflows/go.yml`: Go 1.27 checks formatting, module
consistency, the complete race-enabled suite and vet on Linux, macOS and Windows.
Upstream Docker publishing, cloud fuzzing and third-party upload workflows are
not installed in the fork; they require upstream-specific credentials/services.

## Verified behavior and remaining limits

The receive-side dynamic QPACK implementation follows RFC 9204. It reuses the
unchanged official qpack module for the static table/outbound encoder and x/net's
Huffman codec. Capacity, blocked streams, decoded header size and feedback queues
are bounded. Cancellation, deadlines, connection shutdown and critical-stream
errors retain native QUIC semantics. Zero capacity keeps the upstream static path.
RFC Appendix B vectors, fragmented instructions, table eviction/wrap, blocked
streams, errors, cancellation and real HTTP/3 client/server exchanges are tested.
Outbound encoding remains static: this is not a browser QPACK indexing policy.

`http3.QPACKConfig` optionally reserves encoder/decoder streams in application
order, sends their types eagerly or with their first instruction, and queues an
encoder capacity announcement after SETTINGS or with the next HEADERS block.
The value never exceeds the peer's limit or the configured local budget; absent
or zero peer capacity produces no instruction. One writer per critical stream
preserves instruction order and respects flow control without blocking request
headers or the control parser. Feedback queues remain bounded. Nil configuration
retains native behavior, and server behavior is unchanged. Browser values and
mode selection belong in Surf; the fork contains no browser detection or sleeps.
The protocol matrix, reserved IDs, lazy type bytes, capacity bounds, snapshots,
limited stream credit, critical-stream STOP_SENDING and dynamic response feedback
are tested in `tests/http3/qpack_client_test.go`.

Surf now owns independent Chromium 156 / Firefox 159 QUIC ClientHello fixtures.
Its tests decrypt Initial packets independently and compare TLS, ordered SETTINGS,
headers and supported transport parameters. Manual warmed requests to the external
HTTP/3 endpoint pass, including the Firefox response that previously exposed the
dynamic-QPACK gap. The external endpoint is not a CI dependency.

This does not establish complete browser identity. Official quic-go does not
implement compatible in-flight version negotiation (RFC 9368). Advertising v2 in
version_information while starting v1 makes supporting servers switch keys; this
client cannot consume those packets. Surf's Firefox profile deliberately leaves
that capability unadvertised. Explicit native v2 connections remain supported.
Neqo's legacy min_ack_delay codepoint (`0xff02de1a`, mislabeled GREASE by the
fingerprint endpoint) is likewise not advertised: the native ACK_FREQUENCY parser
has no receiver implementation and its newer last-field semantics differ.
ACK ratio/frequency, packet scheduling/coalescing, congestion/loss behavior,
resource-specific priority policy and dynamic outbound QPACK still differ from
browser engines. Browser defaults and workaround decisions belong in Surf.

Client receive ACK policy is now configurable: initial/decimated packet thresholds,
transition by packet-number span, RTT-scaled delay and floor, fixed earliest deadline,
gap-window/immediate reordering and ECN response. Browser policy remains in Surf.
The native tracker branch and Initial/Handshake spaces are preserved. Policy is
cloned per configuration and connection. This does not implement ACK_FREQUENCY,
its legacy wire parameter, congestion control, packet pacing or version switching.
Deterministic `internal/ackhandler/ack_policy_test.go` cases cover boundary numbers,
non-eliciting packets, timer expiry, real RTT samples, gaps, ECN and snapshots.
