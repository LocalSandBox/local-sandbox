# HTTPS Request Header Injection Implementation Plan

## Summary

Add opt-in HTTPS request interception that lets callers set request headers, initially including a caller-supplied `User-Agent`, when a sandbox is configured. The feature will follow the proxy's current HTTPS boundaries: TCP port 443, visible TLS SNI, and HTTP/1.1. HTTPS on other ports, TLS without usable SNI, HTTP/2, HTTP/3, QUIC, mutual TLS, and certificate-pinned clients are out of scope.

When interception is disabled, or no configured header or secret applies to a destination, preserve the current blind-tunnel behavior. When interception is enabled and at least one header applies, terminate TLS, modify each HTTP/1.1 request, and forward it upstream. Header rules are global by default and may include per-rule host allow and deny lists.

The implementation will also replace the current chunk-local secret substitution with an HTTP/1.1-aware, boundary-safe request transformation. This prevents missed replacements across read boundaries and prevents request framing corruption when a replacement changes a body length.

## Goals

- Default header interception to off.
- Accept the `User-Agent` value at sandbox configuration/start time.
- Provide a general request-header model so additional headers do not require another proxy redesign.
- Support global, allow-listed, deny-listed, and allow-plus-deny header rules.
- Insert a header when absent and replace existing instances case-insensitively when present.
- Apply rules to every HTTP/1.1 request on a keep-alive connection, not just the first request.
- Continue applying secret substitution only to hosts allowed by each secret's existing host rules.
- Make secret replacement reliable across TLS reads, HTTP chunks, and request-body boundaries.
- Preserve request framing after secret values of different lengths are substituted.
- Preserve blind tunnelling, with no CA installation or HTTP parsing, when MITM is unnecessary.
- Keep header and secret values out of debug output and error messages.

## Non-goals

- Detecting or intercepting HTTPS on ports other than 443.
- HTTP/2, gRPC over HTTP/2, HTTP/3, or QUIC support.
- Intercepting TLS without visible/usable SNI, including applicable ECH cases.
- Supporting certificate pinning or private application trust stores.
- Forwarding client certificates for mutual TLS.
- Modifying response headers.
- Modifying plaintext HTTP traffic.
- Allowing arbitrary changes to HTTP framing, routing, or hop-by-hop headers.
- Adding host-specific command-line syntax in the first release. Structured host rules will be available through `lsb.json`, the Rust SDK, and the Node.js binding. A simple global CLI flag may be added later if there is a clear syntax that does not duplicate the structured configuration poorly.

## Proposed Configuration

### `lsb.json`

Add `network.https_interception`:

```json
{
  "allow_net": true,
  "network": {
    "https_interception": {
      "enabled": true,
      "request_headers": [
        {
          "name": "User-Agent",
          "value": "my-sandbox-agent/1.0"
        },
        {
          "name": "X-Client-Name",
          "value": "sandbox",
          "hosts": {
            "allow": ["api.example.com", "*.internal.example.com"],
            "deny": ["billing.internal.example.com"]
          }
        },
        {
          "name": "X-Global-Except-Private",
          "value": "value",
          "hosts": {
            "deny": ["private.example.com", "*.private.example.com"]
          }
        }
      ]
    }
  }
}
```

`enabled` defaults to `false`. Header rules may remain configured while disabled, allowing callers to toggle interception without rebuilding the rule list. Enabling interception with no request headers is a configuration error; secret-only MITM continues to be controlled by the presence of matching secrets.

### Rust proxy types

Add types equivalent to:

```rust
pub struct HttpsInterceptionConfig {
    pub enabled: bool,
    pub request_headers: Vec<RequestHeaderRule>,
}

pub struct RequestHeaderRule {
    pub name: String,
    pub value: String,
    pub hosts: HostScope,
}

pub struct HostScope {
    pub allow: Option<Vec<String>>,
    pub deny: Option<Vec<String>>,
}
```

Use custom `Debug` implementations that show header names and host scopes but redact values. Add the interception configuration to `lsb_proxy::config::ProxyConfig` and expose corresponding types through `lsb-sdk`.

The Rust SDK's `SandboxConfig` should carry the structured interception configuration. The Node binding should expose the same shape using camelCase names (`httpsInterception`, `requestHeaders`). Generated TypeScript declarations and binding conversion tests must be updated together.

### Host scope semantics

Evaluate host scopes against the normalized TLS SNI domain, not the HTTP `Host` header.

- No `hosts` field: apply globally.
- `allow` present: apply only when an allow pattern matches.
- `deny` present: do not apply when a deny pattern matches.
- Both present: require an allow match and no deny match.
- Deny always wins.
- Reuse the existing exact and `*.example.com` matching behavior, including case-insensitive comparison and trailing-dot normalization.
- Reject explicitly supplied empty allow or deny arrays to avoid treating an accidental empty allow list as global.
- A rule that does not apply to a domain must not by itself cause that connection to be intercepted.

### Header mutation semantics

- Implement `set` semantics for the first release: remove all existing instances case-insensitively and emit one configured value.
- Apply rules in configuration order.
- Reject duplicate configured rules for the same header name, ignoring ASCII case, rather than creating order-dependent results.
- Preserve all unmodified header bytes and ordering as far as practical.
- Do not rewrite the request method, target, HTTP version, or `Host` header as part of custom-header handling.
- Validate names as HTTP token values and values as legal HTTP field values. Reject CR, LF, NUL, and other illegal bytes before the VM starts.
- Reject framing, routing, proxy, and hop-by-hop headers, at minimum: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Proxy-Connection`, `Proxy-Authorization`, `TE`, `Trailer`, `Upgrade`, and `Expect`.
- Impose limits on rule count, individual name/value length, and total configured header bytes. Use constants with unit tests and document the selected limits.

## Proxy Routing and CA Trust

Add helpers to `ProxyConfig`:

- `active_header_rules_for_domain(domain)` returns enabled rules that pass their host scopes.
- `secrets_for_domain(domain, placeholders)` retains the existing domain authorization behavior.
- `requires_mitm_for_domain(domain)` is true when either a secret substitution or an active header rule applies.
- `requires_guest_ca()` is true when any secret exists or enabled header interception has at least one rule.

For a TLS connection to port 443:

1. Buffer and parse the TLS ClientHello as today.
2. Apply the existing network allowlist and DNS-destination checks.
3. Resolve secret substitutions and header rules using SNI.
4. If neither applies, blind-tunnel the original TLS bytes exactly as today.
5. If either applies, enter the MITM path and pass both transformations to the HTTP/1.1 request transformer.

Expose an explicit `requires_guest_ca` or `mitm_enabled` flag on `ProxyHandle`. Do not infer CA installation from whether secret placeholders exist. Update all CA installation paths:

- normal CLI runs;
- CLI stdio mode;
- Rust SDK/Node SDK sandbox boot;
- checkpoint creation and restore paths.

Continue injecting secret placeholder environment variables independently of CA installation. Audit checkpoint creation so an ephemeral proxy CA is removed from the guest trust store before a disk is persisted, then refresh the trust store. The proxy CA private key must remain host-process-only and must never be written to the guest or logs.

## HTTP/1.1 Request Transformer

### Parser and connection state

Introduce a dedicated module in `lsb-proxy`, for example `http1.rs`, instead of expanding `proxy.rs` further. Use a small parser such as `httparse` for request lines and headers, while retaining explicit ownership of framing and byte forwarding.

Maintain a state machine per intercepted connection:

1. `ReadingHeaders`
2. `StreamingFixedBody`
3. `StreamingChunkedBody`
4. `AwaitingUpgradeDecision`
5. `OpaqueUpgradedTunnel`

Buffer request headers until `\r\n\r\n`, with a fixed maximum. Parse and validate request framing before forwarding anything upstream. After the current body ends, return to `ReadingHeaders` so keep-alive and pipelined requests are transformed independently.

Parse upstream response headers sufficiently to detect `101 Switching Protocols` and coordinate an opaque bidirectional relay after an accepted upgrade. If an upgrade is rejected, resume normal HTTP request parsing. Preserve interim `1xx` responses, especially `100 Continue`.

Malformed, ambiguous, or oversized HTTP must fail closed with a concise error. In particular, reject conflicting `Content-Length` values and `Content-Length` plus `Transfer-Encoding` combinations rather than risk request smuggling.

### Applying configured headers

After parsing each header block:

1. Select rules using the connection's normalized SNI.
2. Remove existing instances of each configured header using case-insensitive names.
3. Insert exactly one configured field per rule.
4. Apply secret substitution to the request target and header values.
5. Recalculate and serialize headers after any framing changes required by body substitution.

Secret substitution should not alter the method, HTTP version, or header names. Apply it to the serialized request's resulting field values, including a configured field value if it contains an authorized placeholder, without mutating the stored configuration.

## Secret Replacement Redesign

### Existing weaknesses to eliminate

The current relay replaces each read chunk independently. Consequently:

- a placeholder split across reads is missed;
- replacement can occur in protocol syntax or header names;
- changing a secret's byte length inside a fixed-length body leaves `Content-Length` incorrect;
- changing data inside a chunked body leaves chunk sizes incorrect;
- the first-header-only observer does not support multiple keep-alive requests.

### Boundary-safe matcher

Implement a streaming multi-pattern replacer with these properties:

- Match all authorized placeholder-to-secret mappings.
- Scan left-to-right with deterministic handling; generated placeholders are unique and should be validated as non-overlapping.
- Retain up to `max_placeholder_length - 1` bytes between input chunks so a match can span arbitrary TLS reads or HTTP chunk boundaries.
- Flush retained bytes only when they can no longer begin a placeholder.
- Never log input, output, placeholders, or replacement values.
- Track only counts and byte totals for debug statistics.

Header blocks are already buffered, so their request target and field values can be transformed in one pass. Request bodies require framing-aware handling.

### Request body framing

For HTTP/1.1 requests with applicable secrets:

- No body: forward the transformed headers normally.
- Chunked input: decode chunk framing, pass decoded body bytes through the boundary-safe matcher, and re-encode output chunks with correct sizes. Preserve valid trailers, applying secret substitution only to trailer values.
- Fixed `Content-Length` input: remove `Content-Length`, set `Transfer-Encoding: chunked`, and stream transformed bytes as valid chunks. This avoids buffering an unbounded body solely to calculate the post-replacement length and allows `Expect: 100-continue` to operate.
- Fixed bodies with no applicable secret substitution: preserve `Content-Length` and stream bytes unchanged.
- Reject unsupported or ambiguous transfer codings.

Because the current contract replaces authorized placeholders anywhere in a request, every body sent to a domain with an applicable secret must be scanned. Change a fixed-length body to chunked whenever such a secret applies, even if another occurrence was already found in the request target or headers. Document that origins which reject chunked HTTP/1.1 request bodies may be incompatible with body-based secret substitution. Prefer correct framing over forwarding a stale `Content-Length`.

Flush the matcher at the exact end of each request body so bytes cannot carry into the next pipelined request. For chunked requests, finish the transformed chunk stream before forwarding trailers.

## Implementation Phases

### Phase 1: Configuration and validation

- Add proxy configuration types and redacted `Debug` implementations in `crates/lsb-proxy/src/config.rs`.
- Make domain matching reusable by secret and header host scopes.
- Add rule validation and configuration tests.
- Parse `network.https_interception` in `crates/lsb-cli/src/config.rs`.
- Add the structured field to `lsb_sdk::SandboxConfig` and runtime proxy construction.
- Add Node N-API types, conversion logic, generated TypeScript declarations, and binding tests.
- Update public re-exports.
- Confirm defaults leave interception off and preserve all existing configurations.

### Phase 2: MITM selection and CA lifecycle

- Select MITM per SNI domain when secrets or header rules apply.
- Add an explicit CA-required signal to the proxy handle.
- Update CLI, stdio, SDK, and Node-backed boot paths to install the CA for header-only interception.
- Keep placeholder environment construction separate.
- Add checkpoint CA cleanup/rotation behavior.
- Add routing tests proving excluded domains remain blind-tunnelled.

### Phase 3: HTTP/1.1 parsing and header mutation

- Add the request parser/state machine module and parser dependency.
- Implement header validation, set/replace behavior, fragmentation handling, keep-alive, and pipelining.
- Add response-side upgrade detection and opaque relay transition.
- Wire the transformer into `handle_mitm` without changing the blind relay.
- Remove the first-header-only progress observer once equivalent safe metrics exist.

### Phase 4: Secret substitution correctness

- Add the boundary-safe multi-pattern matcher.
- Apply substitution only to the request target, header/trailer values, and framed body data.
- Implement fixed-body-to-chunked conversion when body scanning is required.
- Implement chunk decoding, transformed re-chunking, and trailer handling.
- Remove the old per-read `replace_bytes_count` relay behavior.
- Ensure secret replacement and configured header mutation compose deterministically.

### Phase 5: Cross-platform performance benchmarks and Windows handoff

- Add `scripts/benchmark-windows-user-agent-injection.ps1` following the benchmark contract below.
- Keep the script self-contained and limited to PowerShell/.NET plus Windows-provided process inspection APIs.
- Add `scripts/benchmark-macos-user-agent-injection.sh` with equivalent scenarios, defaults, measurements, and output fields, using standard macOS process-inspection tools and a JSON-safe serializer.
- Generate matched disabled/enabled sandbox configurations and run the same HTTP/1.1 workload for both.
- Emit raw per-run JSON Lines plus a summary JSON document for downstream processing and graphing.
- Use the same schema version, scenario names, units, success rules, aggregation methods, and artifact layout on both platforms.
- Document the macOS and Windows invocations and expected artifacts.
- On macOS, first run a one-warm-up/one-iteration smoke benchmark, then run the default benchmark and retain its raw and summary artifacts.
- On macOS, review the Windows PowerShell script and, if `pwsh` is available, perform parser-only syntax validation. Do not execute the Windows benchmark or report Windows performance results from macOS.
- Hand the script and run instructions to a Windows agent for actual execution and artifact collection.

### Phase 6: Documentation, compatibility, and release readiness

- Document the JSON, Rust, and Node configuration with a caller-supplied User-Agent example.
- Clearly state port 443/SNI/HTTP/1.1 and certificate-trust limitations.
- Document host allow/deny precedence and domain wildcard behavior.
- Document the possible chunked-body compatibility impact for body secret substitution.
- Update README, skill references, changelog, and generated Node declarations.
- Run the full platform-appropriate test suites and add release notes emphasizing that the feature is off by default.

## Test Plan

### Configuration tests

- Missing interception config defaults to off.
- `enabled: false` with stored rules parses but does not intercept.
- `enabled: true` with no rules is rejected.
- Global rule applies to every normalized SNI domain.
- Allow-only, deny-only, and combined scopes follow the documented precedence.
- Deny wins when both lists match.
- Exact, wildcard, mixed-case, and trailing-dot domains match consistently with secrets.
- Empty explicit allow/deny arrays, duplicate header rules, malformed names/values, CRLF injection, and forbidden headers are rejected.
- Header values are redacted from all `Debug` output.
- Rust, JSON, and Node configurations produce equivalent proxy configs.

### Routing and trust tests

- Feature off plus no matching secret uses the blind tunnel.
- Feature on with a matching global/scoped rule enters MITM without secrets.
- A denied or non-allowed domain remains blind-tunnelled when no secret applies.
- A matching secret still enters MITM when header interception is off.
- Header and secret rules can independently cause MITM.
- CA installation occurs for header-only interception in CLI, stdio, and SDK paths.
- Header-only interception creates no secret environment variables.
- Checkpoint persistence does not retain an obsolete ephemeral proxy CA.

### Header transformation tests

- Insert an absent `User-Agent`.
- Replace existing `User-Agent` with mixed casing.
- Collapse duplicate existing instances to one configured value.
- Apply multiple configured headers in configuration order.
- Do not apply a scoped rule to a denied/non-allowed SNI domain.
- Ignore a forged or different HTTP `Host` for scope selection.
- Handle header terminators and individual header lines split across every possible read boundary.
- Transform every request on keep-alive and pipelined connections.
- Preserve bodies byte-for-byte when no secret applies.
- Preserve unmodified headers and request targets.
- Reject oversized, malformed, or request-smuggling-prone headers.
- Preserve `100 Continue` and switch to an opaque relay after a successful WebSocket upgrade.

### Secret replacement tests

- Replace a placeholder split at every possible byte boundary.
- Replace multiple different placeholders and repeated occurrences deterministically.
- Replace placeholders in the request target and header values.
- Replace placeholders split across fixed-body reads.
- Convert a fixed-length body to valid chunked framing and reconstruct the expected transformed body at the origin.
- Replace placeholders spanning original chunk boundaries in chunked bodies and emit correct new chunk sizes.
- Preserve and safely transform trailer values.
- Flush matcher carry at request boundaries so one request cannot combine with the next.
- Never replace header names, methods, or HTTP versions.
- Never send an unauthorized secret to a non-matching domain.
- Confirm logs and errors contain neither placeholders nor real secret values.

### Integration and regression tests

- Use a local TLS origin to verify the received User-Agent and custom headers without relying on the public internet.
- Run curl, Node.js, and Python HTTP/1.1 clients inside a VM against the local origin.
- Exercise macOS and Windows proxy transports.
- Verify ordinary HTTPS remains byte-tunnelled and trusted without installing the proxy CA when the feature is off.
- Verify secrets continue working in authorization headers.
- Verify a large fixed-length upload without applicable secrets streams without buffering or framing changes.
- Verify a large body with applicable substitution has bounded memory use.
- Verify non-HTTP TLS on port 443 fails clearly when selected for interception and remains blind when no rule applies.
- Run `cargo fmt --check`, workspace tests, clippy/static checks used by CI, and Node binding tests.

## macOS Benchmark Execution

Create `scripts/benchmark-macos-user-agent-injection.sh` and run it on the implementing agent's macOS host after the feature and release-mode `lsb` binary are ready. Its purpose is both to measure the local overhead of global User-Agent injection and to produce artifacts directly comparable with the later Windows run.

The macOS script must use the same two `disabled` and `enabled` configurations, caller-supplied User-Agent, HTTP/1.1 workload, URL default, warm-up count, measured iteration count, alternating scenario order, timeouts, success criteria, aggregation formulas, and JSON property names specified for Windows below. Accept equivalent kebab-case arguments such as `--binary`, `--url`, `--user-agent`, `--warmup-iterations`, `--iterations`, `--sample-interval-ms`, and `--results-root`.

Measure each complete `lsb run` invocation:

- wall-clock elapsed time in milliseconds using a monotonic clock;
- accumulated CPU seconds for the `lsb` process tree where observable;
- peak aggregate resident-set bytes sampled across the live process tree;
- exit code, timeout state, sample count, and measurement scope.

Use `ps` process snapshots keyed by PID plus process start time to discover descendants and sample cumulative CPU time and RSS. Apple Virtualization.framework runs primarily in the `lsb` host process, but still include any discovered descendants. Record `peak_private_memory_bytes` as JSON `null` unless the script obtains a semantically equivalent macOS private-memory measurement; do not substitute virtual size and label it as private memory. Include a `supported_metrics` array so downstream consumers can distinguish comparable fields from platform-only fields.

Write the same `runs.jsonl`, `summary.json`, `stdout/`, and `stderr/` layout as Windows. Add `platform`, `platform_version`, and `architecture` to each run record and the summary on both platforms. Use `platform: "macos"` for this script and `platform: "windows"` for the PowerShell script. The macOS summary should also include `sw_vers`, `uname`, logical processor count, total physical memory, binary SHA-256, `lsb --version`, and git revision when available.

The script must use a real JSON serializer rather than interpolating shell strings. It may use a small standard-library helper available on the implementation host, but it must check that dependency before starting and report it in benchmark metadata. Keep human-readable progress off stdout so stdout remains machine-readable.

After implementation:

1. Build `lsb` in release mode.
2. Run a smoke benchmark with one warm-up and one measured iteration per scenario.
3. Inspect both generated configurations and confirm both scenarios succeeded.
4. Run the default benchmark of one warm-up plus five measured iterations per scenario.
5. Validate every JSONL line and `summary.json` with a JSON parser.
6. Report the macOS summary and retain or attach the raw artifacts for later comparison.
7. State the feature commit, binary hash, benchmark URL, and whether the endpoint was local/controlled or public.

Do not present raw macOS-versus-Windows absolute time or memory differences as feature overhead. For platform comparison, primarily compare the enabled-minus-disabled delta and percentage within each platform, then compare those deltas across platforms. Record hardware and endpoint metadata because Apple Virtualization.framework versus WHPX/QEMU, CPU architecture, Defender, host load, and network latency can dominate the absolute figures.

## Windows Benchmark Handoff

Create `scripts/benchmark-windows-user-agent-injection.ps1` to measure the incremental cost of enabling global User-Agent injection on the Windows implementation using the same benchmark contract and schema as macOS. The implementing agent will work on macOS and therefore must not claim to have executed or validated the Windows benchmark results. A Windows agent will run it later against a Windows `lsb.exe`, WHPX/QEMU, and initialized runtime assets.

### Benchmark scenarios

The script must generate two temporary `lsb.json` files that are identical except for interception state:

- `disabled`: `https_interception.enabled` is `false`, with the User-Agent rule retained in configuration.
- `enabled`: `https_interception.enabled` is `true`, with one global `User-Agent` rule using a caller-supplied value.

For both scenarios, run the same command through the same binary and runtime assets. Use an explicitly HTTP/1.1 request, for example:

```text
curl --http1.1 -fsS -o /dev/null https://example.com/
```

Make the URL configurable because a Windows executor may have a controlled HTTPS endpoint that reduces public-network variance. Require `--allow-net` through configuration and avoid secrets so the disabled case remains a blind tunnel. The enabled case must exercise header-only MITM and CA installation.

Run one warm-up iteration per scenario by default, followed by five measured iterations per scenario. Make both counts configurable. Alternate measured scenarios by pair (`disabled`, `enabled`, then `enabled`, `disabled`) to reduce ordering, thermal, and cache bias. Record the actual order in every result.

### Script interface

At minimum, accept:

```powershell
param(
    [string]$Binary = ".\target\release\lsb.exe",
    [string]$Url = "https://example.com/",
    [string]$UserAgent = "lsb-user-agent-benchmark/1.0",
    [ValidateRange(0, 100)] [int]$WarmupIterations = 1,
    [ValidateRange(1, 1000)] [int]$Iterations = 5,
    [ValidateRange(25, 5000)] [int]$SampleIntervalMs = 100,
    [string]$ResultsRoot = ".\target\windows-user-agent-benchmark"
)
```

Allow optional runtime asset arguments if they are needed to match existing Windows benchmark conventions. Resolve paths before changing working directories, use a unique temporary/config directory, and avoid deleting any directory that has not passed an explicit safe-path check.

### Measurements

Measure each complete `lsb run` invocation from process start through exit:

- wall-clock elapsed time in milliseconds using `System.Diagnostics.Stopwatch`;
- total CPU time in seconds for `lsb.exe` and discovered descendants, including QEMU, where observable;
- peak aggregate working set bytes across the live process tree;
- peak aggregate private memory bytes across the live process tree;
- exit code and whether the sample is a warm-up or measured iteration.

Start `lsb.exe` with `System.Diagnostics.Process`, redirect stdout/stderr to per-run files, and poll the process tree at `SampleIntervalMs`. Discover descendants using `Win32_Process.ParentProcessId`, then sample `TotalProcessorTime`, `WorkingSet64`, and `PrivateMemorySize64` for the root and live descendants. Key sampled processes by PID plus start time to avoid PID-reuse errors. Accumulate CPU deltas per process so descendants that exit before the root can still contribute to the total.

Document that polling can undercount very short-lived descendants. Record the sampling interval and whether descendant discovery succeeded in each result. Do not silently fall back to root-only metrics: set a machine-readable scope/status field such as `measurement_scope: "process_tree"` or `measurement_scope: "root_only"` and include any sampling error.

Use bounded polling and process-exit timeouts. A failed or timed-out iteration must still produce a result record, retain its stdout/stderr files, and not be included in successful-run aggregate statistics.

### Machine-readable output

Write UTF-8 without BOM and use stable snake_case property names. Produce:

- `runs.jsonl`: one flat JSON object per warm-up or measured invocation;
- `summary.json`: benchmark metadata and aggregates grouped by scenario;
- `stdout/<run_id>.log` and `stderr/<run_id>.log`: diagnostic output kept outside the measurement records.

Each JSONL record should contain at least:

```json
{
  "schema_version": 1,
  "run_id": "...",
  "timestamp_utc": "...",
  "platform": "windows",
  "platform_version": "...",
  "architecture": "x86_64",
  "scenario": "disabled",
  "iteration": 1,
  "is_warmup": false,
  "order_index": 1,
  "exit_code": 0,
  "succeeded": true,
  "wall_time_ms": 1234.5,
  "cpu_time_seconds": 2.34,
  "peak_working_set_bytes": 123456789,
  "peak_private_memory_bytes": 123456789,
  "measurement_scope": "process_tree",
  "sample_interval_ms": 100,
  "sample_count": 13,
  "sampling_error": null
}
```

`summary.json` should include the platform, architecture, binary path, binary SHA-256, `lsb --version`, git revision when available, URL, redacted/non-sensitive User-Agent value, iteration settings, UTC start/end timestamps, Windows version, PowerShell version, logical processor count, total physical memory, supported metrics, and the raw artifact paths. For each scenario and metric, calculate successful measured-run count, minimum, maximum, arithmetic mean, median, standard deviation, and p95. Include an enabled-versus-disabled delta and percentage for the means, while retaining `runs.jsonl` as the source of truth for graphing. Keep these names and units identical to the macOS summary so the two outputs can be joined by schema version, platform, scenario, and metric.

Keep normal stdout machine-readable: print only a final compact JSON object containing the artifact paths and overall success status. Send human-readable progress to the information/verbose stream or stderr so pipeline consumers can safely parse stdout.

### Correctness and handoff checks

Before measured iterations, the script must verify that the binary exists, runtime assets are available, both generated configurations parse, and one preflight request succeeds for each scenario. If the selected endpoint can echo request headers, optionally accept an expected-header verification mode and confirm the enabled request observes the supplied User-Agent. Do not make a public echo service mandatory for the default benchmark.

The macOS implementing agent must:

- compare conventions with `scripts/benchmark-windows-overlay.ps1`;
- review quoting and argument-array construction without shell string concatenation;
- ensure generated JSON uses PowerShell objects plus `ConvertTo-Json`, not hand-built JSON strings;
- ensure all result records are emitted on failure paths;
- run whitespace/static repository checks;
- optionally use the PowerShell parser for syntax validation if available, without invoking the benchmark;
- leave an explicit handoff note stating that Windows execution remains pending.

The Windows executing agent must run at least one smoke invocation with one warm-up and one measured iteration per scenario before the full default run, confirm both scenarios succeed, inspect `runs.jsonl` and `summary.json`, and attach those files when reporting results.

## Risks and Mitigations

- **Global data disclosure:** Custom headers may contain credentials and global is the default scope. Document this prominently, redact values, and encourage allow lists for sensitive values.
- **MITM compatibility:** Pinned certificates, private trust stores, and mutual TLS will fail. Keep the feature opt-in and document the limitation.
- **Protocol downgrade/compatibility:** The proxy follows its existing HTTP/1.1-only MITM behavior. Test common clients and state that h2-only clients are unsupported.
- **Request smuggling:** Incorrect framing parsing is security-sensitive. Reject ambiguous framing and centralize parsing in a tested state machine.
- **Body framing changes:** Secret substitution in fixed bodies may require chunked upstream encoding. Limit this to requests whose bodies must be scanned and test `Expect: 100-continue`.
- **Performance:** Global interception adds TLS termination, parsing, certificate generation, and header rewriting to every applicable port-443 connection. Keep excluded domains blind, retain certificate caching, and benchmark connection setup plus large transfers.
- **Backpressure and memory:** Use bounded header buffers and streaming body transformation; do not collect whole uploads in memory.
- **Trust-store residue:** Explicitly remove ephemeral CAs before checkpoint persistence and test restored checkpoints.
- **Configuration drift:** Keep one canonical Rust model and conversion tests for CLI JSON and Node bindings.
- **Benchmark noise:** VM boot, CA installation, virtualization startup, endpoint latency, Defender, and host load may dominate header-injection cost. Use paired alternating runs, warm-ups, machine metadata, raw samples, and a configurable controlled endpoint; do not overstate conclusions from five iterations.
- **Benchmark accounting gaps:** Polling may miss short-lived child processes. Record measurement scope and sampling errors, retain the sample interval, and treat the figures as operational process-tree estimates rather than exact hardware counters.
- **Misleading platform comparisons:** macOS and Windows use different virtualization backends and may run on different hardware. Compare enabled-versus-disabled overhead within each host first, keep unsupported metrics null, and compare cross-platform deltas only with the recorded environment and endpoint metadata.

## Acceptance Criteria

- Existing users who do not configure HTTPS interception retain current blind-tunnel behavior.
- A caller can configure a User-Agent value at sandbox start and observe it on every interceptable HTTP/1.1 request to an applicable domain.
- Header rules are global when no host scope is given and honor allow/deny rules with deny precedence when configured.
- Excluded domains are not MITM'd solely because interception is enabled.
- Header-only interception installs the correct ephemeral CA without creating secret placeholders.
- Multiple keep-alive requests and fragmented headers are transformed correctly.
- Secret placeholders are replaced even when split across reads or HTTP chunks.
- Secret body replacement never leaves invalid `Content-Length` or chunk sizes.
- Unauthorized domains never receive configured scoped headers or real secret values.
- Header values, placeholders, and real secrets do not appear in logs.
- CLI JSON, Rust SDK, and Node.js configuration paths are documented and covered by tests.
- Port 443/SNI/HTTP/1.1 scope and MITM incompatibilities are explicitly documented.
- `scripts/benchmark-macos-user-agent-injection.sh` provides the same scenarios, units, schema, and artifact layout as Windows, and the implementing agent has run both its smoke and default benchmarks on macOS.
- The macOS benchmark report includes its summary, binary hash, feature revision, endpoint metadata, and retained raw JSONL artifacts.
- `scripts/benchmark-windows-user-agent-injection.ps1` provides matched disabled/enabled runs, configurable warm-ups and iterations, wall time, CPU, and peak memory measurements in JSONL plus summary JSON.
- The benchmark script is ready for Windows handoff, and the macOS implementation report explicitly states that Windows execution and performance results are pending.
- Both benchmark outputs identify platform, version, architecture, supported metrics, measurement scope, and use identical names for comparable fields so downstream tooling can graph them together.
