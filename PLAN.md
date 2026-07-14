# Node.js Initialization Progress Plan

## Objective

Expose useful, per-invocation progress from the Node.js `initSandbox()` API so a downstream
consumer can distinguish a healthy first startup from a hung initialization and render download
progress while the boot assets are installed.

Keep the existing promise-based API and behavior for callers that do not request progress:

```ts
const result = await initSandbox(options)
```

Cancellation, resumable downloads, retry policy, and changes to the release artifact format are
outside the scope of this work.

## Findings

### Why first startup is opaque

The current call path is:

1. `bindings/nodejs/src/lib.rs::init_sandbox()` accepts `SandboxInitOptions` and starts one
   `tokio::task::spawn_blocking` job.
2. The blocking job calls `lsb_sdk::init_sandbox()` or `init_sandbox_version()`.
3. On Windows x86_64, `crates/lsb-sdk/src/host_tools.rs` may first download, hash, extract, install,
   and probe managed QEMU.
4. `crates/lsb-sdk/src/assets.rs::download_os_image_version()` then sends a synchronous `ureq`
   request and feeds the response directly through `GzDecoder` into `tar::Archive::unpack()`.
5. The SDK writes `VERSION`, pins the rootfs, and only then returns to the Node.js promise.

Nothing reports across the `spawn_blocking` boundary today. The event loop remains available, but
the caller sees only a pending promise until all of the synchronous work finishes or fails.

### The download is large enough to explain the complaint

GitHub release metadata for v0.4.5 reports these compressed artifact sizes:

| Artifact | Bytes | Approximate MiB |
| --- | ---: | ---: |
| macOS arm64 runtime assets | 269,729,017 | 257.2 |
| macOS/Windows x86_64 runtime assets | about 276,085,000 | 263.3 |
| Windows managed QEMU | 89,627,307 | 85.5 |
| Windows first-start total | 365,712,583 | 348.8 |

The Windows total is about 366 MB in decimal units before hashing and extraction, which is
consistent with the reported "around 400 MB" startup cost. The extracted rootfs is substantially
larger than the compressed transfer.

### Progress data is already available at the right boundary

- `ureq::Response` exposes `Content-Length`; the CLI already reads it for CLI self-upgrade in
  `crates/lsb-cli/src/assets.rs`.
- Both runtime and managed-QEMU downloads ultimately implement `std::io::Read`, so a counting reader
  can report compressed bytes consumed without buffering the full runtime archive.
- Runtime download and extraction are intentionally pipelined. Its phase must therefore be named
  "downloading and extracting" rather than claiming that those are two separately measurable
  operations.
- Managed QEMU is first downloaded to a staging archive, so its download, SHA-256 verification,
  extraction, and validation phases can be reported separately.
- NAPI-RS v3 supports `ThreadsafeFunction` fields in an input-only `#[napi(object,
  object_to_js = false)]`. This is the supported bridge for invoking a JavaScript callback from the
  blocking worker.

The existing CLI `ProgressReader` is useful precedent, but it is coupled to stderr and is only used
for the small CLI upgrade archive. The SDK needs a callback-based, output-agnostic equivalent.

## Recommended Public API

### Decision checkpoint

Before implementation, confirm the following public API with the Node.js binding maintainer. It is
the recommended design, but it is a public contract and should not be selected implicitly during
coding.

Add one optional callback to the existing options object:

```ts
export interface SandboxInitOptions {
  dataDir?: string
  version?: string
  force?: boolean
  fix?: boolean
  onProgress?: (progress: SandboxInitProgress) => void
}

export type SandboxInitProgressPhase =
  | 'checking'
  | 'applying-fixes'
  | 'downloading-host-tools'
  | 'verifying-host-tools'
  | 'extracting-host-tools'
  | 'validating-host-tools'
  | 'downloading-and-extracting-runtime-assets'
  | 'pinning-runtime-assets'

export interface SandboxInitProgress {
  phase: SandboxInitProgressPhase
  /** Compressed response bytes consumed; present only during a download phase. */
  downloadedBytes?: number
  /** Content-Length when supplied and valid; otherwise absent. */
  totalBytes?: number
}
```

Example:

```ts
const init = await initSandbox({
  onProgress(progress) {
    if (progress.downloadedBytes !== undefined && progress.totalBytes !== undefined) {
      const percent = Math.floor((progress.downloadedBytes / progress.totalBytes) * 100)
      console.log(`${progress.phase}: ${percent}%`)
    } else {
      console.log(progress.phase)
    }
  },
})
```

The promise remains the authoritative completion/error channel. Do not add a separate `complete`
or `error` progress event: promise resolution/rejection already represents those states and avoids
ordering races between a final queued callback and promise settlement.

### Event semantics

- Emit `checking` immediately when the blocking initialization begins, including on an already-ready
  data directory.
- Emit `applying-fixes` only when `fix: true`.
- Emit a download event at zero bytes once response headers are available, then at most once per
  additional MiB, plus a final EOF event. This keeps a first Windows startup below roughly 350
  download notifications.
- Keep `downloadedBytes` monotonic within each download phase. It resets to zero when Windows moves
  from the host-tools artifact to runtime assets.
- Treat `totalBytes` as optional. Do not send zero or invent a total when `Content-Length` is absent,
  invalid, or zero.
- Report compressed network bytes, not extracted bytes. Document this explicitly.
- Never emit 100% before EOF. If a server-provided total disagrees with actual bytes, report actual
  bytes and let the consumer clamp presentation; do not falsify the counters.
- Phase events are observational. They must not change readiness checks, installation order, error
  propagation, or cleanup behavior.
- Use a non-blocking thread-safe callback so a slow JavaScript handler cannot stall download or
  extraction. A callback return value is ignored. Document that the callback must not throw.
- If the JavaScript environment is closing, stop attempting notifications and allow the existing
  initialization/shutdown behavior to proceed.

### Why not polling or a new operation handle

- A module-global `getInitProgress()` cannot identify which concurrent `initSandbox()` call it
  describes and would retain cross-call state.
- Returning a new operation handle or async iterator would replace the established
  `Promise<SandboxInitResult>` contract and require more lifecycle/cancellation behavior than this
  issue needs.
- A callback is scoped to one invocation, is optional, and leaves every existing call site source-
  and runtime-compatible.

## Implementation Plan

### Phase 1: Add an SDK progress model without breaking existing Rust callers

Add a small progress module in `crates/lsb-sdk`, containing internal/public Rust equivalents of the
phase and progress types plus a reporter abstraction.

- [ ] Define `SandboxInitProgressPhase` and `SandboxInitProgress` as owned, cloneable Rust values.
- [ ] Define a synchronous reporter interface accepted by reference for the duration of init. The
      reporter is called on the same worker thread as initialization; it must not know about N-API.
- [ ] Add progress-aware entry points such as `init_sandbox_with_progress()` and
      `init_sandbox_version_with_progress()`.
- [ ] Keep `SandboxInitOptions` unchanged. Adding a public field would break external Rust struct
      literals even if that field were optional.
- [ ] Make the existing `init_sandbox()` and `init_sandbox_version()` delegate to the new internal
      implementation with a no-op reporter, preserving the published Rust API.
- [ ] Add a progress-aware internal host-tools initializer while keeping `init_host_tools()` as its
      compatibility wrapper.
- [ ] Re-export only the progress types/functions needed by the Node.js binding from
      `crates/lsb-sdk/src/lib.rs`.

### Phase 2: Instrument runtime asset installation

Refactor `crates/lsb-sdk/src/assets.rs` without changing the streaming extraction behavior.

- [ ] Read and parse `Content-Length` before consuming the `ureq::Response` body, using the same
      defensive parsing pattern as the CLI upgrade path.
- [ ] Introduce a generic counting `Read` wrapper that reports zero, MiB boundaries, and EOF.
- [ ] Place the wrapper between the response body reader and `GzDecoder`, so reported bytes are the
      compressed bytes actually consumed by tar extraction.
- [ ] Emit `downloading-and-extracting-runtime-assets` from that wrapper.
- [ ] Emit `pinning-runtime-assets` immediately before `lsb_store::pin_base_version()` on both the
      fresh-download and ready-but-not-yet-pinned paths.
- [ ] Do not emit a runtime download phase when assets and `VERSION` are already ready and `force`
      is false.
- [ ] Preserve the current order: create data directory, stream/unpack, write `VERSION`, then pin.
      Progress must not cause `VERSION` to be written earlier.

### Phase 3: Instrument Windows managed host tools

Thread the same SDK reporter through `crates/lsb-sdk/src/host_tools.rs`.

- [ ] Keep the existing valid-install fast path under `checking` and emit no download events for it.
- [ ] Capture the QEMU response `Content-Length` and wrap the response reader passed to
      `std::io::copy()` with the counting reader using phase `downloading-host-tools`.
- [ ] Emit `verifying-host-tools` before `sha256_file()`.
- [ ] Emit `extracting-host-tools` before archive extraction.
- [ ] Emit `validating-host-tools` before manifest validation and executable probes.
- [ ] Preserve staging-file removal and temporary extraction-directory cleanup on every error.
- [ ] On non-Windows platforms, keep host-tool initialization a no-op and do not emit Windows-only
      phases.

If sharing the exact counting reader between `assets.rs` and `host_tools.rs` would expose awkward
module dependencies, place it in the new SDK progress module. Do not duplicate the throttling and
EOF rules.

### Phase 4: Bridge progress into Node.js

Update the binding while retaining `initSandbox(opts?) => Promise<SandboxInitResult>`.

- [ ] Add output-only N-API progress types in `bindings/nodejs/src/types.rs` and map the SDK phase
      values to the documented kebab-case strings.
- [ ] Add `onProgress` to `SandboxInitOptions` as an optional `ThreadsafeFunction` with
      `CalleeHandled = false`, so TypeScript receives `(progress) => void`, not an error-first
      `(error, progress) => void` callback.
- [ ] Mark `SandboxInitOptions` as `#[napi(object, object_to_js = false)]`; it is an input-only shape
      and NAPI-RS requires that mode for a thread-safe-function field.
- [ ] Extract the callback before converting the remaining fields in
      `bindings/nodejs/src/config.rs`.
- [ ] Inside the existing `spawn_blocking` closure, build an SDK reporter that maps each event to a
      Node progress object and invokes the callback with `ThreadsafeFunctionCallMode::NonBlocking`.
- [ ] Check the returned N-API status. Ignore normal `Closing` during environment teardown, but cover
      unexpected statuses in tests/debug assertions without converting progress-delivery failure
      into a corrupt or half-installed asset state.
- [ ] When `onProgress` is absent, use the existing no-op SDK entry point so there is no N-API queue
      work and negligible overhead.
- [ ] Keep unsupported-platform errors and `SandboxInitResult` mapping unchanged.

### Phase 5: Types, documentation, and release notes

- [ ] Regenerate `bindings/nodejs/index.d.ts` through the existing NAPI build workflow and verify the
      callback is optional and has exactly one progress argument.
- [ ] Add a progress-bar example and event-semantics notes to the "Initialize runtime assets"
      section of `bindings/nodejs/README.md`.
- [ ] Explain that Windows can report two separate downloads and that byte counters reset for the
      second artifact.
- [ ] Note that `totalBytes` is optional and that runtime bytes represent the compressed stream being
      downloaded and extracted.
- [ ] Add a changelog entry describing this as a backward-compatible Node.js API addition.

Do not add stderr output to the Node.js binding. Output policy belongs to its consumer.

## Test Plan

### SDK unit tests

- [ ] Feed the counting reader a deterministic in-memory byte stream and assert zero, threshold, and
      EOF notifications.
- [ ] Assert byte counts are monotonic, never exceed actual bytes read, and retain `None` when the
      total is unknown.
- [ ] Cover an input smaller than one MiB, exactly one MiB, multiple MiB in one large read, empty
      input, and an injected read error.
- [ ] Refactor archive installation behind a reader-oriented helper and use a tiny in-memory gzip/tar
      fixture to prove runtime progress without network access.
- [ ] Assert an already-ready runtime emits checking/pinning as applicable but no download phase.
- [ ] Assert `force: true` takes the instrumented download path.
- [ ] Extend managed-QEMU archive tests to assert verify, extract, and validate ordering while
      retaining cleanup on hash mismatch and unsafe archive entries.
- [ ] Assert the no-op reporter produces the same `SandboxInitResult` and filesystem state as before.

### Node.js tests

- [ ] Extend `bindings/nodejs/test/api-shape.spec.ts` to assert `onProgress`, the progress interface,
      and the one-argument callback signature in generated declarations.
- [ ] Extend the already-present-assets test to collect progress events and assert the first event is
      `checking`, no download phase is emitted, and the final promise result remains unchanged.
- [ ] Add a binding-level test that proves callbacks execute on JavaScript's thread while the init
      work runs in `spawn_blocking` and that omitting the callback remains valid.
- [ ] Verify progress callbacks do not use the Node error-first convention.
- [ ] Keep tests deterministic and offline; do not make the normal suite download a release archive.

### Manual fresh-install smoke tests

Run these against a disposable empty `dataDir` because they intentionally download large artifacts.

- [ ] On macOS arm64 or x86_64, observe a monotonic runtime-assets percentage and successful promise
      resolution.
- [ ] On Windows x86_64 with no managed QEMU in that data directory, observe host-tools download,
      verify/extract/validate, followed by a second runtime-assets download.
- [ ] Repeat with the same directory and verify there is no download phase.
- [ ] Repeat with `force: true` and verify downloads are reported again.
- [ ] Interrupt network access mid-download and verify the promise rejects, no false completion is
      reported, and existing cleanup behavior is preserved.
- [ ] Test a response without `Content-Length` through a local test endpoint and verify byte counts
      still advance without a percentage total.

## Verification Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test -p lsb-sdk --locked
cargo check --workspace --locked
cargo clippy --workspace --locked

cargo fmt --manifest-path bindings/nodejs/Cargo.toml -- --check
cargo check --manifest-path bindings/nodejs/Cargo.toml --locked
cd bindings/nodejs
yarn test
yarn lint
```

Also run the binding build/test on Windows x86_64; macOS alone cannot exercise managed-QEMU phase
ordering.

## Acceptance Criteria

- [ ] Existing `await initSandbox()` and `await initSandbox(options)` callers behave exactly as
      before without source changes.
- [ ] A first-start caller receives phase changes and monotonic compressed-byte progress while the
      promise is pending.
- [ ] Known `Content-Length` responses allow a percentage; unknown totals still expose bytes and
      phase.
- [ ] Windows reports the QEMU and runtime downloads as distinct phases.
- [ ] Ready assets produce no misleading download events.
- [ ] Progress reporting neither blocks JavaScript's event loop nor lets JavaScript handler speed
      control the download worker.
- [ ] Download, verification, extraction, cleanup, version-marker, and pinning semantics are
      unchanged.
- [ ] Offline unit/API-shape tests cover the contract; large real downloads remain manual smoke
      tests.
- [ ] README, generated declarations, and changelog agree on callback shape and byte semantics.
