# SeaWork production parity contract

`contracts/seawork-parity-v1.json` is the versioned acceptance inventory for the
SeaWork Windows service replacement. Its authority is the decision record in
`backlog.md` and SeaWork commit
`0ae88c6d338ffb10d765296625ea38b3b3991f64`, using
`@local-sandbox/lsb-nodejs` 0.4.6.

The contract deliberately separates production reachability from LocalSandbox's wider
SDK. The pinned helper reaches start, exec, spawn, read, write, mkdir, process kill, and
stop. It also forwards mounts, ports, network policy, host exposure, secrets, resource
shape, `instanceId`, `dataDir`, and the legacy `from` string. The pinned source contains
no checkpoint operation or checkpoint producer, so a non-empty `from` must fail with
`CHECKPOINT_UNSUPPORTED` rather than selecting any path or state.

`instanceId` is a bounded one-shot replay key, never a filesystem name or sandbox
adoption token. Protocol 1.4 caches only service-generated start outcomes. A replay on
the owning live connection returns the same opaque sandbox handle. Disconnect still
cleans every owned resource; the replay key becomes a bounded tombstone and reconnect
returns non-retryable `START_RESULT_EXPIRED`, requiring an explicit new `instanceId`
instead of silently creating or adopting a VM.

Protocol 1.5 adds commit-aware filesystem cancellation. A cancellation that wins before
commit returns only after cleanup as `CANCELLED`; one that loses to commit returns
`CANCELLATION_TOO_LATE` on the Cancel control while the original operation reports its
actual result. Protocol 1.4 clients receive the already-known `REQUEST_NOT_ACTIVE` for
that too-late Cancel control.

Each parity entry is one of:

- `equivalent`: the host-neutral service contract already matches the reachable
  behavior;
- `service-superset`: the service is safer or offers additional behavior without
  removing the reachable capability; or
- `blocking`: the named backlog item must be completed before replacement.

The status is an implementation inventory, not Windows acceptance evidence. All four
required role sign-offs remain `external-verification-pending` until the installed,
signed real-Windows matrix passes.

## Verification

Validate the committed contract and golden fixture shapes on any development host:

```sh
cargo run -p xtask -- verify-seawork-parity
```

Re-run every positive and negative pinned-source assertion when the SeaWork repository
is available:

```sh
cargo run -p xtask -- verify-seawork-parity --seawork-repo ~/code/seawork
```

The command fails if the baseline changes, a required field/capability disappears, a
blocking entry lacks a backlog link, a fixed limit drifts, a fixture is malformed, or a
pinned source assertion no longer holds.

## Golden workload handoff

The files under `fixtures/seawork-parity/` define deterministic inputs and assertions
for helper-versus-service comparison. The runner must execute each workload twice on a
disposable Windows machine, normalize only opaque identifiers and timestamps, and
compare the listed filesystem, network, stream-order, exit, and stable-error effects.
The fixtures are committed now; their `blocking` status stays in the contract until the
dual-backend Windows runner and evidence pass.
