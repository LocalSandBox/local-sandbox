# Filesystem cancellation and commit semantics

Status: CAN-01 macOS state-machine tranche implemented; Windows guest-call and SCM-drain
verification pending.

## Decision

Protocol 1.5 makes cancellation and mutation commit a single atomic race. An active
request can move to `cancelled`, `deadline-exceeded`, or `committing`; no transition out
of `committing` is allowed. The dispatcher does not publish a terminal cancellation or
deadline response merely because the token changed. It waits for the bounded VM worker
to settle, including staging cleanup, and the RPC maps the typed reason to `CANCELLED`
or `DEADLINE_EXCEEDED`.

If a Cancel control loses the race to `committing`, the control receives non-retryable
`CANCELLATION_TOO_LATE` on protocol 1.5. The original request remains active and returns
the actual success or failure of the already-unavoidable operation. A negotiated 1.4
client receives the already-known `REQUEST_NOT_ACTIVE` for that Cancel control while the
original request still completes. This avoids sending an unknown enum to an older
strict client.

The request token is separate from the session-shutdown token. Session teardown remains
unconditionally signalled; a controller clone already executing a commit owns the fixed
per-VM worker until the call returns, after which channel disconnect stops and removes
the ephemeral VM. This bounds workers by the existing sandbox quotas rather than
detaching a new thread per cancellation.

## Operation model

| RPC | Cancellable preparation | Commit point | Failure/cleanup model |
| --- | --- | --- | --- |
| `Mkdir` | Queue admission and pre-dispatch checks | Immediately before the one synchronous guest `mkdir` request | The guest reports the real call result. Recursive creation can have a reported partial result on a guest I/O failure; cancellation cannot hide it. |
| `Remove` | Queue admission and pre-dispatch checks | Immediately before the one synchronous guest `remove` request | The real guest result is returned. Recursive deletion is not rolled back after an I/O failure and is never reported as cancellation after dispatch. |
| `Rename` | Queue admission and pre-dispatch checks | Immediately before the guest rename | The guest filesystem rename is the atomic mutation. |
| `Copy` | Queue admission and pre-dispatch checks | Immediately before the one synchronous guest copy request | The real guest result is returned. Recursive copy can have a reported partial result on a guest I/O failure; cancellation cannot hide it. |
| `Chmod` | Queue admission and pre-dispatch checks | Immediately before the guest metadata update | The one metadata update is the atomic mutation. |
| `WriteFile` | Upload collection plus write to a random sibling temporary | Immediately before rename of the complete sibling over the destination | Cancellation or expiry before commit removes the sibling and settles only after cleanup. Rename is atomic; write or rename errors attempt sibling cleanup and return the real failure. |

Read-only file RPCs retain pre- and post-call cancellation checks and never enter the
commit state. Pending uploads have no guest state, so cancellation drops their bounded
buffer before returning `CANCELLED`.

## Required verification

Host-neutral tests cover cancellation/deadline as the first terminal request, commit as
the atomic winner, connection-state too-late reporting, and the before-dispatch, queued,
before-commit, during-call, and after-commit schedule for all six mutating RPCs. Protocol
tests pin the new stable error and 1.5 negotiation.

The Windows runner must still inject faults around real guest calls, immediately around
the write rename, and during failed sibling cleanup; assert the target and temporary
tree after each case; and exercise connection loss, caller exit, STOP, and preshutdown.
Recursive mkdir/copy/remove I/O-failure behavior is explicitly reported rather than
claimed atomic and remains a separate journaling improvement if product parity later
requires rollback on non-cancellation guest failures.
