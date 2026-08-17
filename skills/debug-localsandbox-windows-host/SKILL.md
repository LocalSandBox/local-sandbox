---
name: debug-localsandbox-windows-host
description: Investigate LocalSandbox and related SeaWork Windows telemetry by raw machine hostname, correlate Sentry issues, error events, transactions, traces, spans, and structured logs across components, inspect the repository, and report an evidence-backed root cause with fixes and follow-ups. Use when a user supplies a Windows hostname such as FK6XB54 and asks to debug a LocalSandbox Windows service, desktop, installer, update, sandbox, QEMU, startup, shutdown, or other host-specific problem.
---

# Debug LocalSandbox Windows Host

Build an observed Sentry telemetry bundle for one Windows hostname, then use it with the user's issue description and repository evidence to diagnose the problem. Continue through root-cause analysis; collecting telemetry alone is not completion.

## Required input

Require a raw Windows hostname. Accept an issue description and additional context in any form. If no time or incident timestamp is supplied, start with the last 14 days and narrow around relevant events.

Do not require `service.name`: the bundle intentionally includes related Electron, installer, updater, LocalSandbox service, and other SeaWork components on the host.

## Collect observed telemetry

From the repository root, run:

```bash
python3 skills/debug-localsandbox-windows-host/scripts/collect_observed_telemetry.py \
  --host <HOSTNAME> \
  --period 14d \
  --issue-description '<ISSUE>' \
  --context '<ADDITIONAL_CONTEXT>'
```

Use `--from` and `--to` instead of `--period` when the user gives a bounded incident window. Pass repeated `--context` values when useful. Let the script choose its timestamped output directory unless the user requests a path.

The collector uses the current compatibility aliases separately because the Sentry CLI does not support cross-field `OR`:

- `user.id`: current LocalSandbox Windows service hostname and some other components
- `server.address`: current Electron/Node hostname alias
- `host.name`: reserved for compatible/newer producers

It merges and deduplicates results. Treat every result as observed telemetry, never exhaustive machine history.

If `sentry` is missing, authentication fails, or the project cannot be accessed, report the exact blocker and the successful local checks. Do not print, request, or persist an auth token. Read [references/sentry-queries.md](references/sentry-queries.md) when the collector reports query, pagination, trace, or dataset problems.

## Analyze the bundle

1. Read `manifest.json`, `summary.json`, and `warnings.jsonl` first.
2. Read the normalized JSONL indices and build a UTC timeline around the reported symptom.
3. Separate components using `sdk.name`, `service.name`, `component`, release, logger, transaction, and message. Do not mistake shared-project Electron logs for Native service logs.
4. Correlate by exact `trace`, `run_id`, event ID, update attempt/transaction ID, correlation ID, resource ID, and timestamps. Use hostname alone only to discover candidates.
5. Read full event and issue details for the strongest candidates. Treat `issues/details/*.json` as group-wide metadata: its embedded latest event may belong to another hostname. Use `issues/events/*.jsonl` or exact host-matched error events for occurrence evidence. Treat missing trace detail as an observability gap when the manifest records the current server-side trace API limitation.
6. Inspect `attachments/index.jsonl` and every downloaded file under `attachments/<EVENT_ID>/files/`. The collector downloads every attachment on each exact hostname-matched event without MIME-type, filename, dump, or size filtering. Use the attachment metadata and hashes to distinguish duplicate files and verify binary fidelity. Sentry CLI may reserialize JSON responses; when that occurs, `matches_sentry_sha1` is false even though the JSON content is present and agent-readable.
7. Read [references/localsandbox-telemetry.md](references/localsandbox-telemetry.md), then inspect the relevant repository paths. Use `rg` first. Compare telemetry release/build metadata with the checked-out code; use read-only Git history when the affected release differs from the checkout.
8. Test competing explanations against both supporting and contradicting evidence. Distinguish the initiating cause, downstream failures, recovery behavior, and user-visible symptom.
9. If Sentry evidence and its attachments end at an unclean exit, unavailable transport, or sampled trace, use the documented protected local evidence as a requested follow-up rather than inventing missing facts.

## Reach a conclusion

Assign one conclusion state:

- **Confirmed**: direct telemetry and code behavior establish the cause.
- **Probable**: evidence strongly favors one cause but one required observation is missing.
- **Inconclusive**: multiple live explanations remain; state exactly what evidence would decide between them.

Do not call the latest error or an `UNCLEAN_PREVIOUS_EXIT` companion event the root cause unless evidence establishes what ended the prior process.

Recommend fixes in this order:

1. Immediate user mitigation or recovery, when safe and supported by evidence.
2. Code/configuration fix tied to the causal path.
3. Verification tests and rollout checks.
4. Operational or telemetry follow-ups that would close remaining gaps.

The user has deferred canonical-host migration and Native structured-log dual writing. Do not make those prerequisites for the current diagnosis or primary fixes. Mention their absence only when it materially limits confidence.

## Report

Return:

- hostname and observed UTC window
- concise symptom timeline across components
- root cause and confidence state
- strongest evidence with event/issue/trace IDs and relevant repository paths
- fixes and immediate mitigation
- verification plan and follow-ups
- material gaps or sampling/retention caveats
- absolute path to the generated bundle

Keep raw telemetry in the bundle. Summarize it in the response instead of pasting large event bodies.
