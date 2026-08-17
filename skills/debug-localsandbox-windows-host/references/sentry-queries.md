# Sentry query and collector reference

## Contents

- Current target and identity aliases
- Dataset strategy
- CLI limitations and fallbacks
- Completeness and security

## Current target and identity aliases

Use organization/project `sea/seawork` unless the user overrides them.

The shared project contains multiple producers. Query these fields separately and merge by stable ID:

| Alias | Current meaning |
| --- | --- |
| `user.id` | LocalSandbox Native service hostname; also present on some Node logs |
| `server.address` | Electron/Node workstation hostname in current releases |
| `host.name` | Canonical-compatible alias; may be absent from current releases |

The CLI rejects an expression such as `(user.id:X OR server.address:X)`. Never silently replace separate queries with one alias.

Use producer fields to classify results: `sdk.name`, `service.name`, `component`, `logger`, `release`, `environment`, and `project.name`.

## Dataset strategy

The collector queries:

- `issue list` once per identity alias, then group-wide `issue view` and host-filtered `issue events` for each unique issue
- Explore `errors` once per alias, then `event view` for each unique error event
- `trace list` once per alias, then `event view` for each unique transaction root
- Explore `spans` once per alias
- Explore `logs` once per alias
- attachment metadata and every attachment body for each exact hostname-matched issue, error, or transaction event
- `trace view`, trace-scoped `span list`, and `trace logs` for bounded unique trace IDs

Prefer Explore for logs because `sentry log list --json` returns only core columns and omits arbitrary attributes such as `server.address`.

Useful manual projections:

```bash
sentry explore sea/seawork --dataset errors \
  --query 'user.id:"FK6XB54"' \
  --field id --field timestamp --field title --field trace --field release --json

sentry explore sea/seawork --dataset logs \
  --query 'server.address:"FK6XB54"' \
  --field sentry.item_id --field timestamp --field message --field severity \
  --field sdk.name --field release --field trace --json

sentry trace list sea/seawork \
  --query 'user.id:"FK6XB54"' --period 14d --json
```

Use full error and transaction event bodies for tags, contexts, breadcrumbs, release/build data, and trace context:

```bash
sentry event view sea/seawork/<EVENT_ID> --json
```

Attachments are stored by event under `attachments/<EVENT_ID>/files/`, with one aggregate `attachments/index.jsonl`. The collector calls the project-event attachment endpoints through authenticated `sentry api`, requests up to 100 metadata rows per event, and downloads every returned attachment without content or size exclusions. It never uses group-wide issue metadata to select attachment event IDs.

The index preserves Sentry's size and SHA-1 alongside the downloaded size, SHA-1, and SHA-256. Binary responses are byte-preserving. The CLI can parse and reserialize JSON attachment responses, so a JSON attachment can have `matches_sentry_sha1:false` while retaining equivalent structured content.

`issue view` describes a cross-host group and can embed its latest event from a different machine. Never attribute that embedded event to the requested host. Use the collector's `issues/events/<ISSUE>.jsonl`, which is filtered separately by each hostname alias, or an exact event ID from the errors index.

## CLI limitations and fallbacks

- List commands cap pages at 1,000 rows. Follow `nextCursor` until `hasMore` is false or a collector cap is reached.
- Sentry Explore is a query/table API, not a guaranteed bulk export.
- On the current self-hosted deployment, `trace list` works while `trace view` may return HTTP 404 with maintenance HTML.
- The newer spans dataset may be empty even when legacy transaction events exist.
- `trace logs` can be empty when logs have no trace association.

When trace detail fails:

1. Keep the transaction row from `trace list`.
2. Fetch its event ID with `event view`.
3. Try trace-scoped spans and logs.
4. Record the capability failure as a gap; never reinterpret it as proof that no child activity occurred.

When a command fails, inspect `warnings.jsonl`. The collector redacts token- and authorization-shaped text before persisting diagnostics.

## Completeness and security

Results can be incomplete because of client sampling, retention, offline hosts, failed transport, rate limits, collector caps, and unavailable server endpoints. Always report the observed UTC interval and warnings.

Do not run `sentry auth token`. Do not place Sentry credentials in command arguments, bundle files, tickets, or chat.

Full event JSON and attachments can contain application data. Keep them in the requested local output directory and quote only the evidence needed in the conclusion. Download all attachments belonging to exact hostname-matched events, including incident ZIPs, logs, and dumps.
