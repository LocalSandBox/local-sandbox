#!/usr/bin/env python3
"""Collect a bounded, agent-readable Sentry bundle for one Windows hostname."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Iterable


DEFAULT_TARGET = "sea/seawork"
IDENTITY_FIELDS = ("user.id", "server.address", "host.name")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$")
TOKEN_RE = re.compile(r"(?i)(sntry[a-z]*_[A-Za-z0-9._-]+|Bearer\s+\S+)")
AUTH_ENV_RE = re.compile(r"(?i)(SENTRY_AUTH_TOKEN\s*[=:]\s*)\S+")

ERROR_FIELDS = (
    "id",
    "timestamp",
    "title",
    "level",
    "user.id",
    "server.address",
    "host.name",
    "component",
    "service.name",
    "sdk.name",
    "release",
    "environment",
    "trace",
    "error.code",
    "operation",
    "previous_exit.kind",
    "previous_exit.reason",
    "run_id",
    "update.attempt_id",
    "update.transaction_id",
)
SPAN_FIELDS = (
    "id",
    "parent_span",
    "timestamp",
    "span.op",
    "description",
    "span.duration",
    "transaction",
    "trace",
    "user.id",
    "server.address",
    "host.name",
    "component",
    "service.name",
    "sdk.name",
    "release",
    "environment",
)
LOG_FIELDS = (
    "sentry.item_id",
    "timestamp",
    "message",
    "severity",
    "trace",
    "span_id",
    "user.id",
    "server.address",
    "host.name",
    "component",
    "service.name",
    "sdk.name",
    "release",
    "environment",
)


class CollectionError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect observed Sentry telemetry for a Windows hostname."
    )
    parser.add_argument("--host", required=True, help="Raw Windows hostname")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Sentry org/project")
    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument("--period", default=None, help="Sentry period such as 14d")
    time_group.add_argument("--from", dest="start", help="Inclusive ISO-8601 UTC start")
    parser.add_argument("--to", dest="end", help="Inclusive ISO-8601 UTC end")
    parser.add_argument("--output", type=Path, help="Output directory")
    parser.add_argument("--issue-description", default="", help="User-reported symptom")
    parser.add_argument(
        "--context",
        action="append",
        default=[],
        help="Additional debugging context; repeat as needed",
    )
    parser.add_argument(
        "--max-rows",
        type=positive_int,
        default=10_000,
        help="Maximum merged rows per dataset",
    )
    parser.add_argument(
        "--max-events",
        type=positive_int,
        default=500,
        help="Maximum full error/transaction events to enrich",
    )
    parser.add_argument(
        "--max-issues",
        type=positive_int,
        default=250,
        help="Maximum issue details to enrich",
    )
    parser.add_argument(
        "--max-traces",
        type=positive_int,
        default=100,
        help="Maximum trace IDs to enrich",
    )
    args = parser.parse_args()
    if bool(args.start) != bool(args.end):
        parser.error("--from and --to must be supplied together")
    if not args.period and not args.start:
        args.period = "14d"
    if not HOST_RE.fullmatch(args.host):
        parser.error("hostname must contain only letters, digits, dots, and hyphens")
    if "/" not in args.target or args.target.startswith("/") or args.target.endswith("/"):
        parser.error("--target must be <org>/<project>")
    return args


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def redact(text: str) -> str:
    text = TOKEN_RE.sub("[REDACTED]", text)
    return AUTH_ENV_RE.sub(r"\1[REDACTED]", text)


def summarize_error(text: str) -> str:
    cleaned = redact(text).strip()
    cleaned = "\n".join(
        line
        for line in cleaned.splitlines()
        if not any(
            marker in line
            for marker in (
                "[auth]",
                "SENTRY_AUTH_TOKEN",
                "SENTRY_FORCE_ENV_TOKEN",
            )
        )
    ).strip()
    if "<!doctype html" not in cleaned.lower() and "<html" not in cleaned.lower():
        return cleaned[-4_000:]
    prefix = cleaned.split("<!doctype html", 1)[0].strip()
    title = re.search(r"<title>(.*?)</title>", cleaned, flags=re.IGNORECASE | re.DOTALL)
    parts = [prefix[-1_500:] or "HTML error response"]
    if title:
        parts.append(f"HTML title: {' '.join(title.group(1).split())}")
    return "\n".join(parts)


def sentry_query(field: str, host: str) -> str:
    return f'{field}:"{host}"'


def time_args(args: argparse.Namespace) -> list[str]:
    if args.period:
        return ["--period", args.period]
    return ["--period", f"{args.start}..{args.end}"]


def safe_filename(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return normalized[:180] or "unknown"


def json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def jsonl_dump(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")


class Collector:
    def __init__(self, args: argparse.Namespace, root: Path) -> None:
        self.args = args
        self.root = root
        self.warnings: list[dict[str, Any]] = []
        self.queries: list[dict[str, Any]] = []
        self.caps_hit: set[str] = set()

    def warn(self, stage: str, message: str, command: list[str] | None = None) -> None:
        warning: dict[str, Any] = {
            "timestamp": now_utc(),
            "stage": stage,
            "message": summarize_error(message),
        }
        if command:
            warning["command"] = command
        self.warnings.append(warning)

    def run_json(
        self, command: list[str], stage: str, *, required: bool = False
    ) -> Any | None:
        completed = subprocess.run(
            command,
            cwd=Path.cwd(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "unknown CLI error"
            self.warn(stage, f"exit {completed.returncode}: {detail}", command)
            if required:
                raise CollectionError(f"{stage} failed: {redact(detail)[-1_000:]}")
            return None
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.warn(stage, f"non-JSON response: {error}: {completed.stdout[-2_000:]}", command)
            if required:
                raise CollectionError(f"{stage} returned invalid JSON") from error
            return None

    def run_bytes(self, command: list[str], stage: str) -> bytes | None:
        completed = subprocess.run(
            command,
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=os.environ.copy(),
        )
        if completed.returncode != 0:
            detail = (
                completed.stderr.decode("utf-8", errors="replace").strip()
                or completed.stdout.decode("utf-8", errors="replace").strip()
                or "unknown CLI error"
            )
            self.warn(stage, f"exit {completed.returncode}: {detail}", command)
            return None
        return completed.stdout

    def collect_attachments(self, event_ids: list[str]) -> dict[str, int]:
        org, project = self.args.target.split("/", 1)
        records: list[dict[str, Any]] = []
        events_with_attachments = 0
        attachment_bytes = 0
        failed = 0

        for event_id in event_ids:
            base = f"projects/{org}/{project}/events/{event_id}/attachments"
            metadata = self.run_json(
                ["sentry", "api", f"{base}/?per_page=100", "--json"],
                f"attachment-list:{event_id}",
            )
            if metadata is None:
                failed += 1
                continue
            if not isinstance(metadata, list):
                self.warn(
                    f"attachment-list:{event_id}",
                    "JSON response did not contain an attachment list",
                )
                failed += 1
                continue
            if len(metadata) >= 100:
                self.warn(
                    f"attachment-list:{event_id}",
                    "attachment listing reached 100 rows; the API response may require cursor pagination",
                )
            if metadata:
                events_with_attachments += 1

            event_root = self.root / "attachments" / safe_filename(event_id)
            json_dump(event_root / "metadata.json", metadata)
            for attachment in metadata:
                if not isinstance(attachment, dict):
                    self.warn(
                        f"attachment-list:{event_id}",
                        "attachment metadata contained a non-object entry",
                    )
                    failed += 1
                    continue
                attachment_id = str(attachment.get("id") or "")
                if not attachment_id:
                    self.warn(
                        f"attachment-download:{event_id}",
                        "attachment metadata did not contain an id",
                    )
                    failed += 1
                    continue
                original_name = str(attachment.get("name") or attachment_id)
                basename = original_name.replace("\\", "/").rsplit("/", 1)[-1]
                local_name = (
                    f"{safe_filename(attachment_id)}--{safe_filename(basename)}"
                )
                destination = event_root / "files" / local_name
                payload = self.run_bytes(
                    ["sentry", "api", f"{base}/{attachment_id}/?download=1"],
                    f"attachment-download:{event_id}:{attachment_id}",
                )
                record = {
                    "event_id": event_id,
                    "attachment_id": attachment_id,
                    "name": original_name,
                    "mimetype": attachment.get("mimetype"),
                    "sentry_size": attachment.get("size"),
                    "sentry_sha1": attachment.get("sha1"),
                }
                if payload is None:
                    record["status"] = "failed"
                    failed += 1
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(payload)
                    downloaded_sha1 = hashlib.sha1(payload).hexdigest()
                    record.update(
                        {
                            "status": "downloaded",
                            "local_path": str(destination.relative_to(self.root)),
                            "downloaded_size": len(payload),
                            "downloaded_sha1": downloaded_sha1,
                            "downloaded_sha256": hashlib.sha256(payload).hexdigest(),
                            "matches_sentry_sha1": downloaded_sha1
                            == str(attachment.get("sha1") or ""),
                        }
                    )
                    attachment_bytes += len(payload)
                records.append(record)

        jsonl_dump(self.root / "attachments" / "index.jsonl", records)
        return {
            "attachment_events_queried": len(event_ids),
            "events_with_attachments": events_with_attachments,
            "attachments_found": len(records),
            "attachments_downloaded": sum(
                1 for record in records if record["status"] == "downloaded"
            ),
            "attachment_download_failures": failed,
            "attachment_bytes_downloaded": attachment_bytes,
        }

    def paginate(
        self,
        command: list[str],
        stage: str,
        *,
        row_cap: int,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        pages = 0
        truncated = False
        while len(rows) < row_cap:
            current = [*command]
            if cursor:
                current.extend(["--cursor", cursor])
            payload = self.run_json(current, stage)
            if payload is None:
                break
            pages += 1
            page_rows = payload.get("data", payload if isinstance(payload, list) else [])
            if not isinstance(page_rows, list):
                self.warn(stage, "JSON response did not contain a row list", current)
                break
            rows.extend(row for row in page_rows if isinstance(row, dict))
            has_more = bool(payload.get("hasMore")) if isinstance(payload, dict) else False
            next_cursor = payload.get("nextCursor") if isinstance(payload, dict) else None
            if len(rows) > row_cap or (len(rows) >= row_cap and has_more):
                truncated = True
            if not has_more:
                break
            if not next_cursor or next_cursor in seen_cursors:
                self.warn(stage, "pagination reported more rows without a fresh cursor", current)
                break
            seen_cursors.add(next_cursor)
            cursor = str(next_cursor)
        if truncated:
            self.caps_hit.add(stage)
        self.queries.append({"stage": stage, "command": command, "pages": pages, "rows": len(rows)})
        return rows[:row_cap]

    def collect_by_alias(
        self,
        dataset: str,
        base_builder: Any,
        key_field: str,
    ) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for identity in IDENTITY_FIELDS:
            stage = f"{dataset}:{identity}"
            rows = self.paginate(
                base_builder(sentry_query(identity, self.args.host)),
                stage,
                row_cap=self.args.max_rows,
            )
            for row in rows:
                key = str(row.get(key_field) or row.get("id") or json.dumps(row, sort_keys=True))
                existing = merged.get(key)
                if existing is None:
                    existing = dict(row)
                    existing["_matched_by"] = [identity]
                    merged[key] = existing
                elif identity not in existing["_matched_by"]:
                    existing["_matched_by"].append(identity)
        values = list(merged.values())
        values.sort(key=lambda row: str(row.get("timestamp") or row.get("lastSeen") or ""))
        if len(values) > self.args.max_rows:
            self.caps_hit.add(dataset)
        return values[: self.args.max_rows]

    def collect(self) -> dict[str, int]:
        common_time = time_args(self.args)

        def issues_command(query: str) -> list[str]:
            return [
                "sentry", "issue", "list", self.args.target,
                "--query", query, "--limit", "1000", *common_time, "--json",
            ]

        def explore_command(dataset: str, fields: tuple[str, ...], query: str) -> list[str]:
            command = [
                "sentry", "explore", self.args.target, "--dataset", dataset,
                "--query", query, "--limit", "1000", *common_time,
            ]
            for field in fields:
                command.extend(["--field", field])
            command.append("--json")
            return command

        def traces_command(query: str) -> list[str]:
            return [
                "sentry", "trace", "list", self.args.target,
                "--query", query, "--limit", "1000", *common_time, "--json",
            ]

        issues = self.collect_by_alias("issues", issues_command, "id")
        errors = self.collect_by_alias(
            "errors", lambda query: explore_command("errors", ERROR_FIELDS, query), "id"
        )
        transactions = self.collect_by_alias("transactions", traces_command, "id")
        spans = self.collect_by_alias(
            "spans", lambda query: explore_command("spans", SPAN_FIELDS, query), "id"
        )
        logs = self.collect_by_alias(
            "logs", lambda query: explore_command("logs", LOG_FIELDS, query), "sentry.item_id"
        )

        jsonl_dump(self.root / "issues" / "index.jsonl", issues)
        jsonl_dump(self.root / "errors" / "index.jsonl", errors)
        jsonl_dump(self.root / "transactions" / "index.jsonl", transactions)
        jsonl_dump(self.root / "spans" / "index.jsonl", spans)
        jsonl_dump(self.root / "logs" / "index.jsonl", logs)

        issue_event_ids: list[str] = []
        newest_issues = sorted(
            issues, key=lambda row: str(row.get("lastSeen") or ""), reverse=True
        )
        for issue in newest_issues[: self.args.max_issues]:
            issue_id = str(issue.get("shortId") or issue.get("id") or "")
            if not issue_id:
                continue
            detail = self.run_json(
                ["sentry", "issue", "view", issue_id, "--json"],
                f"issue-detail:{issue_id}",
            )
            if detail is not None:
                json_dump(self.root / "issues" / "details" / f"{safe_filename(issue_id)}.json", detail)
            issue_events = self.collect_by_alias(
                f"issue-events:{issue_id}",
                lambda query, issue_id=issue_id: [
                    "sentry", "issue", "events", issue_id,
                    "--query", query, "--limit", "1000", *common_time, "--json",
                ],
                "eventID",
            )
            jsonl_dump(
                self.root / "issues" / "events" / f"{safe_filename(issue_id)}.jsonl",
                issue_events,
            )
            for issue_event in issue_events:
                event_id = str(issue_event.get("eventID") or issue_event.get("id") or "")
                if event_id and event_id not in issue_event_ids:
                    issue_event_ids.append(event_id)
        if len(issues) > self.args.max_issues:
            self.caps_hit.add("issue-details")

        event_ids: list[str] = []
        newest_events = [
            *sorted(
                errors,
                key=lambda row: str(row.get("timestamp") or ""),
                reverse=True,
            ),
            *sorted(
                transactions,
                key=lambda row: str(row.get("timestamp") or ""),
                reverse=True,
            ),
        ]
        for row in newest_events:
            event_id = str(row.get("id") or "")
            if event_id and event_id not in event_ids:
                event_ids.append(event_id)
        for event_id in issue_event_ids:
            if event_id not in event_ids:
                event_ids.append(event_id)
        for event_id in event_ids[: self.args.max_events]:
            detail = self.run_json(
                ["sentry", "event", "view", f"{self.args.target}/{event_id}", "--json"],
                f"event-detail:{event_id}",
            )
            if detail is not None:
                json_dump(self.root / "events" / f"{safe_filename(event_id)}.json", detail)
        if len(event_ids) > self.args.max_events:
            self.caps_hit.add("event-details")

        attachment_counts = self.collect_attachments(event_ids)

        trace_ids = unique_trace_ids(errors, transactions, spans, logs)
        for trace_id in trace_ids[: self.args.max_traces]:
            trace_root = self.root / "traces" / safe_filename(trace_id)
            detail = self.run_json(
                ["sentry", "trace", "view", f"{self.args.target}/{trace_id}", "--json"],
                f"trace-detail:{trace_id}",
            )
            if detail is not None:
                json_dump(trace_root / "trace.json", detail)
            trace_spans = self.paginate(
                [
                    "sentry", "span", "list", f"{self.args.target}/{trace_id}",
                    "--limit", "1000", "--json",
                ],
                f"trace-spans:{trace_id}",
                row_cap=self.args.max_rows,
            )
            json_dump(trace_root / "spans.json", {"data": trace_spans})
            trace_logs = self.run_json(
                ["sentry", "trace", "logs", f"{self.args.target}/{trace_id}", "--json"],
                f"trace-logs:{trace_id}",
            )
            if trace_logs is not None:
                json_dump(trace_root / "logs.json", trace_logs)
        if len(trace_ids) > self.args.max_traces:
            self.caps_hit.add("trace-details")

        return {
            "issues": len(issues),
            "errors": len(errors),
            "transactions": len(transactions),
            "spans": len(spans),
            "logs": len(logs),
            "unique_events": len(event_ids),
            "unique_traces": len(trace_ids),
            **attachment_counts,
        }


def unique_trace_ids(*datasets: list[dict[str, Any]]) -> list[str]:
    values: dict[str, str] = {}
    for rows in datasets:
        for row in rows:
            trace_id = str(row.get("trace") or "")
            if re.fullmatch(r"[A-Fa-f0-9]{32}", trace_id):
                normalized = trace_id.lower()
                timestamp = str(row.get("timestamp") or "")
                values[normalized] = max(values.get(normalized, ""), timestamp)
    return sorted(values, key=lambda trace_id: values[trace_id], reverse=True)


def prepare_output(args: argparse.Namespace) -> Path:
    if args.output:
        root = args.output.resolve()
    else:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        root = (Path.cwd() / "target" / "sentry-debug" / f"{args.host.upper()}-{stamp}").resolve()
    if root.exists() and any(root.iterdir()):
        raise CollectionError(f"output directory is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    return root


def preflight() -> str:
    if shutil.which("sentry") is None:
        raise CollectionError("sentry CLI is not installed or not on PATH")
    version = subprocess.run(
        ["sentry", "--version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if version.returncode != 0:
        raise CollectionError(f"sentry CLI failed: {redact(version.stderr or version.stdout)}")
    auth = subprocess.run(
        ["sentry", "auth", "status"],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if auth.returncode != 0:
        raise CollectionError(f"Sentry authentication failed: {redact(auth.stderr)[-1_000:]}")
    return version.stdout.strip()


def main() -> int:
    args = parse_args()
    try:
        version = preflight()
        root = prepare_output(args)
        request = {
            "schema_version": 1,
            "host": args.host.upper(),
            "target": args.target,
            "period": args.period,
            "from": args.start,
            "to": args.end,
            "issue_description": args.issue_description,
            "additional_context": args.context,
        }
        json_dump(root / "request.json", request)
        collector = Collector(args, root)
        started_at = now_utc()
        counts = collector.collect()
        finished_at = now_utc()
        jsonl_dump(root / "warnings.jsonl", collector.warnings)
        summary = {
            "schema_version": 1,
            "host": args.host.upper(),
            "target": args.target,
            "observed_time_filter": args.period or f"{args.start}..{args.end}",
            "counts": counts,
            "warning_count": len(collector.warnings),
            "caps_hit": sorted(collector.caps_hit),
            "status": "partial" if collector.warnings or collector.caps_hit else "complete",
        }
        json_dump(root / "summary.json", summary)
        manifest = {
            "schema_version": 1,
            "bundle_kind": "observed-sentry-telemetry",
            "created_at": finished_at,
            "started_at": started_at,
            "host": args.host.upper(),
            "target": args.target,
            "sentry_cli_version": version,
            "identity_aliases": list(IDENTITY_FIELDS),
            "time_filter": args.period or f"{args.start}..{args.end}",
            "limits": {
                "max_rows": args.max_rows,
                "max_events": args.max_events,
                "max_issues": args.max_issues,
                "max_traces": args.max_traces,
            },
            "queries": collector.queries,
            "counts": counts,
            "warning_count": len(collector.warnings),
            "caps_hit": sorted(collector.caps_hit),
            "completeness": "Observed telemetry only; subject to retention, sampling, transport, API, and collector limits.",
        }
        json_dump(root / "manifest.json", manifest)
        print(str(root))
        return 0
    except (CollectionError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
