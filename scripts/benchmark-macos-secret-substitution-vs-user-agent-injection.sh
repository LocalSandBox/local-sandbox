#!/bin/bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "benchmark requires python3 for JSON serialization and process sampling" >&2
  exit 2
fi

exec python3 - "$@" <<'PY'
import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import time
import urllib.parse

SCHEMA_VERSION = 2
SCENARIOS = ("secret_substitution", "secret_plus_user_agent")
REQUEST_COUNTS = (1, 10)
SUPPORTED_METRICS = ("wall_time_ms", "cpu_time_seconds", "peak_working_set_bytes")
SUMMARY_METRICS = SUPPORTED_METRICS + ("peak_private_memory_bytes",)
SECRET_NAME = "LSB_BENCHMARK_SECRET"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="benchmark-macos-secret-substitution-vs-user-agent-injection.sh",
        description=(
            "Compare pre-feature secret substitution with current secret substitution "
            "plus HTTPS User-Agent injection on macOS"
        ),
    )
    parser.add_argument("--baseline-binary", required=True, help="pre-feature lsb binary")
    parser.add_argument("--candidate-binary", default="./target/release/lsb")
    parser.add_argument("--url", default="https://example.com/")
    parser.add_argument("--user-agent", default="lsb-user-agent-benchmark/1.0")
    parser.add_argument("--secret-value", default="lsb-secret-substitution-benchmark-value")
    parser.add_argument("--kernel")
    parser.add_argument("--rootfs")
    parser.add_argument("--initrd")
    parser.add_argument("--warmup-iterations", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument(
        "--results-root",
        default="./target/macos-secret-substitution-vs-user-agent-benchmark",
    )
    parser.add_argument(
        "--endpoint-kind", choices=("local", "controlled", "public"), default="public"
    )
    args = parser.parse_args()
    if not 0 <= args.warmup_iterations <= 100:
        parser.error("--warmup-iterations must be between 0 and 100")
    if not 1 <= args.iterations <= 1000:
        parser.error("--iterations must be between 1 and 1000")
    if not 25 <= args.sample_interval_ms <= 5000:
        parser.error("--sample-interval-ms must be between 25 and 5000")
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    if not args.secret_value:
        parser.error("--secret-value must not be empty")
    runtime_paths = (args.kernel, args.rootfs, args.initrd)
    if any(runtime_paths) and not all(runtime_paths):
        parser.error("--kernel, --rootfs, and --initrd must be supplied together")
    parsed_url = urllib.parse.urlsplit(args.url)
    if parsed_url.scheme.lower() != "https" or not parsed_url.hostname:
        parser.error("--url must be an absolute HTTPS URL")
    if parsed_url.port not in (None, 443):
        parser.error("--url must use port 443 because HTTPS interception is port-scoped")
    args.secret_host = parsed_url.hostname
    return args


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def command_output(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_results_dir(root):
    root = pathlib.Path(root).expanduser().resolve()
    if root == pathlib.Path(root.anchor) or root == pathlib.Path.cwd().resolve():
        raise ValueError(f"unsafe results root: {root}")
    run_dir = root / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = 0
    candidate = run_dir
    while candidate.exists():
        suffix += 1
        candidate = pathlib.Path(f"{run_dir}-{suffix}")
    (candidate / "stdout").mkdir(parents=True)
    (candidate / "stderr").mkdir()
    (candidate / "configs").mkdir()
    return candidate


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_configs(run_dir, args):
    secret = {
        SECRET_NAME: {
            "value": args.secret_value,
            "hosts": [args.secret_host],
        }
    }
    configs = {
        "secret_substitution": {
            "allow_net": True,
            "secrets": secret,
        },
        "secret_plus_user_agent": {
            "allow_net": True,
            "secrets": secret,
            "network": {
                "https_interception": {
                    "enabled": True,
                    "request_headers": [{"name": "User-Agent", "value": args.user_agent}],
                }
            },
        },
    }
    paths = {}
    for scenario, config in configs.items():
        path = run_dir / "configs" / f"{scenario}.json"
        write_json(path, config)
        paths[scenario] = path
    return paths


def cpu_seconds(value):
    days = 0
    if "-" in value:
        day, value = value.split("-", 1)
        days = int(day)
    parts = value.split(":")
    if len(parts) == 2:
        hours, minutes, seconds = 0, int(parts[0]), float(parts[1])
    else:
        hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def process_snapshot(root_pid):
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,lstart=,time=,rss="],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "ps failed")
    processes = {}
    children = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 9:
            continue
        try:
            pid, ppid = int(fields[0]), int(fields[1])
            start = " ".join(fields[2:7])
            cpu = cpu_seconds(fields[7])
            rss = int(fields[8]) * 1024
        except (ValueError, IndexError):
            continue
        processes[pid] = (ppid, start, cpu, rss)
        children.setdefault(ppid, []).append(pid)
    selected, pending = set(), [root_pid]
    while pending:
        pid = pending.pop()
        if pid in selected or pid not in processes:
            continue
        selected.add(pid)
        pending.extend(children.get(pid, ()))
    return [(pid, *processes[pid]) for pid in selected]


def request_arguments(url, request_count):
    argv = [
        "sh",
        "-ceu",
        'exec curl --http1.1 -fsS -H "Authorization: Bearer $LSB_BENCHMARK_SECRET" "$@"',
        "sh",
    ]
    for _ in range(request_count):
        argv.extend(["-o", "/dev/null", url])
    return argv


def invoke(binary, config, scenario, request_count, run_id, is_warmup, iteration, order_index, args, run_dir):
    stdout_path = run_dir / "stdout" / f"{run_id}.log"
    stderr_path = run_dir / "stderr" / f"{run_id}.log"
    argv = [str(binary), "run"]
    if args.kernel:
        argv.extend(
            [
                "--kernel",
                str(pathlib.Path(args.kernel).expanduser().resolve()),
                "--rootfs",
                str(pathlib.Path(args.rootfs).expanduser().resolve()),
                "--initrd",
                str(pathlib.Path(args.initrd).expanduser().resolve()),
            ]
        )
    argv.extend(["--config", str(config), "--"])
    argv.extend(request_arguments(args.url, request_count))
    started_utc = utc_now()
    started = time.monotonic()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    last_cpu, total_cpu, peak_rss, samples = {}, 0.0, 0, 0
    discovery_ok, sampling_error, timed_out = True, None, False
    interval = args.sample_interval_ms / 1000.0
    while process.poll() is None:
        try:
            snapshot = process_snapshot(process.pid)
            samples += 1
            aggregate_rss = 0
            for pid, _ppid, start_time, cpu, rss in snapshot:
                key = (pid, start_time)
                previous = last_cpu.get(key, 0.0)
                total_cpu += max(0.0, cpu - previous)
                last_cpu[key] = cpu
                aggregate_rss += rss
            peak_rss = max(peak_rss, aggregate_rss)
        except Exception as error:
            discovery_ok = False
            sampling_error = str(error)
        if time.monotonic() - started > args.timeout_seconds:
            timed_out = True
            try:
                for pid, *_rest in process_snapshot(process.pid):
                    try:
                        os.kill(pid, 9)
                    except (ProcessLookupError, PermissionError):
                        pass
            finally:
                process.kill()
            break
        time.sleep(interval)
    stdout, stderr = process.communicate()
    elapsed_ms = (time.monotonic() - started) * 1000.0
    stdout_path.write_bytes(stdout)
    stderr_path.write_bytes(stderr)
    exit_code = process.returncode
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "timestamp_utc": started_utc,
        "platform": "macos",
        "platform_version": platform.mac_ver()[0],
        "architecture": platform.machine(),
        "scenario": scenario,
        "request_count": request_count,
        "iteration": iteration,
        "is_warmup": is_warmup,
        "order_index": order_index,
        "binary_path": str(binary),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "succeeded": exit_code == 0 and not timed_out,
        "wall_time_ms": elapsed_ms,
        "cpu_time_seconds": total_cpu,
        "peak_working_set_bytes": peak_rss,
        "peak_private_memory_bytes": None,
        "measurement_scope": "process_tree" if discovery_ok else "root_only",
        "descendant_discovery_succeeded": discovery_ok,
        "sample_interval_ms": args.sample_interval_ms,
        "sample_count": samples,
        "sampling_error": sampling_error,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def percentile95(values):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def metric_summary(values):
    return {
        "successful_run_count": len(values),
        "minimum": min(values),
        "maximum": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "standard_deviation": statistics.pstdev(values),
        "p95": percentile95(values),
    }


def summarize(records):
    workloads = {}
    for request_count in REQUEST_COUNTS:
        scenarios = {}
        for scenario in SCENARIOS:
            runs = [
                record
                for record in records
                if record["request_count"] == request_count
                and record["scenario"] == scenario
                and not record["is_warmup"]
                and record["succeeded"]
            ]
            scenarios[scenario] = {}
            for metric in SUMMARY_METRICS:
                values = [record[metric] for record in runs if record[metric] is not None]
                scenarios[scenario][metric] = metric_summary(values) if values else None
        deltas = {}
        for metric in SUMMARY_METRICS:
            baseline = scenarios["secret_substitution"][metric]
            candidate = scenarios["secret_plus_user_agent"][metric]
            if not baseline or not candidate:
                deltas[metric] = None
                continue
            difference = candidate["mean"] - baseline["mean"]
            deltas[metric] = {
                "candidate_minus_baseline_mean": difference,
                "candidate_minus_baseline_percent": (
                    difference / baseline["mean"] * 100.0 if baseline["mean"] else None
                ),
            }
        workloads[f"startup_plus_{request_count}_requests"] = {
            "request_count": request_count,
            "scenarios": scenarios,
            "candidate_vs_baseline": deltas,
        }
    return workloads


def summarize_request_scaling(workloads):
    one = workloads["startup_plus_1_requests"]["scenarios"]
    ten = workloads["startup_plus_10_requests"]["scenarios"]
    scenarios = {}
    for scenario in SCENARIOS:
        scenarios[scenario] = {}
        for metric in SUMMARY_METRICS:
            one_metric = one[scenario][metric]
            ten_metric = ten[scenario][metric]
            if not one_metric or not ten_metric:
                scenarios[scenario][metric] = None
                continue
            difference = ten_metric["mean"] - one_metric["mean"]
            scenarios[scenario][metric] = {
                "ten_minus_one_mean": difference,
                "per_additional_request_estimate": difference / 9.0,
            }
    candidate_vs_baseline = {}
    for metric in SUMMARY_METRICS:
        baseline = scenarios["secret_substitution"][metric]
        candidate = scenarios["secret_plus_user_agent"][metric]
        if not baseline or not candidate:
            candidate_vs_baseline[metric] = None
            continue
        difference = candidate["ten_minus_one_mean"] - baseline["ten_minus_one_mean"]
        candidate_vs_baseline[metric] = {
            "candidate_minus_baseline_ten_minus_one": difference,
            "candidate_minus_baseline_per_additional_request_estimate": difference / 9.0,
        }
    return {
        "method": "(startup_plus_10_requests mean - startup_plus_1_requests mean) / 9",
        "scenarios": scenarios,
        "candidate_vs_baseline": candidate_vs_baseline,
    }


def main():
    args = parse_args()
    binaries = {
        "secret_substitution": pathlib.Path(args.baseline_binary).expanduser().resolve(),
        "secret_plus_user_agent": pathlib.Path(args.candidate_binary).expanduser().resolve(),
    }
    for scenario, binary in binaries.items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SystemExit(f"{scenario} binary does not exist or is not executable: {binary}")
    for runtime_path in (args.kernel, args.rootfs, args.initrd):
        if runtime_path and not pathlib.Path(runtime_path).expanduser().resolve().is_file():
            raise SystemExit(f"runtime asset does not exist: {runtime_path}")

    run_dir = safe_results_dir(args.results_root)
    configs = write_configs(run_dir, args)
    started_at = utc_now()
    records, order_index = [], 0
    runs_path = run_dir / "runs.jsonl"

    def run(scenario, request_count, warmup, iteration):
        nonlocal order_index
        order_index += 1
        kind = "warmup" if warmup else "measured"
        run_id = (
            f"{order_index:04d}-{kind}-{scenario}-{request_count:02d}req-{iteration:03d}"
        )
        print(f"running {run_id}", file=sys.stderr, flush=True)
        record = invoke(
            binaries[scenario],
            configs[scenario],
            scenario,
            request_count,
            run_id,
            warmup,
            iteration,
            order_index,
            args,
            run_dir,
        )
        records.append(record)
        with runs_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        return record

    for request_count in REQUEST_COUNTS:
        for scenario in SCENARIOS:
            if not run(scenario, request_count, True, 0)["succeeded"]:
                raise SystemExit(
                    f"preflight failed for {scenario}/{request_count} requests; "
                    f"artifacts retained at {run_dir}"
                )
    for warmup in range(1, args.warmup_iterations + 1):
        for request_count in REQUEST_COUNTS:
            for scenario in SCENARIOS:
                run(scenario, request_count, True, warmup)
    for iteration in range(1, args.iterations + 1):
        request_order = REQUEST_COUNTS if iteration % 2 else tuple(reversed(REQUEST_COUNTS))
        scenario_order = SCENARIOS if iteration % 2 else tuple(reversed(SCENARIOS))
        for request_count in request_order:
            for scenario in scenario_order:
                run(scenario, request_count, False, iteration)

    workloads = summarize(records)
    request_scaling = summarize_request_scaling(workloads)
    binary_metadata = {}
    for scenario, binary in binaries.items():
        binary_metadata[scenario] = {
            "path": str(binary),
            "sha256": sha256(binary),
            "lsb_version": command_output([str(binary), "--version"]),
        }
    total_memory = command_output(["sysctl", "-n", "hw.memsize"])
    summary = {
        "schema_version": SCHEMA_VERSION,
        "platform": "macos",
        "platform_version": platform.mac_ver()[0],
        "architecture": platform.machine(),
        "benchmark": "secret_substitution_vs_user_agent_injection",
        "started_at_utc": started_at,
        "ended_at_utc": utc_now(),
        "binaries": binary_metadata,
        "git_revision": command_output(["git", "rev-parse", "HEAD"]),
        "url": args.url,
        "endpoint_kind": args.endpoint_kind,
        "secret_name": SECRET_NAME,
        "secret_value": "<redacted>",
        "secret_value_sha256": hash_text(args.secret_value),
        "user_agent": "<redacted>",
        "user_agent_sha256": hash_text(args.user_agent),
        "request_counts": list(REQUEST_COUNTS),
        "curl_invocation": "one curl process per VM run; repeated URLs permit connection reuse",
        "warmup_iterations": args.warmup_iterations,
        "iterations": args.iterations,
        "sample_interval_ms": args.sample_interval_ms,
        "timeout_seconds": args.timeout_seconds,
        "supported_metrics": list(SUPPORTED_METRICS),
        "aggregation": "successful measured runs; population standard deviation; nearest-rank p95",
        "logical_processor_count": os.cpu_count(),
        "total_physical_memory_bytes": int(total_memory) if total_memory else None,
        "sw_vers": command_output(["sw_vers"]),
        "uname": command_output(["uname", "-a"]),
        "serializer": {"name": "python-json", "python_version": platform.python_version()},
        "artifacts": {
            "runs_jsonl": str(runs_path),
            "summary_json": str(run_dir / "summary.json"),
            "stdout_directory": str(run_dir / "stdout"),
            "stderr_directory": str(run_dir / "stderr"),
            "configs": {key: str(value) for key, value in configs.items()},
        },
        "workloads": workloads,
        "request_scaling": request_scaling,
        "overall_success": all(
            sum(
                1
                for record in records
                if record["scenario"] == scenario
                and record["request_count"] == request_count
                and not record["is_warmup"]
                and record["succeeded"]
            )
            == args.iterations
            for request_count in REQUEST_COUNTS
            for scenario in SCENARIOS
        ),
    }
    write_json(run_dir / "summary.json", summary)
    print(
        json.dumps(
            {
                "overall_success": summary["overall_success"],
                "runs_jsonl": str(runs_path),
                "summary_json": str(run_dir / "summary.json"),
            },
            separators=(",", ":"),
        )
    )
    return 0 if summary["overall_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
