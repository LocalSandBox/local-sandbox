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
import shutil
import statistics
import subprocess
import sys
import time

SCHEMA_VERSION = 1
SUPPORTED_METRICS = ("wall_time_ms", "cpu_time_seconds", "peak_working_set_bytes")
SUMMARY_METRICS = SUPPORTED_METRICS + ("peak_private_memory_bytes",)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="benchmark-macos-user-agent-injection.sh",
        description="Benchmark HTTPS User-Agent injection on macOS",
    )
    parser.add_argument("--binary", default="./target/release/lsb")
    parser.add_argument("--url", default="https://example.com/")
    parser.add_argument("--user-agent", default="lsb-user-agent-benchmark/1.0")
    parser.add_argument("--kernel")
    parser.add_argument("--rootfs")
    parser.add_argument("--initrd")
    parser.add_argument("--warmup-iterations", type=int, default=1)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--results-root", default="./target/macos-user-agent-benchmark")
    parser.add_argument("--endpoint-kind", choices=("local", "controlled", "public"), default="public")
    args = parser.parse_args()
    if not 0 <= args.warmup_iterations <= 100:
        parser.error("--warmup-iterations must be between 0 and 100")
    if not 1 <= args.iterations <= 1000:
        parser.error("--iterations must be between 1 and 1000")
    if not 25 <= args.sample_interval_ms <= 5000:
        parser.error("--sample-interval-ms must be between 25 and 5000")
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    runtime_paths = (args.kernel, args.rootfs, args.initrd)
    if any(runtime_paths) and not all(runtime_paths):
        parser.error("--kernel, --rootfs, and --initrd must be supplied together")
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


def write_configs(run_dir, user_agent):
    paths = {}
    for scenario, enabled in (("disabled", False), ("enabled", True)):
        config = {
            "allow_net": True,
            "network": {
                "https_interception": {
                    "enabled": enabled,
                    "request_headers": [{"name": "User-Agent", "value": user_agent}],
                }
            },
        }
        path = run_dir / "configs" / f"{scenario}.json"
        write_json(path, config)
        paths[scenario] = path
    return paths


def cpu_seconds(value):
    # ps time is [[dd-]hh:]mm:ss, optionally with fractions.
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


def invoke(binary, config, url, run_id, is_warmup, iteration, order_index, args, run_dir):
    stdout_path = run_dir / "stdout" / f"{run_id}.log"
    stderr_path = run_dir / "stderr" / f"{run_id}.log"
    argv = [
        str(binary), "run",
    ]
    if args.kernel:
        argv.extend([
            "--kernel", str(pathlib.Path(args.kernel).expanduser().resolve()),
            "--rootfs", str(pathlib.Path(args.rootfs).expanduser().resolve()),
            "--initrd", str(pathlib.Path(args.initrd).expanduser().resolve()),
        ])
    argv.extend([
        "--config", str(config), "--", "curl", "--http1.1", "-fsS", "-o", "/dev/null", url,
    ])
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
        except Exception as error:  # retain a result even when sampling fails
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
    succeeded = exit_code == 0 and not timed_out
    scenario = config.stem
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "timestamp_utc": started_utc,
        "platform": "macos",
        "platform_version": platform.mac_ver()[0],
        "architecture": platform.machine(),
        "scenario": scenario,
        "iteration": iteration,
        "is_warmup": is_warmup,
        "order_index": order_index,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "succeeded": succeeded,
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
    scenarios = {}
    for scenario in ("disabled", "enabled"):
        runs = [r for r in records if r["scenario"] == scenario and not r["is_warmup"] and r["succeeded"]]
        scenarios[scenario] = {}
        for metric in SUMMARY_METRICS:
            values = [r[metric] for r in runs if r[metric] is not None]
            scenarios[scenario][metric] = metric_summary(values) if values else None
    deltas = {}
    for metric in SUMMARY_METRICS:
        disabled = scenarios["disabled"][metric]
        enabled = scenarios["enabled"][metric]
        if not disabled or not enabled:
            deltas[metric] = None
            continue
        difference = enabled["mean"] - disabled["mean"]
        baseline = disabled["mean"]
        deltas[metric] = {
            "enabled_minus_disabled_mean": difference,
            "enabled_minus_disabled_percent": (difference / baseline * 100.0) if baseline else None,
        }
    return scenarios, deltas


def main():
    args = parse_args()
    binary = pathlib.Path(args.binary).expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit(f"binary does not exist or is not executable: {binary}")
    for runtime_path in (args.kernel, args.rootfs, args.initrd):
        if runtime_path and not pathlib.Path(runtime_path).expanduser().resolve().is_file():
            raise SystemExit(f"runtime asset does not exist: {runtime_path}")
    run_dir = safe_results_dir(args.results_root)
    configs = write_configs(run_dir, args.user_agent)
    start_utc = utc_now()
    records, order_index = [], 0
    runs_path = run_dir / "runs.jsonl"

    def run(scenario, warmup, iteration):
        nonlocal order_index
        order_index += 1
        kind = "warmup" if warmup else "measured"
        run_id = f"{order_index:04d}-{kind}-{scenario}-{iteration:03d}"
        print(f"running {run_id}", file=sys.stderr, flush=True)
        record = invoke(binary, configs[scenario], args.url, run_id, warmup, iteration, order_index, args, run_dir)
        records.append(record)
        with runs_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        return record

    # Parsing and one successful request per scenario are the preflight checks.
    for scenario in ("disabled", "enabled"):
        if not run(scenario, True, 0)["succeeded"]:
            raise SystemExit(f"preflight failed for {scenario}; artifacts retained at {run_dir}")
    for warmup in range(1, args.warmup_iterations + 1):
        for scenario in ("disabled", "enabled"):
            run(scenario, True, warmup)
    for iteration in range(1, args.iterations + 1):
        order = ("disabled", "enabled") if iteration % 2 else ("enabled", "disabled")
        for scenario in order:
            run(scenario, False, iteration)

    scenarios, deltas = summarize(records)
    sw_vers = command_output(["sw_vers"])
    uname = command_output(["uname", "-a"])
    total_memory = command_output(["sysctl", "-n", "hw.memsize"])
    summary = {
        "schema_version": SCHEMA_VERSION,
        "platform": "macos",
        "platform_version": platform.mac_ver()[0],
        "architecture": platform.machine(),
        "benchmark": "https_user_agent_injection",
        "started_at_utc": start_utc,
        "ended_at_utc": utc_now(),
        "binary_path": str(binary),
        "binary_sha256": sha256(binary),
        "lsb_version": command_output([str(binary), "--version"]),
        "git_revision": command_output(["git", "rev-parse", "HEAD"]),
        "runtime_assets": {
            name: {
                "path": str(pathlib.Path(path).expanduser().resolve()),
                "sha256": sha256(pathlib.Path(path).expanduser().resolve()),
            }
            for name, path in (("kernel", args.kernel), ("rootfs", args.rootfs), ("initrd", args.initrd))
            if path
        },
        "url": args.url,
        "endpoint_kind": args.endpoint_kind,
        "user_agent": "<redacted>",
        "user_agent_sha256": hashlib.sha256(args.user_agent.encode()).hexdigest(),
        "warmup_iterations": args.warmup_iterations,
        "iterations": args.iterations,
        "sample_interval_ms": args.sample_interval_ms,
        "timeout_seconds": args.timeout_seconds,
        "supported_metrics": list(SUPPORTED_METRICS),
        "aggregation": "successful measured runs; population standard deviation; nearest-rank p95",
        "logical_processor_count": os.cpu_count(),
        "total_physical_memory_bytes": int(total_memory) if total_memory and total_memory.isdigit() else None,
        "sw_vers": sw_vers,
        "uname": uname,
        "serializer": {"name": "python-json", "python_version": platform.python_version()},
        "artifacts": {
            "runs_jsonl": str(runs_path),
            "summary_json": str(run_dir / "summary.json"),
            "stdout_directory": str(run_dir / "stdout"),
            "stderr_directory": str(run_dir / "stderr"),
            "configs": {key: str(value) for key, value in configs.items()},
        },
        "scenarios": scenarios,
        "enabled_vs_disabled": deltas,
        "overall_success": all(
            sum(1 for r in records if r["scenario"] == scenario and not r["is_warmup"] and r["succeeded"])
            == args.iterations
            for scenario in ("disabled", "enabled")
        ),
    }
    write_json(run_dir / "summary.json", summary)
    print(json.dumps({"overall_success": summary["overall_success"], "runs_jsonl": str(runs_path), "summary_json": str(run_dir / "summary.json")}, separators=(",", ":")))
    return 0 if summary["overall_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
