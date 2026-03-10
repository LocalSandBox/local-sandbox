/**
 * Integration tests for streaming exec, kill, and file watching
 * against a real shuru VM.
 *
 * Prerequisites:
 *   1. cargo build -p shuru-cli -p shuru-guest --target aarch64-unknown-linux-musl --release
 *   2. ./scripts/prepare-rootfs.sh
 *   3. codesign --entitlements shuru.entitlements --force -s - target/debug/shuru
 *   4. shuru init
 *
 * Run: bun test test/integration/streaming.test.ts
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Sandbox } from "../../src/sandbox";
import type { FileChangeEvent } from "../../src/types";

const REPO_ROOT = resolve(import.meta.dir, "../../../..");
const SHURU_BIN = resolve(REPO_ROOT, "target/debug/shuru");

const canRun = existsSync(SHURU_BIN);

describe.if(canRun)("streaming exec", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: SHURU_BIN });
	}, 60_000);

	afterAll(async () => {
		await sb?.stop();
	}, 15_000);

	test("spawn streams stdout in chunks", async () => {
		const proc = await sb.spawn(
			"for i in 1 2 3; do echo chunk$i; sleep 0.05; done",
		);
		const chunks: string[] = [];

		proc.on("stdout", (data) => {
			chunks.push(data.toString());
		});

		const code = await proc.exited;
		expect(code).toBe(0);
		expect(chunks.join("")).toContain("chunk1");
		expect(chunks.join("")).toContain("chunk2");
		expect(chunks.join("")).toContain("chunk3");
	}, 30_000);

	test("spawn captures stderr separately", async () => {
		const proc = await sb.spawn("echo out && echo err >&2");
		const stdout: string[] = [];
		const stderr: string[] = [];

		proc.on("stdout", (data) => stdout.push(data.toString()));
		proc.on("stderr", (data) => stderr.push(data.toString()));

		const code = await proc.exited;
		expect(code).toBe(0);
		expect(stdout.join("").trim()).toBe("out");
		expect(stderr.join("").trim()).toBe("err");
	}, 30_000);

	test("spawn exit code", async () => {
		const proc = await sb.spawn("exit 7");
		const code = await proc.exited;
		expect(code).toBe(7);
	}, 30_000);

	test("spawn with cwd", async () => {
		const proc = await sb.spawn("pwd", { cwd: "/tmp" });
		const chunks: string[] = [];

		proc.on("stdout", (data) => chunks.push(data.toString()));

		const code = await proc.exited;
		expect(code).toBe(0);
		expect(chunks.join("").trim()).toBe("/tmp");
	}, 30_000);

	test("kill terminates a running process", async () => {
		const proc = await sb.spawn("sleep 60");

		// Give the process time to start
		await Bun.sleep(500);

		await proc.kill();
		const code = await proc.exited;
		// SIGTERM = 128 + 15 = 143
		expect(code).toBeGreaterThan(0);
	}, 30_000);

	test("multiple concurrent spawns", async () => {
		const p1 = await sb.spawn("echo one");
		const p2 = await sb.spawn("echo two");

		const out1: string[] = [];
		const out2: string[] = [];

		p1.on("stdout", (data) => out1.push(data.toString()));
		p2.on("stdout", (data) => out2.push(data.toString()));

		const [c1, c2] = await Promise.all([p1.exited, p2.exited]);
		expect(c1).toBe(0);
		expect(c2).toBe(0);
		expect(out1.join("").trim()).toBe("one");
		expect(out2.join("").trim()).toBe("two");
	}, 30_000);

	test("spawn then exec (both work)", async () => {
		const proc = await sb.spawn("echo from-spawn");
		const chunks: string[] = [];
		proc.on("stdout", (data) => chunks.push(data.toString()));
		await proc.exited;

		const result = await sb.exec("echo from-exec");
		expect(result.stdout.trim()).toBe("from-exec");
		expect(chunks.join("").trim()).toBe("from-spawn");
	}, 30_000);

	test("spawn with stdin write", async () => {
		const proc = await sb.spawn("cat");
		const chunks: string[] = [];
		proc.on("stdout", (data) => chunks.push(data.toString()));

		proc.write("hello from stdin\n");

		// Give cat time to echo it back, then kill it
		await Bun.sleep(500);
		await proc.kill();
		await proc.exited;

		expect(chunks.join("")).toContain("hello from stdin");
	}, 30_000);
});

describe.if(canRun)("file watching", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: SHURU_BIN });
		// Create the directory we'll watch
		await sb.exec("mkdir -p /tmp/watched");
	}, 60_000);

	afterAll(async () => {
		await sb?.stop();
	}, 15_000);

	test("detects file creation", async () => {
		const events: FileChangeEvent[] = [];

		await sb.watch("/tmp/watched", (event) => {
			events.push(event);
		});

		// Create a file inside the watched directory
		await sb.exec("touch /tmp/watched/newfile.txt");

		// Give inotify time to fire and events to propagate
		await Bun.sleep(1000);

		expect(events.length).toBeGreaterThan(0);
		const createEvent = events.find(
			(e) => e.path.includes("newfile.txt") && e.event === "create",
		);
		expect(createEvent).toBeDefined();
	}, 30_000);

	test("detects file modification", async () => {
		const events: FileChangeEvent[] = [];

		// Create the file first
		await sb.exec("echo initial > /tmp/watched/modtest.txt");
		await Bun.sleep(500);

		await sb.watch("/tmp/watched", (event) => {
			events.push(event);
		});

		// Modify the file
		await sb.exec("echo updated >> /tmp/watched/modtest.txt");

		await Bun.sleep(1000);

		expect(events.length).toBeGreaterThan(0);
		const modEvent = events.find(
			(e) => e.path.includes("modtest.txt") && e.event === "modify",
		);
		expect(modEvent).toBeDefined();
	}, 30_000);

	test("detects file deletion", async () => {
		const events: FileChangeEvent[] = [];

		// Create a file to delete
		await sb.exec("touch /tmp/watched/todelete.txt");
		await Bun.sleep(500);

		await sb.watch("/tmp/watched", (event) => {
			events.push(event);
		});

		// Delete the file
		await sb.exec("rm /tmp/watched/todelete.txt");

		await Bun.sleep(1000);

		expect(events.length).toBeGreaterThan(0);
		const deleteEvent = events.find(
			(e) => e.path.includes("todelete.txt") && e.event === "delete",
		);
		expect(deleteEvent).toBeDefined();
	}, 30_000);

	test("watches subdirectories recursively", async () => {
		const events: FileChangeEvent[] = [];

		await sb.exec("mkdir -p /tmp/watched/sub");

		await sb.watch("/tmp/watched", (event) => {
			events.push(event);
		});

		// Create file in subdirectory
		await sb.exec("touch /tmp/watched/sub/deep.txt");

		await Bun.sleep(1000);

		expect(events.length).toBeGreaterThan(0);
		const deepEvent = events.find((e) => e.path.includes("deep.txt"));
		expect(deepEvent).toBeDefined();
	}, 30_000);

	test("watch runs concurrently with spawn", async () => {
		const events: FileChangeEvent[] = [];
		const stdout: string[] = [];

		await sb.watch("/tmp/watched", (event) => {
			events.push(event);
		});

		// Spawn a process that creates files and prints output
		const proc = await sb.spawn(
			"echo started && touch /tmp/watched/concurrent.txt && echo done",
		);
		proc.on("stdout", (data) => stdout.push(data.toString()));

		const code = await proc.exited;
		expect(code).toBe(0);

		await Bun.sleep(1000);

		expect(stdout.join("")).toContain("started");
		expect(stdout.join("")).toContain("done");
		expect(events.length).toBeGreaterThan(0);
	}, 30_000);
});

describe.if(!canRun)("streaming exec (skipped)", () => {
	test("shuru binary not found", () => {
		console.log(
			"Build with: cargo build -p shuru-cli && codesign --entitlements shuru.entitlements --force -s - target/debug/shuru",
		);
	});
});
