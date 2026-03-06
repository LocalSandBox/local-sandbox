/**
 * Integration tests that run against the real shuru binary + VM.
 *
 * Prerequisites:
 *   1. cargo build -p shuru-cli
 *   2. codesign --entitlements shuru.entitlements --force -s - target/debug/shuru
 *   3. shuru init
 *
 * Run: bun test test/integration/
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";
import { Sandbox } from "../../src/sandbox";

const REPO_ROOT = resolve(import.meta.dir, "../../../..");
const SHURU_BIN = resolve(REPO_ROOT, "target/debug/shuru");

const canRun = existsSync(SHURU_BIN);

describe.if(canRun)("sandbox lifecycle", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: SHURU_BIN });
	}, 60_000);

	afterAll(async () => {
		await sb?.stop();
	}, 15_000);

	test("exec echo", async () => {
		const result = await sb.exec("echo hello");
		expect(result.exitCode).toBe(0);
		expect(result.stdout.trim()).toBe("hello");
		expect(result.stderr).toBe("");
	}, 30_000);

	test("exec captures exit code", async () => {
		const result = await sb.exec("exit 42");
		expect(result.exitCode).toBe(42);
	}, 30_000);

	test("exec captures stderr", async () => {
		const result = await sb.exec("echo err >&2");
		expect(result.exitCode).toBe(0);
		expect(result.stderr.trim()).toBe("err");
	}, 30_000);

	test("writeFile and readFile roundtrip", async () => {
		const content = "hello from integration test\nline 2\n";
		await sb.writeFile("/tmp/sdk-test.txt", content);
		const read = await sb.readFile("/tmp/sdk-test.txt");
		expect(new TextDecoder().decode(read)).toBe(content);
	}, 30_000);

	test("multiple sequential execs", async () => {
		await sb.exec("echo a > /tmp/seq.txt");
		await sb.exec("echo b >> /tmp/seq.txt");
		const result = await sb.exec("cat /tmp/seq.txt");
		expect(result.stdout).toBe("a\nb\n");
	}, 30_000);

	test("checkpoint creates disk snapshot", async () => {
		const cpPath = resolve(
			process.env.HOME ?? "/tmp",
			".local/share/shuru/checkpoints/sdk-integration-test.ext4",
		);

		try {
			unlinkSync(cpPath);
		} catch {
			// no leftover
		}

		await sb.exec("echo checkpoint-data > /tmp/cp-test.txt");
		await sb.checkpoint("sdk-integration-test");
		expect(existsSync(cpPath)).toBe(true);

		try {
			unlinkSync(cpPath);
		} catch {
			// cleanup
		}
	}, 30_000);
});

describe.if(!canRun)("sandbox lifecycle (skipped)", () => {
	test("shuru binary not found", () => {
		console.log(
			"Build with: cargo build -p shuru-cli && codesign --entitlements shuru.entitlements --force -s - target/debug/shuru",
		);
	});
});
