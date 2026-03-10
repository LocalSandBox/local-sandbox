import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { resolve } from "node:path";
import { Sandbox } from "../../src/sandbox";
import type { FileChangeEvent } from "../../src/types";

const MOCK_BIN = `bun ${resolve(import.meta.dir, "mock-shuru.ts")}`;

describe("spawn", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: MOCK_BIN });
	}, 10_000);

	afterAll(async () => {
		await sb?.stop();
	}, 5_000);

	test("streams stdout chunks", async () => {
		const proc = await sb.spawn("stream-test");
		const chunks: string[] = [];

		proc.on("stdout", (data) => {
			chunks.push(data.toString());
		});

		const code = await proc.exited;
		expect(code).toBe(0);
		expect(chunks.join("")).toBe("chunk1\nchunk2\nchunk3\n");
	});

	test("streams stderr", async () => {
		const proc = await sb.spawn("stream-test");
		const stderrChunks: string[] = [];

		proc.on("stderr", (data) => {
			stderrChunks.push(data.toString());
		});

		await proc.exited;
		expect(stderrChunks.join("")).toBe("warn\n");
	});

	test("exit event fires", async () => {
		const proc = await sb.spawn("stream-test");
		let exitCode = -1;

		proc.on("exit", (code) => {
			exitCode = code;
		});

		const code = await proc.exited;
		expect(code).toBe(0);
		expect(exitCode).toBe(0);
	});

	test("non-zero exit code", async () => {
		const proc = await sb.spawn("exit-42");
		const code = await proc.exited;
		expect(code).toBe(42);
	});

	test("passes cwd to spawn", async () => {
		const proc = await sb.spawn("cwd-test", { cwd: "/workspace" });
		const chunks: string[] = [];

		proc.on("stdout", (data) => {
			chunks.push(data.toString());
		});

		await proc.exited;
		expect(chunks.join("")).toBe("cwd=/workspace\n");
	});

	test("has pid", async () => {
		const proc = await sb.spawn("stream-test");
		expect(proc.pid).toMatch(/^p\d+$/);
		await proc.exited;
	});
});

describe("kill", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: MOCK_BIN });
	}, 10_000);

	afterAll(async () => {
		await sb?.stop();
	}, 5_000);

	test("kills a running process", async () => {
		const proc = await sb.spawn("long-running");
		const chunks: string[] = [];

		proc.on("stdout", (data) => {
			chunks.push(data.toString());
		});

		// Let it run a bit
		await Bun.sleep(120);

		await proc.kill();
		const code = await proc.exited;
		expect(code).toBe(137);
		expect(chunks.length).toBeGreaterThan(0);
	});
});

describe("watch", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: MOCK_BIN });
	}, 10_000);

	afterAll(async () => {
		await sb?.stop();
	}, 5_000);

	test("receives all event types", async () => {
		const events: FileChangeEvent[] = [];

		await sb.watch("/workspace", (event) => {
			events.push(event);
		});

		// Wait for mock to send all events
		await Bun.sleep(150);

		expect(events.length).toBe(4);
		expect(events[0]).toEqual({
			path: "/workspace/src/main.ts",
			event: "modify",
		});
		expect(events[1]).toEqual({
			path: "/workspace/src/new.ts",
			event: "create",
		});
		expect(events[2]).toEqual({
			path: "/workspace/src/old.ts",
			event: "delete",
		});
		expect(events[3]).toEqual({
			path: "/workspace/src/renamed.ts",
			event: "rename",
		});
	});

	test("events include full path from watched root", async () => {
		const events: FileChangeEvent[] = [];

		await sb.watch("/custom/path", (event) => {
			events.push(event);
		});

		await Bun.sleep(150);

		// All paths should be relative to the watched root
		for (const evt of events) {
			expect(evt.path.startsWith("/custom/path/")).toBe(true);
		}
	});

	test("watch resolves immediately without blocking", async () => {
		const start = Date.now();
		await sb.watch("/fast", () => {});
		const elapsed = Date.now() - start;
		// watch() should return immediately (< 1s), not block waiting for events
		expect(elapsed).toBeLessThan(1000);
	});
});

describe("exec still works", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: MOCK_BIN });
	}, 10_000);

	afterAll(async () => {
		await sb?.stop();
	}, 5_000);

	test("buffered exec returns full result", async () => {
		const result = await sb.exec("echo hello");
		expect(result.exitCode).toBe(0);
		expect(result.stdout).toBe("hello\n");
	});
});

describe("multiple concurrent spawns", () => {
	let sb: Sandbox;

	beforeAll(async () => {
		sb = await Sandbox.start({ shuruBin: MOCK_BIN });
	}, 10_000);

	afterAll(async () => {
		await sb?.stop();
	}, 5_000);

	test("two spawns run concurrently", async () => {
		const proc1 = await sb.spawn("stream-test");
		const proc2 = await sb.spawn("exit-42");

		const [code1, code2] = await Promise.all([proc1.exited, proc2.exited]);
		expect(code1).toBe(0);
		expect(code2).toBe(42);
	});

	test("each spawn gets unique pid", async () => {
		const proc1 = await sb.spawn("stream-test");
		const proc2 = await sb.spawn("stream-test");

		expect(proc1.pid).not.toBe(proc2.pid);

		await Promise.all([proc1.exited, proc2.exited]);
	});
});
