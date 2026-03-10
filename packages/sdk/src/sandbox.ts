import { ShuruProcess } from "./process";
import { SandboxProcess } from "./process-handle";
import type {
	ExecResult,
	FileChangeEvent,
	SpawnOptions,
	StartOptions,
	WatchOptions,
} from "./types";

const Method = {
	EXEC: "exec",
	SPAWN: "spawn",
	READ_FILE: "read_file",
	WRITE_FILE: "write_file",
	CHECKPOINT: "checkpoint",
	WATCH: "watch",
} as const;

export class Sandbox {
	private proc: ShuruProcess;
	private stopped = false;

	private constructor(proc: ShuruProcess) {
		this.proc = proc;
	}

	static async start(opts: StartOptions = {}): Promise<Sandbox> {
		const bin = opts.shuruBin ?? "shuru";
		const args = buildArgs(bin, opts);

		const proc = new ShuruProcess();
		await proc.start(args);

		return new Sandbox(proc);
	}

	async exec(command: string): Promise<ExecResult> {
		const resp = await this.proc.send(Method.EXEC, {
			argv: ["sh", "-c", command],
		});
		const r = resp.result as {
			stdout: string;
			stderr: string;
			exit_code: number;
		};
		return {
			stdout: r.stdout,
			stderr: r.stderr,
			exitCode: r.exit_code,
		};
	}

	async spawn(command: string, opts?: SpawnOptions): Promise<SandboxProcess> {
		const resp = await this.proc.send(Method.SPAWN, {
			argv: ["sh", "-c", command],
			cwd: opts?.cwd,
			env: opts?.env,
		});
		const { pid } = resp.result as { pid: string };
		return new SandboxProcess(this.proc, pid);
	}

	async watch(
		path: string,
		handler: (event: FileChangeEvent) => void,
		opts?: WatchOptions,
	): Promise<void> {
		this.proc.fileChangeHandler = handler;
		await this.proc.send(Method.WATCH, {
			path,
			recursive: opts?.recursive ?? true,
		});
	}

	async readFile(path: string): Promise<Uint8Array> {
		const resp = await this.proc.send(Method.READ_FILE, { path });
		const r = resp.result as { content: string };
		return new Uint8Array(Buffer.from(r.content, "base64"));
	}

	async writeFile(path: string, content: Uint8Array | string): Promise<void> {
		const b64 = Buffer.from(content).toString("base64");
		await this.proc.send(Method.WRITE_FILE, { path, content: b64 });
	}

	async checkpoint(name: string): Promise<void> {
		await this.proc.send(Method.CHECKPOINT, { name });
		this.stopped = true;
		await this.proc.stop();
	}

	async stop(): Promise<void> {
		if (this.stopped) return;
		this.stopped = true;
		await this.proc.stop();
	}
}

/** @internal exported for testing */
export function buildArgs(bin: string, opts: StartOptions): string[] {
	const args = [...bin.split(/\s+/), "run", "--stdio"];

	if (opts.from) args.push("--from", opts.from);
	if (opts.cpus) args.push("--cpus", String(opts.cpus));
	if (opts.memory) args.push("--memory", String(opts.memory));
	if (opts.diskSize) args.push("--disk-size", String(opts.diskSize));
	if (opts.allowNet) args.push("--allow-net");

	if (opts.secrets) {
		for (const [name, secret] of Object.entries(opts.secrets)) {
			args.push("--secret", `${name}=${secret.from}@${secret.hosts.join(",")}`);
		}
	}

	if (opts.network?.allow) {
		for (const host of opts.network.allow) {
			args.push("--allow-host", host);
		}
	}

	if (opts.ports) {
		for (const p of opts.ports) {
			args.push("-p", p);
		}
	}

	if (opts.mounts) {
		for (const [host, guest] of Object.entries(opts.mounts)) {
			args.push("--mount", `${host}:${guest}`);
		}
	}

	return args;
}
