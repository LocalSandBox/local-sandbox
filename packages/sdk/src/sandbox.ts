import { ShuruProcess } from "./process";
import type { ExecResult, StartOptions } from "./types";

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
		const resp = await this.proc.send({
			type: "exec",
			argv: ["sh", "-c", command],
		});
		if (resp.type !== "exec") {
			throw new Error(`unexpected response type: ${resp.type}`);
		}
		return {
			stdout: resp.stdout,
			stderr: resp.stderr,
			exitCode: resp.exit_code,
		};
	}

	async readFile(path: string): Promise<string> {
		const resp = await this.proc.send({
			type: "exec",
			argv: ["cat", path],
		});
		if (resp.type !== "exec") {
			throw new Error(`unexpected response type: ${resp.type}`);
		}
		if (resp.exit_code !== 0) {
			throw new Error(
				`readFile failed (exit ${resp.exit_code}): ${resp.stderr}`,
			);
		}
		return resp.stdout;
	}

	async writeFile(path: string, content: string): Promise<void> {
		const b64 = btoa(content);
		const resp = await this.proc.send({
			type: "exec",
			argv: ["sh", "-c", `echo '${b64}' | base64 -d > "$1"`, "--", path],
		});
		if (resp.type !== "exec") {
			throw new Error(`unexpected response type: ${resp.type}`);
		}
		if (resp.exit_code !== 0) {
			throw new Error(
				`writeFile failed (exit ${resp.exit_code}): ${resp.stderr}`,
			);
		}
	}

	async checkpoint(name: string): Promise<void> {
		const resp = await this.proc.send({ type: "checkpoint", name });
		if (resp.type !== "checkpoint") {
			throw new Error(`unexpected response type: ${resp.type}`);
		}
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
