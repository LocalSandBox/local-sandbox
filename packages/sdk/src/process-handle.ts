import type { ShuruProcess } from "./process";

type EventMap = {
	stdout: (data: Buffer) => void;
	stderr: (data: Buffer) => void;
	exit: (code: number) => void;
};

export class SandboxProcess {
	readonly pid: string;
	readonly exited: Promise<number>;
	private proc: ShuruProcess;
	private listeners: {
		stdout: ((data: Buffer) => void)[];
		stderr: ((data: Buffer) => void)[];
		exit: ((code: number) => void)[];
	} = { stdout: [], stderr: [], exit: [] };

	constructor(proc: ShuruProcess, pid: string) {
		this.proc = proc;
		this.pid = pid;

		this.exited = new Promise<number>((resolve) => {
			proc.processHandlers.set(pid, {
				onStdout: (data) => {
					for (const h of this.listeners.stdout) h(data);
				},
				onStderr: (data) => {
					for (const h of this.listeners.stderr) h(data);
				},
				onExit: (code) => {
					for (const h of this.listeners.exit) h(code);
					resolve(code);
				},
			});
		});
	}

	on<K extends keyof EventMap>(event: K, handler: EventMap[K]): this {
		this.listeners[event].push(handler);
		return this;
	}

	write(data: Buffer | string): void {
		this.proc.sendNotification("input", {
			pid: this.pid,
			data: Buffer.from(data).toString("base64"),
		});
	}

	async kill(): Promise<void> {
		await this.proc.send("kill", { pid: this.pid });
	}
}
