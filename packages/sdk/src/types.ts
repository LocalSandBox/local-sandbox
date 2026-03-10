export interface SecretConfig {
	/** Host environment variable containing the real value. */
	from: string;
	/** Domains where this secret may be sent (e.g. "api.openai.com"). */
	hosts: string[];
}

export interface NetworkConfig {
	/** Allowed domain patterns. Omit to allow all. */
	allow?: string[];
}

export interface StartOptions {
	from?: string;
	cpus?: number;
	memory?: number;
	diskSize?: number;
	allowNet?: boolean;
	ports?: string[];
	mounts?: Record<string, string>;
	secrets?: Record<string, SecretConfig>;
	network?: NetworkConfig;
	shuruBin?: string;
}

export interface ExecResult {
	stdout: string;
	stderr: string;
	exitCode: number;
}

export interface SpawnOptions {
	cwd?: string;
	env?: Record<string, string>;
}

export interface WatchOptions {
	recursive?: boolean;
}

export interface FileChangeEvent {
	path: string;
	event: "create" | "modify" | "delete" | "rename";
}

// --- JSON-RPC 2.0 wire types (internal) ---

export interface JsonRpcResult {
	jsonrpc: "2.0";
	id: number;
	result: unknown;
}

export interface JsonRpcError {
	jsonrpc: "2.0";
	id: number;
	error: { code: number; message: string };
}

export interface JsonRpcNotification {
	jsonrpc: "2.0";
	method: string;
	params?: Record<string, unknown>;
}

export type JsonRpcResponse =
	| JsonRpcResult
	| JsonRpcError
	| JsonRpcNotification;
