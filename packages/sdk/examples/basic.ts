import { resolve } from "node:path";
import { Sandbox } from "../src/sandbox";

const SHURU_BIN = resolve(import.meta.dir, "../../../target/debug/shuru");

async function main() {
	console.log("starting sandbox...");
	const sb = await Sandbox.start({ shuruBin: SHURU_BIN });

	try {
		// exec: run a command
		const result = await sb.exec("echo 'hello from the VM!'");
		console.log("exec stdout:", result.stdout.trim());
		console.log("exec exit code:", result.exitCode);

		// exec: get system info
		const uname = await sb.exec("uname -a");
		console.log("uname:", uname.stdout.trim());

		// writeFile + readFile roundtrip
		const msg = "written from the SDK\n";
		await sb.writeFile("/tmp/example.txt", msg);
		const read = await sb.readFile("/tmp/example.txt");
		const content = new TextDecoder().decode(read);
		console.log("file roundtrip:", content.trim());

		// exec: verify the file from the shell side
		const cat = await sb.exec("cat /tmp/example.txt");
		console.log("cat from VM:", cat.stdout.trim());

		console.log("all good!");
	} finally {
		await sb.stop();
		console.log("sandbox stopped.");
	}
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
