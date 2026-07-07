# Architecture Notes

This document records call graphs and behavioral contracts for important `lsb`
runtime paths. Each path should capture:

- Ordered call graph from public entrypoint to implementation boundary.
- Host/guest boundary and protocol messages.
- Important structs, enums, and state carried across layers.
- Contracts and invariants that future platform implementations must preserve.
- Known unknowns or follow-up questions.

## Code Paths

- [`lsb run -- echo hello`](#lsb-run----echo-hello)
- [Mount Overlay Path](#mount-overlay-path)
- [Port Forwarding Path](#port-forwarding-path)
- [Checkpoint Save/Restore Path](#checkpoint-saverestore-path)
- [`--allow-net` + Secrets Path](#--allow-net--secrets-path)
- [Node `Sandbox.start` Path](#node-sandboxstart-path)

## `lsb run -- echo hello`

### Summary

`lsb run -- echo hello` parses `echo hello` as a direct argv vector, prepares an
ephemeral VM disk, boots the Linux guest, opens a vsock connection to the guest
init process, sends an `ExecRequest`, streams output back over the binary frame
protocol, stops the VM, removes the per-run instance directory, and exits with
the guest process exit code.

The command is not wrapped in a host shell. With no config override, the argv
that crosses the host/guest boundary is:

```text
["echo", "hello"]
```

If host stdin is a terminal, the CLI uses the TTY path (`Sandbox::shell`) and the
guest executes via `openpty` + `fork` + `execvp`. If host stdin is not a terminal,
the CLI uses the piped path (`Sandbox::exec_with_env`) and the guest executes via
`std::process::Command`.

### Ordered Call Graph

1. `lsb` binary enters `main()`.
   - `crates/lsb-cli/src/main.rs:18`

2. `main()` initializes tracing and calls `Cli::parse()`.
   - `crates/lsb-cli/src/main.rs:19`
   - `crates/lsb-cli/src/main.rs:26`
   - `crates/lsb-cli/src/cli.rs:70`

3. Clap matches `Commands::Run`.
   - `crates/lsb-cli/src/main.rs:28`
   - `crates/lsb-cli/src/main.rs:29`
   - `crates/lsb-cli/src/cli.rs:77`

4. `Run.command` captures trailing argv.
   - `#[arg(trailing_var_arg = true, allow_hyphen_values = true)]`
   - `crates/lsb-cli/src/cli.rs:96`
   - `crates/lsb-cli/src/cli.rs:97`

5. `main()` loads `lsb.json` or returns the default empty config.
   - `crates/lsb-cli/src/main.rs:36`
   - `crates/lsb-cli/src/config.rs:102`
   - `crates/lsb-cli/src/config.rs:108`
   - `crates/lsb-cli/src/config.rs:118`

6. `main()` resolves the command by precedence.
   - CLI argv wins when non-empty.
   - Config `command` is used when CLI argv is empty.
   - Default command is `/bin/sh`.
   - `crates/lsb-cli/src/main.rs:38`
   - `crates/lsb-cli/src/main.rs:39`
   - `crates/lsb-cli/src/main.rs:41`
   - `crates/lsb-cli/src/main.rs:44`

7. `main()` calls `vm::prepare_vm(&vm, &cfg, from.as_deref())`.
   - `crates/lsb-cli/src/main.rs:47`
   - `crates/lsb-cli/src/vm.rs:37`

8. `prepare_vm()` merges VM defaults and config.
   - `cpus`: CLI > config > `2`
   - `memory`: CLI > config > `2048`
   - `disk_size`: CLI > config > `4096`
   - `allow_net`: CLI flag or config
   - `crates/lsb-cli/src/vm.rs:38`
   - `crates/lsb-cli/src/vm.rs:41`

9. `prepare_vm()` resolves asset paths and storage.
   - `lsb_vm::default_data_dir()`
   - `lsb_platform::asset_paths(&data_dir)`
   - `lsb_sdk::prepare_storage(...)`
   - `crates/lsb-cli/src/vm.rs:107`
   - `crates/lsb-cli/src/vm.rs:108`
   - `crates/lsb-cli/src/vm.rs:133`
   - `crates/lsb-sdk/src/storage.rs:46`

10. `prepare_vm()` creates the per-process instance directory and working rootfs.
    - Instance directory: `{data_dir}/instances/{pid}`
    - Working disk: `{instance_dir}/rootfs.ext4`
    - Direct storage copies from source rootfs.
    - NBD storage creates an empty placeholder file and serves blocks over NBD.
    - `crates/lsb-cli/src/vm.rs:143`
    - `crates/lsb-cli/src/vm.rs:147`
    - `crates/lsb-cli/src/vm.rs:148`
    - `crates/lsb-cli/src/vm.rs:152`
    - `crates/lsb-cli/src/vm.rs:154`

11. `main()` calls the default command runner unless `--stdio` or `--console`
    were set.
    - `crates/lsb-cli/src/main.rs:49`
    - `crates/lsb-cli/src/main.rs:51`
    - `crates/lsb-cli/src/main.rs:54`
    - `crates/lsb-cli/src/vm.rs:266`

12. `run_command_inner()` optionally starts the proxy, starts NBD, builds the
    sandbox, and starts the VM.
    - `crates/lsb-cli/src/vm.rs:277`
    - `crates/lsb-cli/src/vm.rs:291`
    - `crates/lsb-cli/src/vm.rs:305`
    - `crates/lsb-cli/src/vm.rs:308`
    - `crates/lsb-cli/src/vm.rs:313`

13. `build_sandbox()` configures `Sandbox::builder()`.
    - Kernel path
    - Working rootfs path
    - CPU count
    - Memory size
    - Console/verbose mode
    - Optional network fd
    - Optional NBD URI
    - Optional initrd
    - Optional mount requests
    - `crates/lsb-cli/src/vm.rs:206`
    - `crates/lsb-cli/src/vm.rs:212`
    - `crates/lsb-cli/src/vm.rs:220`
    - `crates/lsb-cli/src/vm.rs:224`
    - `crates/lsb-cli/src/vm.rs:228`
    - `crates/lsb-cli/src/vm.rs:232`

14. `VmConfigBuilder::build()` creates a platform VM through
    `lsb_platform::create_vm(PlatformVmConfig { ... })`.
    - `crates/lsb-vm/src/sandbox.rs:125`
    - `crates/lsb-vm/src/sandbox.rs:129`
    - `crates/lsb-vm/src/sandbox.rs:132`
    - `crates/lsb-vm/src/sandbox.rs:133`

15. The current macOS backend builds the Virtualization.framework VM.
    - Linux boot loader with kernel/initrd and command line.
    - Serial console attachment.
    - Virtio block device or NBD attachment.
    - Optional virtio network device.
    - Optional virtiofs directory sharing devices.
    - Virtio socket device.
    - Entropy and memory balloon devices.
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:107`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:112`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:117`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:127`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:139`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:155`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:162`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:171`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:174`

16. `Sandbox::start()` delegates to `PlatformVm::start()`.
    - `crates/lsb-vm/src/sandbox.rs:205`
    - `crates/lsb-platform/src/lib.rs:202`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:160`

17. Guest boot reaches `lsb-guest` as PID 1.
    - The initramfs mounts `/dev/vda`, copies `lsb-init`, and
      `switch_root`s into `/usr/bin/lsb-init`.
    - The rootfs image also contains `/usr/bin/lsb-init`.
    - `xtask/src/rootfs.rs:42`
    - `xtask/src/rootfs.rs:48`
    - `xtask/src/rootfs.rs:49`
    - `xtask/src/rootfs.rs:57`
    - `xtask/src/rootfs.rs:212`
    - `crates/lsb-guest/src/main.rs:1347`

18. Guest PID 1 initializes filesystems/networking, installs signal handlers,
    listens on vsock port `1024`, and accepts host control connections.
    - `crates/lsb-guest/src/main.rs:1350`
    - `crates/lsb-guest/src/main.rs:1359`
    - `crates/lsb-guest/src/main.rs:1362`
    - `crates/lsb-guest/src/main.rs:1378`
    - `crates/lsb-guest/src/main.rs:1390`
    - `crates/lsb-guest/src/main.rs:1401`

19. Host chooses TTY or piped exec.
    - TTY when `std::io::stdin().is_terminal()` is true:
      `sandbox.shell(command, &env)`.
    - Piped otherwise:
      `sandbox.exec_with_env(command, &env, stdout, stderr)`.
    - `crates/lsb-cli/src/vm.rs:346`
    - `crates/lsb-cli/src/vm.rs:347`
    - `crates/lsb-cli/src/vm.rs:349`

20. Piped host path: `Sandbox::exec_with_env()` connects to vsock, sends pending
    mount requests, then sends `EXEC_REQ` with `tty: None`.
    - `crates/lsb-vm/src/sandbox.rs:262`
    - `crates/lsb-vm/src/sandbox.rs:269`
    - `crates/lsb-vm/src/sandbox.rs:273`
    - `crates/lsb-vm/src/sandbox.rs:275`
    - `crates/lsb-vm/src/sandbox.rs:283`

21. TTY host path: `Sandbox::shell()` connects to vsock, sends pending mounts,
    sends `EXEC_REQ` with `tty: Some(true)`, enters raw mode, and relays stdin,
    resize, stdout, and exit frames.
    - `crates/lsb-vm/src/sandbox.rs:583`
    - `crates/lsb-vm/src/sandbox.rs:587`
    - `crates/lsb-vm/src/sandbox.rs:592`
    - `crates/lsb-vm/src/sandbox.rs:595`
    - `crates/lsb-vm/src/sandbox.rs:606`
    - `crates/lsb-vm/src/sandbox.rs:614`
    - `crates/lsb-vm/src/sandbox.rs:641`

22. Guest `handle_connection()` decodes `EXEC_REQ` and rejects empty argv.
    - `crates/lsb-guest/src/main.rs:330`
    - `crates/lsb-guest/src/main.rs:337`
    - `crates/lsb-guest/src/main.rs:356`
    - `crates/lsb-guest/src/main.rs:357`
    - `crates/lsb-guest/src/main.rs:366`

23. Guest dispatches to TTY or piped execution.
    - `req.tty.unwrap_or(false)` selects TTY.
    - Otherwise piped execution is used.
    - `crates/lsb-guest/src/main.rs:371`
    - `crates/lsb-guest/src/main.rs:377`
    - `crates/lsb-guest/src/main.rs:381`
    - `crates/lsb-guest/src/main.rs:382`

24. Piped guest path spawns the process.
    - `Command::new(&req.argv[0])`
    - `cmd.args(&req.argv[1..])`
    - Env overrides from request are applied.
    - Optional cwd is applied.
    - Stdin/stdout/stderr are piped.
    - Child gets its own process group for `KILL`.
    - `crates/lsb-guest/src/main.rs:730`
    - `crates/lsb-guest/src/main.rs:735`
    - `crates/lsb-guest/src/main.rs:736`
    - `crates/lsb-guest/src/main.rs:739`
    - `crates/lsb-guest/src/main.rs:742`
    - `crates/lsb-guest/src/main.rs:745`
    - `crates/lsb-guest/src/main.rs:751`
    - `crates/lsb-guest/src/main.rs:758`

25. Piped guest path relays output and exit.
    - stdout thread emits `STDOUT`.
    - stderr thread emits `STDERR`.
    - stdin thread consumes host `STDIN` and `KILL`.
    - Guest waits for child, calls `sync()`, sends `EXIT`.
    - `crates/lsb-guest/src/main.rs:775`
    - `crates/lsb-guest/src/main.rs:793`
    - `crates/lsb-guest/src/main.rs:811`
    - `crates/lsb-guest/src/main.rs:837`
    - `crates/lsb-guest/src/main.rs:840`
    - `crates/lsb-guest/src/main.rs:844`

26. TTY guest path executes through PTY + `execvp`.
    - `openpty()`
    - `fork()`
    - Child creates session, attaches controlling TTY, maps slave PTY to
      stdin/stdout/stderr, applies env/default `TERM`/default `PATH`, and calls
      `execvp`.
    - Parent runs `pty_poll_loop()`, relays frames, waits, syncs, and emits
      `EXIT`.
    - `crates/lsb-guest/src/main.rs:1005`
    - `crates/lsb-guest/src/main.rs:1020`
    - `crates/lsb-guest/src/main.rs:1033`
    - `crates/lsb-guest/src/main.rs:1042`
    - `crates/lsb-guest/src/main.rs:1067`
    - `crates/lsb-guest/src/main.rs:1073`
    - `crates/lsb-guest/src/main.rs:1077`
    - `crates/lsb-guest/src/main.rs:1085`
    - `crates/lsb-guest/src/main.rs:1097`
    - `crates/lsb-guest/src/main.rs:1108`
    - `crates/lsb-guest/src/main.rs:1230`
    - `crates/lsb-guest/src/main.rs:1239`
    - `crates/lsb-guest/src/main.rs:1251`

27. Host reads frames until `EXIT` or `ERROR`.
    - Piped host path writes `STDOUT` payloads to host stdout and `STDERR`
      payloads to host stderr.
    - TTY host path writes `STDOUT` payloads directly to host stdout.
    - Exit payload is parsed as the process exit code.
    - `crates/lsb-vm/src/sandbox.rs:287`
    - `crates/lsb-vm/src/sandbox.rs:289`
    - `crates/lsb-vm/src/sandbox.rs:292`
    - `crates/lsb-vm/src/sandbox.rs:295`
    - `crates/lsb-vm/src/sandbox.rs:649`
    - `crates/lsb-vm/src/sandbox.rs:660`

28. CLI stops the sandbox, removes the instance directory, and exits with the
    guest exit code.
    - `crates/lsb-cli/src/vm.rs:361`
    - `crates/lsb-cli/src/vm.rs:362`
    - `crates/lsb-cli/src/vm.rs:363`
    - `crates/lsb-cli/src/main.rs:57`
    - `crates/lsb-cli/src/main.rs:58`

### Host/Guest Boundary

- VM device boundary:
  - Kernel image, initramfs, rootfs/NBD, serial console, virtio socket, optional
    network device, optional virtiofs devices.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`

- Control channel:
  - Host connects to guest vsock port `1024`.
  - `crates/lsb-proto/src/lib.rs:192`
  - `crates/lsb-vm/src/sandbox.rs:764`
  - `crates/lsb-guest/src/main.rs:1378`

- Protocol framing:
  - Frame format is `[u32 BE length][u8 type][payload...]`.
  - `EXEC_REQ` carries JSON `ExecRequest`.
  - `STDOUT`, `STDERR`, `ERROR`, and `EXIT` return process results.
  - `crates/lsb-proto/src/frame.rs:4`
  - `crates/lsb-proto/src/frame.rs:10`
  - `crates/lsb-proto/src/frame.rs:15`
  - `crates/lsb-proto/src/frame.rs:50`
  - `crates/lsb-proto/src/lib.rs:13`

- Guest process boundary:
  - Piped path: `std::process::Command` spawns the child.
  - TTY path: guest calls `execvp` in the forked child.
  - `crates/lsb-guest/src/main.rs:735`
  - `crates/lsb-guest/src/main.rs:758`
  - `crates/lsb-guest/src/main.rs:1097`

### Important Structs And Enums

- `Cli`, `Commands::Run`, `VmArgs`
  - CLI shape and clap parsing.
  - `crates/lsb-cli/src/cli.rs:3`
  - `crates/lsb-cli/src/cli.rs:70`
  - `crates/lsb-cli/src/cli.rs:77`

- `LsbConfig`
  - Optional config file values merged with CLI flags.
  - `crates/lsb-cli/src/config.rs:6`

- `PreparedVm`
  - Runtime bundle after CLI/config/storage resolution.
  - Holds data dirs, source/work rootfs paths, kernel/initrd, resources, proxy
    config, forwards, and mounts.
  - `crates/lsb-cli/src/vm.rs:15`

- `StoragePrepareOptions`, `PreparedStorage`
  - Resolve direct vs CAS/NBD storage source and logical disk size.
  - `crates/lsb-sdk/src/storage.rs:3`
  - `crates/lsb-sdk/src/storage.rs:14`

- `Sandbox`, `VmConfigBuilder`, `MountConfig`
  - High-level host runtime API and mount plan source.
  - `crates/lsb-vm/src/sandbox.rs:24`
  - `crates/lsb-vm/src/sandbox.rs:39`
  - `crates/lsb-vm/src/sandbox.rs:152`

- `PlatformVmConfig`, `PlatformVm`, `VmState`
  - Platform backend contract used by `lsb-vm`.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/macos_aarch64/vm.rs:21`

- `ExecRequest`
  - Guest command request: `argv`, env, optional TTY size, optional cwd.
  - `crates/lsb-proto/src/lib.rs:13`

### Contracts And Invariants

- CLI argv is preserved as an argv vector. `lsb run -- echo hello` must execute
  `echo` with one argument `hello`, without host shell interpretation.

- Command resolution precedence is stable: CLI argv > config `command` >
  default `/bin/sh`.

- An empty `ExecRequest.argv` is invalid and returns a guest error.

- Each run gets a per-process instance directory and working rootfs. Normal
  `run` stops the VM and deletes that instance directory after completion.

- Host output behavior depends on TTY mode:
  - Piped mode keeps stdout and stderr separate.
  - TTY mode sends PTY output as stdout frames.

- The exit code returned by the CLI is the guest process exit code parsed from
  the `EXIT` frame.

- Guest syncs filesystem writes before reporting exit in both piped and TTY
  paths. This protects checkpoint and immediate-stop workflows.

- The frame protocol is endian-sensitive and size-limited. Frame length and exit
  payloads are big-endian.

- Pending mount requests are sent before the `EXEC_REQ` on the first vsock
  operation that needs them.

- `lsb-vm` is currently macOS-only at compile time. Platform metadata already
  lists Windows targets as planned, but the runtime trait and module exports are
  only enabled for macOS today.
  - `crates/lsb-vm/src/lib.rs:3`
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

### Windows Support Invariants

Future Windows runtime support for this path must preserve:

- Direct argv semantics across CLI, host protocol, and guest execution.
- The same guest Linux ABI and `lsb-guest` `ExecRequest` protocol.
- Equivalent vsock-like stream semantics for control connections.
- Correct stdout/stderr/exit behavior in piped mode.
- Correct raw terminal, resize, and process exit behavior in TTY mode.
- Per-run disk isolation and cleanup.
- Storage behavior equivalent to rootfs clone or CAS/NBD-backed disk.
- Guest boot into `/usr/bin/lsb-init` as PID 1.

Open Windows-specific design points:

- What backend provides `PlatformVm`: Hyper-V/WHP, WSL2, QEMU, or another
  runtime?
- Should `PlatformVm::connect_to_vsock_port() -> TcpStream` remain the cross
  platform API, or should it become an abstract stream type?
- What replaces Unix-domain NBD sockets on Windows?
- How will Windows host paths be represented without conflicting with current
  `HOST:GUEST[:mode]` mount parsing?
- What replaces macOS terminal support built on `termios`, `kqueue`, and raw
  file descriptors?

## Mount Overlay Path

### Summary

Overlay mounts share a host directory into the VM as a read-only VirtioFS lower
layer, then the Linux guest mounts a tmpfs-backed overlay at the requested guest
path. Guest writes go to the tmpfs upper layer and are discarded when the VM
exits; the host directory is not modified by overlay writes.

The CLI default for `--mount HOST:GUEST` is overlay. `:ro` also maps to overlay.
Only `:rw` maps to a direct VirtioFS mount, and that path requires
`--allow-host-writes`.

### Ordered Call Graph

1. CLI mount flags are declared as `HOST:GUEST[:ro|:rw]`.
   - `crates/lsb-cli/src/cli.rs:45`

2. `prepare_vm()` merges CLI mount flags with `lsb.json` `mounts`, parses each
   spec, and validates all mounts.
   - `crates/lsb-cli/src/vm.rs:91`
   - `crates/lsb-cli/src/vm.rs:99`
   - `crates/lsb-cli/src/vm.rs:103`

3. `parse_mount_spec()` canonicalizes the host path, then
   `parse_mount_parts()` converts mode to `MountConfig`.
   - Missing mode or `ro`: `MountConfig::Overlay`.
   - `rw`: `MountConfig::Direct { flags: 0 }`.
   - Guest paths must be absolute.
   - `crates/lsb-cli/src/vm.rs:369`
   - `crates/lsb-cli/src/vm.rs:375`
   - `crates/lsb-cli/src/vm.rs:383`
   - `crates/lsb-cli/src/vm.rs:388`

4. `validate_mounts()` rejects unsafe host paths and direct writable mounts
   without explicit host-write permission.
   - Current working directory cannot be `/`.
   - Host path cannot be `/`.
   - Host path must be under the current working directory.
   - Direct read-write mounts require `--allow-host-writes` or
     `allow_host_writes: true`.
   - `crates/lsb-cli/src/vm.rs:402`
   - `crates/lsb-cli/src/vm.rs:414`
   - `crates/lsb-cli/src/vm.rs:433`
   - `crates/lsb-cli/src/vm.rs:437`
   - `crates/lsb-cli/src/vm.rs:445`

5. `build_sandbox()` adds parsed mounts to `Sandbox::builder()`.
   - `crates/lsb-cli/src/vm.rs:206`
   - `crates/lsb-cli/src/vm.rs:232`
   - `crates/lsb-vm/src/sandbox.rs:119`

6. SDK and Node enter the same VM layer through typed mount configuration.
   Node `Sandbox.start()` builds `SandboxConfig`, validates absolute guest paths,
   canonicalizes host paths, rejects overlay flags, and creates
   `lsb_sdk::MountConfig::Overlay`.
   - `bindings/nodejs/src/sandbox.rs:36`
   - `bindings/nodejs/src/config.rs:41`
   - `bindings/nodejs/src/config.rs:60`
   - `bindings/nodejs/src/config.rs:100`
   - `bindings/nodejs/src/config.rs:117`

7. `VmConfigBuilder::build()` calls `build_mount_plan()`.
   - `crates/lsb-vm/src/sandbox.rs:125`
   - `crates/lsb-vm/src/sandbox.rs:130`
   - `crates/lsb-vm/src/sandbox.rs:157`

8. `build_mount_plan()` assigns deterministic tags (`mount0`, `mount1`, ...)
   and splits each logical mount into host platform device configuration plus a
   guest protocol request.
   - Overlay host side: `PlatformSharedDir { read_only: true }`.
   - Overlay guest side: `MountRequest::Overlay { source: tag, target }`.
   - Direct host side: read-only is derived from `MS_RDONLY`.
   - Direct guest side: `MountRequest::Direct { source, target, flags }`.
   - `crates/lsb-vm/src/sandbox.rs:161`
   - `crates/lsb-vm/src/sandbox.rs:162`
   - `crates/lsb-vm/src/sandbox.rs:168`
   - `crates/lsb-vm/src/sandbox.rs:173`
   - `crates/lsb-vm/src/sandbox.rs:183`
   - `crates/lsb-vm/src/sandbox.rs:188`

9. `lsb_platform::create_vm()` receives `PlatformVmConfig.shared_dirs`. The
   current macOS backend maps them to VirtioFS directory sharing devices.
   - `crates/lsb-vm/src/sandbox.rs:132`
   - `crates/lsb-vm/src/sandbox.rs:143`
   - `crates/lsb-platform/src/lib.rs:186`
   - `crates/lsb-platform/src/lib.rs:198`
   - `crates/lsb-platform/src/macos_aarch64/mod.rs:162`
   - `crates/lsb-platform/src/macos_aarch64/mod.rs:168`

10. The macOS directory sharing backend creates a `VZSharedDirectory` with the
    requested read-only bit and attaches it to a
    `VZVirtioFileSystemDeviceConfiguration` with the mount tag.
    - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:13`
    - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:18`
    - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:32`
    - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:36`
    - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:46`

11. After VM start, the first operation that opens the control vsock connection
    sends pending mount requests before its own request. This applies to exec,
    shell, file I/O, filesystem operations, and watch.
    - `crates/lsb-vm/src/sandbox.rs:217`
    - `crates/lsb-vm/src/sandbox.rs:220`
    - `crates/lsb-vm/src/sandbox.rs:262`
    - `crates/lsb-vm/src/sandbox.rs:313`
    - `crates/lsb-vm/src/sandbox.rs:371`
    - `crates/lsb-vm/src/sandbox.rs:503`
    - `crates/lsb-vm/src/sandbox.rs:531`
    - `crates/lsb-vm/src/sandbox.rs:561`
    - `crates/lsb-vm/src/sandbox.rs:591`

12. `send_mount_requests()` drains the pending mount vector, sends each request
    as `MOUNT_REQ`, reads a `MountResponse`, and fails the caller if the guest
    reports an error.
    - `crates/lsb-vm/src/sandbox.rs:219`
    - `crates/lsb-vm/src/sandbox.rs:220`
    - `crates/lsb-vm/src/sandbox.rs:222`
    - `crates/lsb-vm/src/sandbox.rs:226`
    - `crates/lsb-vm/src/sandbox.rs:235`

13. The guest control loop receives `MOUNT_REQ`, deserializes `MountRequest`,
    calls `process_mount()`, and replies with `MOUNT_RESP`.
    - `crates/lsb-guest/src/main.rs:330`
    - `crates/lsb-guest/src/main.rs:343`
    - `crates/lsb-guest/src/main.rs:345`
    - `crates/lsb-guest/src/main.rs:353`
    - `crates/lsb-guest/src/main.rs:354`

14. `process_mount()` creates the target mount point, dispatches overlay mounts
    to `mount_overlay()`, and returns a structured success or error response.
    - `crates/lsb-guest/src/main.rs:72`
    - `crates/lsb-guest/src/main.rs:78`
    - `crates/lsb-guest/src/main.rs:87`
    - `crates/lsb-guest/src/main.rs:96`

15. `mount_overlay()` builds the guest overlay stack.
    - Mount VirtioFS tag at `/mnt/.virtiofs/{source}`.
    - Mount tmpfs at `/mnt/.overlay/{source}`.
    - Re-create `upper` and `work` inside tmpfs.
    - Mount Linux `overlay` at the requested target with
      `lowerdir`, `upperdir`, and `workdir`.
    - `crates/lsb-guest/src/main.rs:112`
    - `crates/lsb-guest/src/main.rs:113`
    - `crates/lsb-guest/src/main.rs:118`
    - `crates/lsb-guest/src/main.rs:123`
    - `crates/lsb-guest/src/main.rs:127`
    - `crates/lsb-guest/src/main.rs:131`
    - `crates/lsb-guest/src/main.rs:136`
    - `crates/lsb-guest/src/main.rs:140`

### Host/Guest Boundary

- Host directory device boundary:
  - Host paths become platform shared directory devices before VM boot.
  - Overlay mounts must set the platform share read-only.
  - `crates/lsb-platform/src/lib.rs:178`
  - `crates/lsb-platform/src/macos_aarch64/directory_sharing.rs:18`

- VirtioFS tag boundary:
  - Host and guest coordinate through generated tags (`mount0`, `mount1`, ...).
  - The guest never sees host paths; it sees only the VirtioFS source tag and
    guest target path.
  - `crates/lsb-vm/src/sandbox.rs:162`
  - `crates/lsb-proto/src/lib.rs:56`

- Control protocol boundary:
  - `MOUNT_REQ` is frame type `0x11`.
  - `MOUNT_RESP` is frame type `0x12`.
  - Requests and responses are JSON payloads inside the binary frame protocol.
  - `crates/lsb-proto/src/frame.rs:17`
  - `crates/lsb-proto/src/frame.rs:50`
  - `crates/lsb-proto/src/frame.rs:91`

- Guest kernel boundary:
  - The guest performs Linux `mount(2)` calls for `virtiofs`, `tmpfs`, and
    `overlay`.
  - `crates/lsb-guest/src/main.rs:21`
  - `crates/lsb-guest/src/main.rs:35`

### Important Structs And Enums

- `MountConfig`
  - Host-side logical mount shape used by CLI, SDK, and VM builder.
  - `crates/lsb-vm/src/sandbox.rs:24`

- `PlatformSharedDir`
  - Platform device input: host path, generated tag, read-only bit.
  - `crates/lsb-platform/src/lib.rs:178`

- `MountRequest`
  - Host-to-guest wire request: overlay or direct.
  - Uses serde tag `type` with snake-case variants.
  - `crates/lsb-proto/src/lib.rs:51`

- `MountResponse`
  - Guest-to-host structured result with `ok` and optional `error`.
  - `crates/lsb-proto/src/lib.rs:67`

- Node `MountConfig`
  - Public JS mount shape: `type`, `hostPath`, `guestPath`, optional `flags`.
  - `bindings/nodejs/src/types.rs:49`

### Contracts And Invariants

- Overlay is the default CLI mount mode. `HOST:GUEST` and `HOST:GUEST:ro` must
  continue to isolate guest writes from the host.

- Overlay host shares must be read-only at the platform layer. The tmpfs upper
  layer is the only writable layer for overlay writes.

- Direct read-write mounts are a separate behavior and must remain guarded by
  explicit host-write opt-in.

- Mount tags are generated deterministically from mount order and must match on
  both sides of the host/guest boundary.

- Guest mount targets must be absolute paths and must be created before mount.

- Pending mount requests are drained exactly once. Any first VM operation that
  opens the control channel must apply mounts before issuing its own request.

- A guest that cannot deserialize mount responses is treated as an old checkpoint
  that does not support directory mounts, and the user is told to recreate or
  upgrade the checkpoint.

- The Linux guest kernel must include VirtioFS, overlayfs, FUSE, and tmpfs.
  - `kernel/lsb_defconfig:57`
  - `kernel/lsb_defconfig:74`
  - `kernel/lsb_defconfig:75`
  - `kernel/lsb_defconfig:76`
  - `kernel/lsb_x86_64_defconfig:103`
  - `kernel/lsb_x86_64_defconfig:110`
  - `kernel/lsb_x86_64_defconfig:111`
  - `kernel/lsb_x86_64_defconfig:112`

### Windows Support Invariants

Future Windows host support for overlay mounts must preserve:

- A platform shared-directory device equivalent to VirtioFS, or a guest-visible
  filesystem with the same Linux mount semantics.

- Per-share read-only enforcement for overlay lower layers. Relying only on
  guest overlay behavior is not equivalent if the lower share can still be
  written directly.

- The existing guest protocol: `MountRequest::Overlay { source, target }`,
  frame `MOUNT_REQ`, and `MountResponse` compatibility.

- Linux guest behavior: mount source tag as `virtiofs`, tmpfs upper/work dirs,
  and Linux `overlay` at the requested target.

- Deterministic tag generation and no host-path leakage into the guest protocol.

- Existing safety checks: host root rejection, CWD containment for CLI mounts,
  absolute guest paths, and opt-in direct host writes.

- Correct path handling for Windows drive-letter and UNC paths. The current
  `HOST:GUEST[:mode]` parser uses `splitn(3, ':')`, which conflicts with paths
  like `C:\project`.

- Equivalent first-operation ordering: mounts are applied before exec, file I/O,
  watch, or shell operations observe the guest filesystem.

Current Windows state:

- Windows platform metadata exists but is marked `Planned`.
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

- `lsb-vm` currently fails compilation on non-macOS hosts.
  - `crates/lsb-vm/src/lib.rs:3`

- `PlatformSharedDir`, `PlatformVmConfig`, `PlatformVm`, and `create_vm()` are
  currently exported only for macOS.
  - `crates/lsb-platform/src/lib.rs:178`
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/lib.rs:219`

### Questions And Unknowns

- Which Windows backend should provide the platform VM and directory sharing:
  Hyper-V/WHP, WSL2, QEMU, or something else?

- Can the Windows backend expose a Linux guest filesystem that supports the same
  `mount -t virtiofs source target` path, or does the guest mount code need a
  backend-specific filesystem type?

- Can Windows enforce read-only host sharing strongly enough for overlay lower
  layers?

- What CLI/API syntax should represent Windows drive-letter and UNC host paths
  without breaking existing `HOST:GUEST[:mode]` specs?

- How should Windows handle symlinks, junctions, reparse points, long paths,
  case-insensitive collisions, and host path canonicalization?

- The top-level README and code agree that overlay writes are tmpfs-backed and
  discarded, but `skills/lsb/SKILL.md` says mounts are read-write and
  host-visible. That documentation conflict should be resolved.

## Port Forwarding Path

### Summary

Port forwarding maps host loopback TCP ports to guest loopback TCP ports over
vsock. It does not require `--allow-net`; the guest can have no network device
and still serve traffic forwarded from the host.

The public shape is `HOST:GUEST` for CLI/config callers and `{ host, guest }`
for Node callers. The host binds `127.0.0.1:HOST`, opens one fresh vsock
connection to guest forwarding port `1025` for each accepted client connection,
sends a framed `ForwardRequest { port: GUEST }`, waits for `ForwardResponse`,
then relays raw bytes between the host TCP stream and the vsock stream. The
guest accepts the vsock connection, connects to `127.0.0.1:GUEST` inside Linux,
then relays bytes between vsock and that guest-local TCP stream.

### Ordered Call Graph

1. CLI exposes `-p/--port HOST:GUEST`.
   - `crates/lsb-cli/src/cli.rs:41`
   - `crates/lsb-cli/src/cli.rs:42`
   - `crates/lsb-cli/src/cli.rs:43`

2. `main()` handles `Commands::Run`, loads config, resolves the command, and
   calls `vm::prepare_vm(...)`.
   - `crates/lsb-cli/src/main.rs:28`
   - `crates/lsb-cli/src/main.rs:36`
   - `crates/lsb-cli/src/main.rs:47`

3. `prepare_vm()` merges CLI `-p` flags with `lsb.json` `ports`. CLI ports are
   pushed first; config ports are appended, not used as replacements.
   - `crates/lsb-cli/src/vm.rs:77`
   - `crates/lsb-cli/src/vm.rs:78`
   - `crates/lsb-cli/src/vm.rs:79`
   - `crates/lsb-cli/src/vm.rs:84`
   - `skills/lsb/references/networking.md:84`

4. Each port string is parsed as exactly `HOST:GUEST` into `PortMapping`.
   - `crates/lsb-cli/src/vm.rs:85`
   - `crates/lsb-cli/src/vm.rs:87`
   - `crates/lsb-cli/src/vm.rs:479`
   - `crates/lsb-cli/src/vm.rs:490`

5. Normal CLI execution starts the VM, then starts forwarding if any mappings
   were configured.
   - `crates/lsb-cli/src/vm.rs:313`
   - `crates/lsb-cli/src/vm.rs:318`
   - `crates/lsb-cli/src/vm.rs:319`

6. Stdio mode follows the same ordering: build/start the sandbox, then start
   forwarding before sending the ready notification.
   - `crates/lsb-cli/src/stdio.rs:329`
   - `crates/lsb-cli/src/stdio.rs:335`
   - `crates/lsb-cli/src/stdio.rs:355`

7. SDK callers pass `SandboxConfig.ports`; `boot_vm()` starts forwarding after
   `sandbox.start()`.
   - `crates/lsb-sdk/src/types.rs:27`
   - `crates/lsb-sdk/src/runtime.rs:433`
   - `crates/lsb-sdk/src/runtime.rs:581`
   - `crates/lsb-sdk/src/runtime.rs:583`

8. Node callers pass `StartOptions.ports`; `Sandbox.start()` converts JS port
   objects to SDK `PortMapping` before boot.
   - `bindings/nodejs/src/types.rs:39`
   - `bindings/nodejs/src/types.rs:85`
   - `bindings/nodejs/src/sandbox.rs:40`
   - `bindings/nodejs/src/config.rs:42`
   - `bindings/nodejs/src/config.rs:53`
   - `bindings/nodejs/src/config.rs:152`

9. `Sandbox::start_port_forwarding()` creates one nonblocking host
   `TcpListener` per mapping, bound to `127.0.0.1:host_port`.
   - `crates/lsb-vm/src/sandbox.rs:692`
   - `crates/lsb-vm/src/sandbox.rs:694`
   - `crates/lsb-vm/src/sandbox.rs:699`
   - `crates/lsb-vm/src/sandbox.rs:700`
   - `crates/lsb-vm/src/sandbox.rs:702`

10. Each listener runs in a thread, accepts host clients, forces the accepted
    stream back to blocking mode, and spawns one handler thread per connection.
    - `crates/lsb-vm/src/sandbox.rs:713`
    - `crates/lsb-vm/src/sandbox.rs:715`
    - `crates/lsb-vm/src/sandbox.rs:717`
    - `crates/lsb-vm/src/sandbox.rs:719`
    - `crates/lsb-vm/src/sandbox.rs:721`
    - `crates/lsb-vm/src/sandbox.rs:723`

11. The host connection handler opens a fresh vsock connection to
    `VSOCK_PORT_FORWARD` (`1025`), sends `FWD_REQ`, reads `FWD_RESP`, and fails
    the client connection if the guest rejects the forward.
    - `crates/lsb-vm/src/sandbox.rs:804`
    - `crates/lsb-vm/src/sandbox.rs:809`
    - `crates/lsb-vm/src/sandbox.rs:815`
    - `crates/lsb-vm/src/sandbox.rs:816`
    - `crates/lsb-vm/src/sandbox.rs:819`
    - `crates/lsb-vm/src/sandbox.rs:825`

12. On success, the host starts bidirectional byte relay between host TCP and
    vsock. Each direction runs in its own thread and half-closes the peer write
    side when `std::io::copy` returns.
    - `crates/lsb-vm/src/sandbox.rs:832`
    - `crates/lsb-vm/src/sandbox.rs:837`
    - `crates/lsb-vm/src/sandbox.rs:843`
    - `crates/lsb-vm/src/sandbox.rs:844`
    - `crates/lsb-vm/src/sandbox.rs:845`
    - `crates/lsb-vm/src/sandbox.rs:847`

13. The current macOS platform backend implements `connect_to_vsock_port()` via
    the Virtualization.framework virtio socket device, duplicates the returned
    file descriptor, and wraps it as `TcpStream`.
    - `crates/lsb-platform/src/lib.rs:201`
    - `crates/lsb-platform/src/lib.rs:206`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:171`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:241`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:247`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:269`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:276`

14. Guest PID 1 creates a forwarding vsock listener on `VSOCK_PORT_FORWARD`
    (`1025`) and runs it on a separate accept loop thread.
    - `crates/lsb-guest/src/main.rs:251`
    - `crates/lsb-guest/src/main.rs:271`
    - `crates/lsb-guest/src/main.rs:293`
    - `crates/lsb-guest/src/main.rs:1381`
    - `crates/lsb-guest/src/main.rs:1386`

15. The guest forwarding accept loop spawns one handler thread per vsock client.
    - `crates/lsb-guest/src/main.rs:1254`
    - `crates/lsb-guest/src/main.rs:1256`
    - `crates/lsb-guest/src/main.rs:1263`
    - `crates/lsb-guest/src/main.rs:1264`

16. The guest handler reads `FWD_REQ`, deserializes `ForwardRequest`, connects to
    `127.0.0.1:req.port` inside the guest, sends `FWD_RESP`, then starts
    bidirectional relay.
    - `crates/lsb-guest/src/main.rs:1269`
    - `crates/lsb-guest/src/main.rs:1274`
    - `crates/lsb-guest/src/main.rs:1279`
    - `crates/lsb-guest/src/main.rs:1291`
    - `crates/lsb-guest/src/main.rs:1292`
    - `crates/lsb-guest/src/main.rs:1306`
    - `crates/lsb-guest/src/main.rs:1315`

17. Guest relay mirrors the host relay: one thread copies vsock to guest TCP,
    the other copies guest TCP to vsock, and both use write-side shutdown for
    EOF propagation.
    - `crates/lsb-guest/src/main.rs:1318`
    - `crates/lsb-guest/src/main.rs:1324`
    - `crates/lsb-guest/src/main.rs:1325`
    - `crates/lsb-guest/src/main.rs:1326`
    - `crates/lsb-guest/src/main.rs:1328`
    - `crates/lsb-guest/src/main.rs:1330`

### Host/Guest Boundary

- Host public TCP boundary:
  - The only host address currently exposed is `127.0.0.1:HOST`.
  - Remote machines cannot connect unless another host-level proxy forwards to
    that loopback listener.
  - `crates/lsb-vm/src/sandbox.rs:699`

- VM transport boundary:
  - Port forwarding crosses the VM boundary over virtio-vsock, not over the
    optional proxy network device.
  - Forwarding uses dedicated vsock port `1025`; regular control traffic uses
    vsock port `1024`.
  - `crates/lsb-proto/src/lib.rs:192`
  - `crates/lsb-proto/src/lib.rs:193`

- Guest service boundary:
  - The guest forwards only to `127.0.0.1:GUEST` inside Linux.
  - Guest services listening on non-loopback-only interfaces may still be
    reachable through the loopback path only if Linux routes them there; the
    implementation does not connect to guest external addresses.
  - `crates/lsb-guest/src/main.rs:1291`
  - `crates/lsb-guest/src/main.rs:1292`

- Protocol boundary:
  - The handshake is a JSON payload inside the shared binary frame protocol:
    `[u32 BE length][u8 type][payload]`.
  - `FWD_REQ` is frame type `0x20`; `FWD_RESP` is frame type `0x21`.
  - After `FWD_RESP { status: "ok" }`, the stream switches to raw byte relay.
  - `crates/lsb-proto/src/frame.rs:28`
  - `crates/lsb-proto/src/frame.rs:50`
  - `crates/lsb-proto/src/frame.rs:91`

- Kernel boundary:
  - The guest kernel must include vsock and virtio-vsock support.
  - `kernel/lsb_defconfig:60`
  - `kernel/lsb_defconfig:61`
  - `kernel/lsb_defconfig:62`
  - `kernel/lsb_defconfig:63`
  - `kernel/lsb_x86_64_defconfig:69`
  - `kernel/lsb_x86_64_defconfig:70`
  - `kernel/lsb_x86_64_defconfig:71`

### Important Structs And Enums

- `PortMapping`
  - Host-side logical mapping: `host_port` is the listener port on the host,
    `guest_port` is the target port inside Linux.
  - `crates/lsb-proto/src/lib.rs:30`

- `ForwardRequest`
  - Host-to-guest wire request. It carries only the guest port because the host
    port is already consumed by the host listener.
  - `crates/lsb-proto/src/lib.rs:37`

- `ForwardResponse`
  - Guest-to-host handshake result. `status == "ok"` permits raw byte relay;
    any other status is treated as a refused forward.
  - `crates/lsb-proto/src/lib.rs:43`
  - `crates/lsb-vm/src/sandbox.rs:825`

- `VSOCK_PORT_FORWARD`
  - Dedicated guest vsock listener port for forwarding, currently `1025`.
  - `crates/lsb-proto/src/lib.rs:193`

- `PortForwardHandle`
  - Owns listener-thread shutdown. Dropping it sets a shared stop flag and joins
    listener threads.
  - `crates/lsb-vm/src/sandbox.rs:788`
  - `crates/lsb-vm/src/sandbox.rs:795`

- `PlatformVm`
  - Host-platform abstraction that must provide `connect_to_vsock_port()`.
  - Current exports are macOS-only.
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/lib.rs:206`

- Node `PortMappingConfig`
  - Public JS shape with `host` and `guest` as `u32`, validated down to `u16`.
  - `bindings/nodejs/src/types.rs:39`
  - `bindings/nodejs/src/config.rs:169`

### Contracts And Invariants

- Port forwarding must continue to work without `--allow-net`. It is documented
  as vsock-based and independent of the guest network device.
  - `README.md:66`
  - `README.md:68`
  - `skills/lsb/references/networking.md:64`

- The host bind address is loopback-only: `127.0.0.1`, not `0.0.0.0`.

- `HOST:GUEST` parsing is strict for CLI/config. A single port form is not
  accepted for host-to-guest forwarding.

- CLI `-p` flags and config `ports` are merged. Existing behavior appends config
  ports after CLI ports.

- Each accepted host TCP connection gets a fresh vsock connection and handshake.
  There is no multiplexing over a single shared vsock stream.

- The host and guest relay code assumes blocking `TcpStream` behavior,
  `try_clone()` for split read/write ownership, and `Shutdown::Write` to
  propagate half-close.

- Listener failure to accept a single client should not stop other forwarding
  mappings. Per-connection errors are logged at debug level and the listener
  loop continues unless the listener itself fails or the handle is dropped.

- The guest target remains guest-local loopback TCP. The wire request must not
  let a host caller select arbitrary guest IP addresses without an intentional
  security review.

- `ForwardResponse.status` string compatibility matters. Current host code checks
  for literal `"ok"` and treats anything else as an error.

- The forwarding handshake currently ignores the returned frame type on both
  host and guest while parsing payloads. Tightening that behavior would be a
  protocol change unless compatibility is handled.

- Node and SDK API shapes should keep the same port range validation. Node
  rejects ports outside `u16`.
  - `bindings/nodejs/test/index.spec.ts:326`

### Windows Support Invariants

Future Windows host support for port forwarding must preserve:

- A platform VM implementation that can attach a Linux guest vsock device and
  connect from host to guest vsock port `1025`.

- A host-side stream abstraction with the same practical behavior as the current
  `TcpStream` returned by macOS: blocking reads/writes, clonable read/write
  handles, and write-side shutdown.

- Loopback-only host exposure by default. Windows implementations should bind
  equivalent IPv4 loopback behavior unless the public API explicitly changes.

- The existing public API:
  - CLI/config `HOST:GUEST`.
  - Rust SDK `PortMapping { host_port, guest_port }`.
  - Node `{ host, guest }`.

- `--allow-net` independence. Windows support must not require the outbound
  proxy network device just to make host-to-guest forwarding work.

- Per-accepted-connection vsock dialing and handshake. A Windows transport that
  multiplexes internally must still preserve the externally observable behavior:
  connection isolation, EOF behavior, and failure of one client not affecting
  other clients.

- The same guest Linux daemon protocol and port constants:
  `FWD_REQ`, `FWD_RESP`, and `VSOCK_PORT_FORWARD = 1025`.

- Guest kernel vsock support in the Windows-targeted OS image.

- Correct lifecycle cleanup: dropping the forwarding handle must unblock or end
  listener loops and join owned listener threads without leaking background
  runtime state.

Current Windows state:

- Windows platform metadata exists but is marked `Planned`.
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

- `lsb-vm` currently fails compilation on non-macOS hosts.
  - `crates/lsb-vm/src/lib.rs:3`

- `PlatformVm`, `PlatformVmConfig`, and `create_vm()` are currently exported only
  for macOS.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/lib.rs:219`

- Node runtime support is currently gated to macOS x86_64 and Apple Silicon.
  - `bindings/nodejs/build.rs:1`
  - `bindings/nodejs/build.rs:7`
  - `bindings/nodejs/src/error.rs:3`

### Questions And Unknowns

- Which Windows VM backend should own vsock: Hyper-V/WHP, WSL2, QEMU, or another
  backend?

- Can the selected Windows backend expose host-to-guest vsock as something that
  can safely satisfy the current `TcpStream`-shaped contract, or should
  `PlatformVm::connect_to_vsock_port()` return a custom stream trait?

- Should Windows support IPv6 loopback (`::1`) in addition to current IPv4
  `127.0.0.1`, and if so how should that be represented without changing
  existing behavior?

- Should host port `0` be accepted? The current `u16` parser allows it, but there
  is no API to report the kernel-assigned ephemeral port.

- Should the forwarding handshake validate frame types explicitly? Current host
  and guest code deserialize payloads regardless of the received frame type.

- There does not appear to be an end-to-end port-forwarding test in the searched
  tree. Node currently covers out-of-range port validation, but not successful
  forwarding behavior.

## Checkpoint Save/Restore Path

### Summary

Checkpoints save root disk state, not VM memory or running process state. Restore
boots a new VM whose root disk is sourced from the saved checkpoint.

There are two checkpoint formats:

- CAS/NBD checkpoints: `{data_dir}/checkpoints/{name}.idx`
- Direct ext4 checkpoints: `{data_dir}/checkpoints/{name}.ext4`

Default storage mode uses CAS/NBD. `LSB_STORAGE=direct` uses ext4 files and
cannot restore `.idx` checkpoints.

Before saving a checkpoint, the host asks the guest to flush filesystem state by
executing `sync` over the normal guest exec protocol. The guest also calls
`libc::sync()` after command completion in both piped and TTY exec paths.

### Ordered Call Graph

#### CLI `lsb checkpoint create`

1. CLI exposes `checkpoint create <name> [--from <checkpoint>] [-- command...]`.
   - `crates/lsb-cli/src/cli.rs:115`
   - `crates/lsb-cli/src/cli.rs:125`
   - `crates/lsb-cli/src/cli.rs:127`

2. `main()` dispatches `CheckpointCommands::Create` to `checkpoint::create(...)`
   and exits with the guest command exit code.
   - `crates/lsb-cli/src/main.rs:102`
   - `crates/lsb-cli/src/main.rs:103`
   - `crates/lsb-cli/src/main.rs:109`
   - `crates/lsb-cli/src/main.rs:110`

3. `checkpoint::create()` loads config, defaults the command to `/bin/sh`, and
   validates the checkpoint name.
   - `crates/lsb-cli/src/checkpoint.rs:11`
   - `crates/lsb-cli/src/checkpoint.rs:17`
   - `crates/lsb-cli/src/checkpoint.rs:19`
   - `crates/lsb-cli/src/checkpoint.rs:27`

4. CLI checkpoint creation rejects an existing `.idx` or `.ext4` checkpoint with
   the same name.
   - `crates/lsb-cli/src/checkpoint.rs:28`
   - `crates/lsb-cli/src/checkpoint.rs:150`

5. `checkpoint::create()` prepares the VM, then runs the requested command using
   the checkpoint-aware command path.
   - `crates/lsb-cli/src/checkpoint.rs:32`
   - `crates/lsb-cli/src/checkpoint.rs:33`
   - `crates/lsb-cli/src/vm.rs:270`

6. `vm::prepare_vm()` resolves data paths, storage, instance directory, working
   rootfs path, kernel/initrd, resources, proxy config, forwards, and mounts.
   - `crates/lsb-cli/src/vm.rs:37`
   - `crates/lsb-cli/src/vm.rs:107`
   - `crates/lsb-cli/src/vm.rs:133`
   - `crates/lsb-cli/src/vm.rs:143`
   - `crates/lsb-cli/src/vm.rs:147`

7. `prepare_vm()` delegates checkpoint/base-rootfs resolution to
   `lsb_sdk::prepare_storage(...)`.
   - `crates/lsb-cli/src/vm.rs:133`
   - `crates/lsb-sdk/src/storage.rs:46`

8. For default NBD storage, `prepare_vm()` creates an empty working rootfs
   placeholder. The actual root disk blocks are served by NBD.
   - `crates/lsb-cli/src/vm.rs:148`
   - `crates/lsb-cli/src/vm.rs:154`

9. For direct storage, `prepare_vm()` creates a COW copy of the selected source
   rootfs into the instance directory.
   - `crates/lsb-cli/src/vm.rs:148`
   - `crates/lsb-cli/src/vm.rs:152`

10. `run_command_for_checkpoint()` calls `run_command_inner(..., true)`.
    - `crates/lsb-cli/src/vm.rs:270`
    - `crates/lsb-cli/src/vm.rs:274`
    - `crates/lsb-cli/src/vm.rs:277`

11. `run_command_inner()` optionally starts proxy networking, starts NBD, builds
    the sandbox, and starts the VM.
    - `crates/lsb-cli/src/vm.rs:291`
    - `crates/lsb-cli/src/vm.rs:305`
    - `crates/lsb-cli/src/vm.rs:308`
    - `crates/lsb-cli/src/vm.rs:313`

12. `start_nbd()` creates a per-instance Unix socket, points CAS at the active
    rootfs/index, and starts the NBD server.
    - `crates/lsb-cli/src/vm.rs:244`
    - `crates/lsb-cli/src/vm.rs:249`
    - `crates/lsb-cli/src/vm.rs:257`
    - `crates/lsb-store/src/lib.rs:106`

13. `build_sandbox()` passes either the working rootfs path or the NBD URI into
    `Sandbox::builder()`.
    - `crates/lsb-cli/src/vm.rs:206`
    - `crates/lsb-cli/src/vm.rs:212`
    - `crates/lsb-cli/src/vm.rs:224`
    - `crates/lsb-cli/src/vm.rs:236`

14. `VmConfigBuilder::build()` creates `PlatformVmConfig`. The macOS backend
    attaches either `NbdAttachment` or `DiskImageAttachment` as the virtio block
    device.
    - `crates/lsb-vm/src/sandbox.rs:125`
    - `crates/lsb-vm/src/sandbox.rs:132`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:139`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:141`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:145`

15. The guest command runs over the existing exec protocol. After it exits,
    `run_command_inner()` executes guest `sync` because
    `sync_before_stop == true`.
    - `crates/lsb-cli/src/vm.rs:346`
    - `crates/lsb-cli/src/vm.rs:357`
    - `crates/lsb-cli/src/vm.rs:358`
    - `crates/lsb-guest/src/main.rs:840`
    - `crates/lsb-guest/src/main.rs:1239`

16. The host stops the VM and returns `RunResult { exit_code, nbd_handle }`.
    - `crates/lsb-cli/src/vm.rs:361`
    - `crates/lsb-cli/src/vm.rs:362`
    - `crates/lsb-cli/src/vm.rs:363`

17. `checkpoint::create()` saves the disk state after command completion,
    regardless of the guest command exit code.
    - `crates/lsb-cli/src/checkpoint.rs:35`
    - `crates/lsb-cli/src/checkpoint.rs:37`
    - `crates/lsb-cli/src/checkpoint.rs:48`

18. If an NBD handle exists, saving writes a CAS index at
    `{checkpoints_dir}/{name}.idx`.
    - `crates/lsb-cli/src/checkpoint.rs:37`
    - `crates/lsb-cli/src/checkpoint.rs:38`
    - `crates/lsb-cli/src/checkpoint.rs:39`
    - `crates/lsb-store/src/lib.rs:33`
    - `crates/lsb-store/src/cas.rs:310`

19. If no NBD handle exists, saving COW-copies the working rootfs to
    `{checkpoints_dir}/{name}.ext4`.
    - `crates/lsb-cli/src/checkpoint.rs:40`
    - `crates/lsb-cli/src/checkpoint.rs:41`
    - `crates/lsb-cli/src/checkpoint.rs:42`

20. The NBD handle is dropped and the per-instance directory is removed.
    - `crates/lsb-cli/src/checkpoint.rs:46`
    - `crates/lsb-cli/src/checkpoint.rs:47`
    - `crates/lsb-store/src/lib.rs:42`

#### SDK And Node `checkpoint()`

1. Node `Sandbox.checkpoint(name)` delegates to `lsb_sdk::AsyncSandbox`.
   - `bindings/nodejs/src/sandbox.rs:390`
   - `bindings/nodejs/src/sandbox.rs:394`
   - `bindings/nodejs/src/sandbox.rs:397`

2. `AsyncSandbox::checkpoint()` sends `SandboxCmd::Checkpoint` to the VM owner
   thread.
   - `crates/lsb-sdk/src/runtime.rs:399`
   - `crates/lsb-sdk/src/runtime.rs:401`
   - `crates/lsb-sdk/src/runtime.rs:403`
   - `crates/lsb-sdk/src/runtime.rs:404`

3. `run_vm_loop()` handles the command on the VM thread, validates the name,
   creates the checkpoint directory, runs guest `sync`, and saves `.idx` or
   `.ext4`.
   - `crates/lsb-sdk/src/runtime.rs:631`
   - `crates/lsb-sdk/src/runtime.rs:714`
   - `crates/lsb-sdk/src/runtime.rs:716`
   - `crates/lsb-sdk/src/runtime.rs:717`
   - `crates/lsb-sdk/src/runtime.rs:718`
   - `crates/lsb-sdk/src/runtime.rs:719`
   - `crates/lsb-sdk/src/runtime.rs:723`

4. Unlike CLI `checkpoint create`, the SDK checkpoint command does not stop the
   VM after saving. The caller must call `stop()`.
   - `crates/lsb-sdk/src/runtime.rs:733`
   - `crates/lsb-sdk/src/runtime.rs:735`

#### Stdio JSON-RPC `checkpoint`

1. Hidden stdio mode exposes method `"checkpoint"` with `CheckpointParams { name }`.
   - `crates/lsb-cli/src/stdio.rs:16`
   - `crates/lsb-cli/src/stdio.rs:24`
   - `crates/lsb-cli/src/stdio.rs:171`

2. `run_stdio()` starts the VM and holds the optional NBD handle.
   - `crates/lsb-cli/src/stdio.rs:314`
   - `crates/lsb-cli/src/stdio.rs:326`
   - `crates/lsb-cli/src/stdio.rs:329`
   - `crates/lsb-cli/src/stdio.rs:335`

3. On method `"checkpoint"`, stdio mode calls `handle_checkpoint(...)`, stops the
   VM, joins the event thread, and returns `Ok(0)`.
   - `crates/lsb-cli/src/stdio.rs:700`
   - `crates/lsb-cli/src/stdio.rs:713`
   - `crates/lsb-cli/src/stdio.rs:721`
   - `crates/lsb-cli/src/stdio.rs:724`

4. `handle_checkpoint()` executes guest `sync`, creates the checkpoint directory,
   and saves `.idx` or `.ext4`.
   - `crates/lsb-cli/src/stdio.rs:976`
   - `crates/lsb-cli/src/stdio.rs:986`
   - `crates/lsb-cli/src/stdio.rs:995`
   - `crates/lsb-cli/src/stdio.rs:1004`
   - `crates/lsb-cli/src/stdio.rs:1015`

#### Restore From Checkpoint

1. CLI restore starts at `lsb run --from <name>` or
   `lsb checkpoint create <new> --from <name>`.
   - `crates/lsb-cli/src/cli.rs:84`
   - `crates/lsb-cli/src/cli.rs:135`
   - `crates/lsb-cli/src/main.rs:47`
   - `crates/lsb-cli/src/checkpoint.rs:32`

2. Node restore starts at `Sandbox.start({ from })`, which maps JS options to
   `SandboxConfig.from`.
   - `bindings/nodejs/src/types.rs:66`
   - `bindings/nodejs/src/types.rs:72`
   - `bindings/nodejs/src/config.rs:42`
   - `bindings/nodejs/src/config.rs:46`
   - `bindings/nodejs/src/sandbox.rs:40`

3. SDK restore starts in `boot_vm(config)` and calls the same
   `prepare_storage(...)` helper.
   - `crates/lsb-sdk/src/runtime.rs:433`
   - `crates/lsb-sdk/src/runtime.rs:457`
   - `crates/lsb-sdk/src/runtime.rs:461`

4. `prepare_storage()` rejects `from` with `base_version`.
   - `crates/lsb-sdk/src/storage.rs:46`
   - `crates/lsb-sdk/src/storage.rs:47`
   - `crates/lsb-sdk/src/storage.rs:48`

5. Direct mode restore checks `{name}.idx` first and rejects it, because direct
   mode can only boot from an ext4 checkpoint.
   - `crates/lsb-sdk/src/storage.rs:51`
   - `crates/lsb-sdk/src/storage.rs:72`
   - `crates/lsb-sdk/src/storage.rs:76`
   - `crates/lsb-sdk/src/storage.rs:78`

6. Direct mode restore uses `{name}.ext4` as the direct source rootfs.
   - `crates/lsb-sdk/src/storage.rs:84`
   - `crates/lsb-sdk/src/storage.rs:85`

7. Default NBD restore prefers `{name}.idx`. It loads the index size and uses the
   base rootfs path plus checkpoint index as the NBD source.
   - `crates/lsb-sdk/src/storage.rs:113`
   - `crates/lsb-sdk/src/storage.rs:117`
   - `crates/lsb-sdk/src/storage.rs:119`
   - `crates/lsb-sdk/src/storage.rs:120`
   - `crates/lsb-sdk/src/storage.rs:121`

8. If only `{name}.ext4` exists in default NBD mode, the ext4 checkpoint is pinned
   into CAS, then restored through the pinned index.
   - `crates/lsb-sdk/src/storage.rs:127`
   - `crates/lsb-sdk/src/storage.rs:128`
   - `crates/lsb-sdk/src/storage.rs:129`
   - `crates/lsb-sdk/src/storage.rs:130`

9. The selected storage source then follows the normal VM boot path: create
   per-instance working rootfs or NBD placeholder, start NBD if needed, build VM,
   attach disk, and boot.
   - `crates/lsb-cli/src/vm.rs:143`
   - `crates/lsb-cli/src/vm.rs:148`
   - `crates/lsb-cli/src/vm.rs:244`
   - `crates/lsb-sdk/src/runtime.rs:471`
   - `crates/lsb-sdk/src/runtime.rs:495`
   - `crates/lsb-sdk/src/runtime.rs:540`
   - `crates/lsb-sdk/src/runtime.rs:554`

### Host/Guest Boundary

- Save consistency boundary:
  - Host sends an `EXEC_REQ` for `sync` over vsock port `1024`.
  - Guest runs the command and exits through the same `STDOUT`/`STDERR`/`EXIT`
    frame protocol as normal exec.
  - `crates/lsb-vm/src/sandbox.rs:253`
  - `crates/lsb-vm/src/sandbox.rs:269`
  - `crates/lsb-vm/src/sandbox.rs:283`
  - `crates/lsb-guest/src/main.rs:356`

- Disk device boundary:
  - Direct storage attaches a host ext4 file as a virtio block device.
  - NBD storage attaches a host NBD server as a virtio block device.
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:139`
  - `crates/lsb-platform/src/macos_aarch64/storage.rs:54`
  - `crates/lsb-platform/src/macos_aarch64/storage.rs:101`

- NBD protocol boundary:
  - Host NBD server listens on a per-instance Unix socket.
  - macOS Virtualization.framework connects as NBD client.
  - NBD reads/writes are backed by `CasBackend`.
  - `crates/lsb-store/src/lib.rs:58`
  - `crates/lsb-store/src/lib.rs:63`
  - `crates/lsb-store/src/lib.rs:82`
  - `crates/lsb-store/src/nbd.rs:76`
  - `crates/lsb-store/src/nbd.rs:278`

- CAS persistence boundary:
  - Dirty chunk data is not fully durable until `CasBackend::flush()`.
  - `NbdHandle::save_checkpoint()` calls `save_index()`, which flushes dirty
    chunks before saving the index.
  - `NbdHandle::drop()` also flushes the CAS backend.
  - `crates/lsb-store/src/lib.rs:33`
  - `crates/lsb-store/src/lib.rs:44`
  - `crates/lsb-store/src/cas.rs:295`
  - `crates/lsb-store/src/cas.rs:310`

- Mount boundary:
  - Host directory mounts are separate virtiofs devices.
  - Overlay mount writes live in guest tmpfs and are not captured in root disk
    checkpoints.
  - Direct mount writes go to the host directory and are not root disk checkpoint
    content.
  - `crates/lsb-vm/src/sandbox.rs:157`
  - `crates/lsb-guest/src/main.rs:112`
  - `crates/lsb-guest/src/main.rs:148`

### Important Structs And Enums

- `CheckpointCommands`
  - Public CLI checkpoint subcommands.
  - `crates/lsb-cli/src/cli.rs:125`

- `PreparedVm`
  - CLI-prepared runtime state: data dirs, checkpoint dir, instance dir,
    source/work rootfs, optional CAS index, kernel/initrd, resources, proxy,
    port forwards, and mounts.
  - `crates/lsb-cli/src/vm.rs:15`

- `RunResult`
  - Carries guest command exit code and optional `NbdHandle` back to
    checkpoint-saving code.
  - `crates/lsb-cli/src/vm.rs:239`

- `StoragePrepareOptions`, `PreparedStorage`, `NbdSource`
  - Shared storage resolver used by CLI and SDK restore paths.
  - `crates/lsb-sdk/src/storage.rs:3`
  - `crates/lsb-sdk/src/storage.rs:14`
  - `crates/lsb-sdk/src/storage.rs:40`

- `SandboxConfig`
  - SDK boot config. `from` selects a checkpoint, and `base_version` selects a
    pinned base rootfs version when no checkpoint is used.
  - `crates/lsb-sdk/src/types.rs:9`
  - `crates/lsb-sdk/src/types.rs:31`
  - `crates/lsb-sdk/src/types.rs:33`

- `SandboxCmd::Checkpoint`
  - SDK VM-thread command used by Rust and Node callers.
  - `crates/lsb-sdk/src/runtime.rs:88`

- `NbdHandle`
  - Owns the NBD socket, server thread, shutdown channel, and optional CAS
    backend used for checkpoint saves.
  - `crates/lsb-store/src/lib.rs:21`

- `ChunkIndex`
  - Serialized checkpoint index: disk size, chunk hashes, optional parent path,
    and optional fallback rootfs path.
  - `crates/lsb-store/src/cas.rs:62`
  - `crates/lsb-store/src/cas.rs:100`
  - `crates/lsb-store/src/cas.rs:126`

- `CasBackend`
  - NBD backend that reads from dirty chunks, current index, parent indexes,
    fallback rootfs, or zero-filled chunks.
  - `crates/lsb-store/src/cas.rs:175`
  - `crates/lsb-store/src/cas.rs:322`

- `PinnedRootfs`, `BaseVersionRecord`
  - CAS-pinned base image metadata used for stable base-version resolution.
  - `crates/lsb-store/src/base.rs:11`
  - `crates/lsb-store/src/base.rs:18`

- `PlatformVmConfig`, `PlatformVm`
  - Host-platform abstraction that must provide VM lifecycle and vsock
    connection support.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`

### Contracts And Invariants

- Checkpoints represent root disk state only. They do not preserve VM RAM, kernel
  state, running processes, open file descriptors, port-forward connections, or
  proxy state.

- Restore always creates a fresh per-instance VM from the saved disk source.
  Changes made after restore are discarded unless another checkpoint is saved.

- Checkpoint names must not be empty or contain `/`, `\`, NUL, or `..`.
  - `crates/lsb-vm/src/lib.rs:17`

- `from` and `base_version` are mutually exclusive.

- Default storage mode prefers `.idx` over `.ext4` for the same checkpoint name.

- Direct storage mode cannot restore CAS `.idx` checkpoints.

- Guest filesystem writes must be flushed before host-side checkpoint capture.
  The implementation currently layers guest command-exit `sync`, explicit
  checkpoint `sync`, NBD flush, and CAS index save.

- CAS checkpoint save must flush dirty chunks before writing the index.

- CAS indexes must preserve disk size, hash order, parent path, fallback path,
  and the `"ZERO"` sparse-chunk sentinel.

- NBD logical disk size must match the checkpoint/base logical size, extended to
  the requested disk size only when the requested size is larger.

- Requested disk size must not be smaller than the selected source image or CAS
  logical size.

- `copy_file_cow()` must produce an isolated writable working copy/checkpoint
  copy. On macOS this is APFS `clonefile`.

- Host directory mount contents are not root disk checkpoint contents. Overlay
  upperdirs are tmpfs and direct mount writes affect host files directly.

- CLI `checkpoint create` currently rejects existing checkpoint names. SDK
  checkpoint save currently overwrites the target `.idx` path and removes an
  existing `.ext4` path before direct save.

### Windows Support Invariants

Future Windows host support for checkpoints must preserve:

- The public checkpoint model: save root disk state, restore by booting a fresh
  Linux guest from that disk state.

- Compatibility with existing `.idx` CAS checkpoints and `.ext4` checkpoints, or
  an explicit migration path.

- CAS chunk semantics: 64 KiB chunks, BLAKE3 hash-addressed chunk files,
  `"ZERO"` sparse chunks, parent chains, fallback rootfs paths, and durable index
  writes.

- Equivalent NBD behavior or a storage backend with the same observable block
  semantics: guest reads/writes a virtio-style block device, host can flush dirty
  writes, and checkpoint save captures a consistent index.

- Equivalent guest `sync` ordering before host-side capture.

- Per-instance working disk isolation and cleanup.

- A copy-on-write or equivalent copy primitive for direct `.ext4` mode. Windows
  cannot use APFS `clonefile`; ReFS block cloning, full copy, or another backend
  must preserve isolation and correctness.

- Path handling that does not break checkpoint names or CAS index paths on
  Windows. Current code stores string paths inside indexes and validates both `/`
  and `\` in checkpoint names.

- A platform VM implementation that provides the current `PlatformVm` lifecycle
  and vsock control connection behavior.

Current Windows state:

- Windows platform metadata exists but is marked `Planned`.
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

- `lsb-vm` currently fails compilation on non-macOS hosts.
  - `crates/lsb-vm/src/lib.rs:3`

- `PlatformVmConfig`, `PlatformVm`, `copy_file_cow()`, and `create_vm()` are
  currently exported only for macOS.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/lib.rs:209`
  - `crates/lsb-platform/src/lib.rs:219`

- Node runtime support is currently gated to macOS x86_64 and Apple Silicon.
  - `bindings/nodejs/build.rs:1`
  - `bindings/nodejs/build.rs:7`

### Questions And Unknowns

- `stdio::handle_checkpoint()` does not appear to call
  `validate_checkpoint_name()` or reject existing names, unlike CLI create and
  SDK checkpoint.
  - `crates/lsb-cli/src/stdio.rs:976`

- The README says `await sb.checkpoint("after-run")` saves disk state and stops
  the VM, but SDK/Node checkpoint only saves; it does not stop the VM.
  - `README.md:177`
  - `crates/lsb-sdk/src/runtime.rs:714`
  - `crates/lsb-sdk/src/runtime.rs:735`

- Overwrite policy differs by surface. CLI create rejects existing checkpoints;
  SDK checkpoint can overwrite; stdio behavior depends on filesystem create/save
  behavior and lacks the explicit preflight.

- CAS indexes store parent/fallback paths as host strings. It is unclear whether
  these should be portable across machines, data dirs, or operating systems.

- The intended Windows VM backend is not selected. The storage answer depends on
  whether Windows uses Hyper-V/WHP, WSL2, QEMU, or another runtime.

- It is unclear whether Windows should keep NBD as the host block protocol or use
  a backend-native differencing disk while preserving `.idx` compatibility.

## `--allow-net` + Secrets Path

### Summary

`--allow-net` turns on a host-side transparent proxy and gives the guest a
Virtio network device backed by a host socketpair. Secrets are never injected as
real values into the VM. The guest receives random placeholder tokens as
environment variables, and the proxy substitutes those placeholders with real
secret values only for HTTPS connections whose TLS SNI matches the secret's host
allowlist.

Without `--allow-net`, no proxy config is built, no network fd is attached to
the VM, no proxy CA is installed, and secret placeholders are not injected.

### Ordered Call Graph

1. CLI argument parsing captures networking and secret flags.
   - `crates/lsb-cli/src/cli.rs:33`
   - `crates/lsb-cli/src/cli.rs:49`
   - `crates/lsb-cli/src/cli.rs:53`

2. `main()` loads `lsb.json`, prepares the VM, then chooses normal CLI,
   console, or stdio execution.
   - `crates/lsb-cli/src/main.rs:36`
   - `crates/lsb-cli/src/main.rs:47`
   - `crates/lsb-cli/src/main.rs:49`

3. `prepare_vm()` computes `allow_net` from CLI or config. It only builds
   `PreparedVm.proxy_config` when networking is enabled.
   - `crates/lsb-cli/src/vm.rs:37`
   - `crates/lsb-cli/src/vm.rs:41`
   - `crates/lsb-cli/src/vm.rs:45`

4. Config file secrets and network allow rules are converted into
   `lsb_proxy::config::ProxyConfig`.
   - `crates/lsb-cli/src/config.rs:39`
   - `crates/lsb-cli/src/config.rs:44`
   - `crates/lsb-cli/src/config.rs:56`

5. CLI `--secret` flags are parsed as `NAME=VALUE@host1,host2` and merged into
   the proxy config.
   - `crates/lsb-cli/src/vm.rs:48`
   - `crates/lsb-cli/src/vm.rs:56`
   - `crates/lsb-cli/src/vm.rs:459`

6. Normal CLI execution creates a Unix datagram socketpair, starts `lsb-proxy`
   on the host end, and passes the VM end into the VM builder.
   - `crates/lsb-cli/src/vm.rs:291`
   - `crates/lsb-cli/src/vm.rs:293`
   - `crates/lsb-cli/src/vm.rs:294`
   - `crates/lsb-cli/src/vm.rs:308`

7. Stdio mode follows the same proxy setup and keeps a `secret_env` map for
   later JSON-RPC `exec` and `spawn` requests.
   - `crates/lsb-cli/src/stdio.rs:314`
   - `crates/lsb-cli/src/stdio.rs:317`
   - `crates/lsb-cli/src/stdio.rs:338`
   - `crates/lsb-cli/src/stdio.rs:463`
   - `crates/lsb-cli/src/stdio.rs:490`

8. The Rust SDK path builds `ProxyConfig` from `SandboxConfig` when
   `config.allow_net` is true. Node sets `allow_net` by providing a `network`
   option.
   - `crates/lsb-sdk/src/runtime.rs:527`
   - `crates/lsb-sdk/src/runtime.rs:529`
   - `crates/lsb-sdk/src/runtime.rs:533`
   - `bindings/nodejs/src/config.rs:67`

9. `Sandbox::builder().network_fd(fd)` carries the network fd into
   `PlatformVmConfig`.
   - `crates/lsb-cli/src/vm.rs:206`
   - `crates/lsb-cli/src/vm.rs:220`
   - `crates/lsb-vm/src/sandbox.rs:108`
   - `crates/lsb-vm/src/sandbox.rs:125`
   - `crates/lsb-vm/src/sandbox.rs:141`

10. The macOS platform backend attaches the fd as a Virtio network device using
    `VZFileHandleNetworkDeviceAttachment`.
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:155`
    - `crates/lsb-platform/src/macos_aarch64/network.rs:20`
    - `crates/lsb-platform/src/macos_x86_64/mod.rs:155`
    - `crates/lsb-platform/src/macos_x86_64/network.rs:20`

11. The proxy creates placeholders and starts two threads: a smoltcp network
    stack thread and an async proxy engine thread.
    - `crates/lsb-proxy/src/lib.rs:43`
    - `crates/lsb-proxy/src/lib.rs:84`
    - `crates/lsb-proxy/src/lib.rs:91`
    - `crates/lsb-proxy/src/lib.rs:100`
    - `crates/lsb-proxy/src/lib.rs:109`

12. When placeholders exist, the host writes the generated proxy CA certificate
    into the guest trust store and runs `update-ca-certificates`.
    - `crates/lsb-cli/src/vm.rs:324`
    - `crates/lsb-cli/src/vm.rs:328`
    - `crates/lsb-cli/src/vm.rs:332`
    - `crates/lsb-cli/src/stdio.rs:337`
    - `crates/lsb-sdk/src/runtime.rs:589`

13. Command execution sends placeholder env values through the vsock
    `ExecRequest`. The guest sets those env vars before spawning the process.
    - `crates/lsb-vm/src/sandbox.rs:262`
    - `crates/lsb-vm/src/sandbox.rs:275`
    - `crates/lsb-vm/src/sandbox.rs:518`
    - `crates/lsb-guest/src/main.rs:735`
    - `crates/lsb-guest/src/main.rs:739`
    - `crates/lsb-guest/src/main.rs:1067`

14. Initramfs configures proxy-backed IPv4 networking when `eth0` exists:
    guest `10.0.0.2`, gateway `10.0.0.1`, DNS `10.0.0.1`.
    - `xtask/src/rootfs.rs:51`
    - `xtask/src/rootfs.rs:52`
    - `xtask/src/rootfs.rs:53`
    - `xtask/src/rootfs.rs:54`
    - `crates/lsb-guest/src/main.rs:190`

15. DNS queries go to the proxy, which resolves on the host and applies the
    configured domain allowlist.
    - `crates/lsb-proxy/src/stack.rs:106`
    - `crates/lsb-proxy/src/stack.rs:371`
    - `crates/lsb-proxy/src/dns.rs:11`
    - `crates/lsb-proxy/src/dns.rs:40`
    - `crates/lsb-proxy/src/dns.rs:113`

16. TCP connections are accepted by the smoltcp stack and dispatched to
    `ProxyEngine`.
    - `crates/lsb-proxy/src/stack.rs:204`
    - `crates/lsb-proxy/src/stack.rs:303`
    - `crates/lsb-proxy/src/stack.rs:335`
    - `crates/lsb-proxy/src/proxy.rs:60`
    - `crates/lsb-proxy/src/proxy.rs:89`

17. For TCP port 443, the proxy buffers ClientHello, extracts SNI, and asks
    `ProxyConfig::secrets_for_domain()` for placeholder-to-real substitutions.
    If none match, the connection is blind-tunneled.
    - `crates/lsb-proxy/src/proxy.rs:146`
    - `crates/lsb-proxy/src/proxy.rs:149`
    - `crates/lsb-proxy/src/proxy.rs:169`
    - `crates/lsb-proxy/src/proxy.rs:172`
    - `crates/lsb-proxy/src/config.rs:68`

18. When substitutions match, the proxy MITMs TLS with a generated cert,
    connects upstream with BoringSSL, and replaces placeholders in guest-to-host
    bytes before sending upstream.
    - `crates/lsb-proxy/src/proxy.rs:256`
    - `crates/lsb-proxy/src/proxy.rs:268`
    - `crates/lsb-proxy/src/proxy.rs:278`
    - `crates/lsb-proxy/src/proxy.rs:281`
    - `crates/lsb-proxy/src/proxy.rs:296`
    - `crates/lsb-proxy/src/proxy.rs:297`

### Important Structs and Enums

- `VmArgs`: CLI surface for `allow_net`, `secret`, `allow_host`, and
  `expose_host`.
  - `crates/lsb-cli/src/cli.rs:3`

- `LsbConfig`, `SecretEntry`, `NetworkEntry`: config-file representation of
  network and secret policy.
  - `crates/lsb-cli/src/config.rs:6`
  - `crates/lsb-cli/src/config.rs:21`
  - `crates/lsb-cli/src/config.rs:32`

- `PreparedVm`: carries optional `proxy_config` plus runtime VM configuration.
  - `crates/lsb-cli/src/vm.rs:15`

- `SandboxConfig`: SDK-level network, secret, and host exposure config.
  - `crates/lsb-sdk/src/types.rs:7`

- `ProxyConfig`, `SecretConfig`, `NetworkConfig`, `ExposeHostMapping`: proxy
  policy and secret material. Secret values live here on the host.
  - `crates/lsb-proxy/src/config.rs:4`
  - `crates/lsb-proxy/src/config.rs:11`
  - `crates/lsb-proxy/src/config.rs:24`
  - `crates/lsb-proxy/src/config.rs:34`

- `ProxyHandle`: owns proxy threads, generated placeholder env values, and the
  generated CA certificate bytes.
  - `crates/lsb-proxy/src/lib.rs:20`

- `VZDevice`, `NetworkStack`, `StackEvent`, `StackCommand`: raw frame device,
  smoltcp stack, and stack/proxy command channel.
  - `crates/lsb-proxy/src/device.rs:15`
  - `crates/lsb-proxy/src/stack.rs:37`
  - `crates/lsb-proxy/src/stack.rs:49`
  - `crates/lsb-proxy/src/stack.rs:63`

- `ProxyEngine`: async TCP/DNS handling and TLS MITM decision point.
  - `crates/lsb-proxy/src/proxy.rs:25`

- `CertificateAuthority`: generated root CA and per-domain server cert cache.
  - `crates/lsb-proxy/src/tls.rs:12`

- `ExecRequest`: host-to-guest process request carrying placeholder env values.
  - `crates/lsb-proto/src/lib.rs:13`

### Host/Guest Boundary Points

- Raw network boundary: host creates a socketpair; the VM side becomes the guest
  Virtio NIC and the host side becomes `VZDevice`.
  - `crates/lsb-proxy/src/lib.rs:43`
  - `crates/lsb-proxy/src/device.rs:10`

- VM configuration boundary: `network_fd` crosses from CLI/SDK into
  `PlatformVmConfig` and then the platform backend.
  - `crates/lsb-vm/src/sandbox.rs:141`
  - `crates/lsb-platform/src/lib.rs:186`

- DNS boundary: guest sends UDP DNS to `10.0.0.1`; proxy resolves through the
  host system resolver and returns an IPv4 response.
  - `xtask/src/rootfs.rs:54`
  - `crates/lsb-proxy/src/dns.rs:40`
  - `crates/lsb-proxy/src/dns.rs:126`

- Exec boundary: placeholder env values cross over vsock in `ExecRequest`; real
  secret values do not.
  - `crates/lsb-vm/src/sandbox.rs:275`
  - `crates/lsb-guest/src/main.rs:739`

- Trust boundary: host installs the generated proxy CA into the guest only when
  MITM can be needed, which is currently represented by non-empty placeholders.
  - `crates/lsb-cli/src/vm.rs:327`
  - `crates/lsb-sdk/src/runtime.rs:590`

- TLS boundary: guest TLS is terminated only on matching secret host SNI; the
  upstream TLS connection is separate and uses BoringSSL.
  - `crates/lsb-proxy/src/proxy.rs:172`
  - `crates/lsb-proxy/src/proxy.rs:278`
  - `crates/lsb-proxy/src/proxy.rs:281`

### Windows Support Invariants

- `allow_net = false` must continue to mean no guest network device, no proxy,
  no proxy CA installation, and no secret placeholder env injection.

- Real secret values must remain host-side. The guest can receive only generated
  placeholders through env.

- Placeholder env injection must be consistent across normal CLI exec, TTY
  shell, stdio `exec`, stdio `spawn`, Rust SDK `exec`/`spawn`/shell, and Node
  `Sandbox.start`.

- The proxy must outlive all guest network traffic that depends on it.

- Guest networking must remain proxy-backed: `eth0`, guest address
  `10.0.0.2/24`, gateway `10.0.0.1`, and resolver `10.0.0.1`.

- Host DNS resolution must continue to use the host resolver so VPN and
  split-DNS behavior is preserved.

- Network allow rules must continue to block DNS for disallowed domains.

- MITM must remain limited to TLS port 443 connections whose SNI matches at
  least one secret host pattern. Non-matching TLS and non-TLS TCP must remain
  blind relays.

- Host exposure through `host.lsb.internal` must continue to resolve to
  `10.0.0.1` and map only configured guest ports to host localhost ports.

- The current implementation exposes Unix `RawFd`, `AF_UNIX` socketpair, and
  Apple `VZFileHandleNetworkDeviceAttachment` assumptions. Windows support must
  hide those behind a platform-neutral raw-frame attachment boundary.

- `lsb-vm` is currently compile-gated to macOS, and Windows platform specs are
  currently marked `Planned`.
  - `crates/lsb-vm/src/lib.rs:3`
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

### Questions and Unknowns

- Should `--secret` without `--allow-net` remain inert, or should the CLI reject
  it as a configuration error?

- What Windows backend will provide the raw Ethernet-frame attachment currently
  supplied by Apple Virtualization's file-handle network device?

- How should the host/guest vsock protocol be implemented on Windows while
  preserving `VSOCK_PORT` and the binary frame protocol?

- `allowed_hosts` is enforced in the DNS path. Direct IP TCP connections appear
  to bypass domain policy because `handle_connection()` receives only a
  destination socket address.

- Placeholder generation uses timestamp plus counter. If placeholders are a
  security boundary, this may need cryptographic randomness.

- `replace_bytes()` operates per decrypted read buffer. A placeholder split
  across adjacent TLS read chunks may not be substituted.

## Node `Sandbox.start` Path

### Summary

`Sandbox.start(opts)` is the Node.js entrypoint for booting a sandbox VM through
the Rust SDK. The N-API layer converts JavaScript options into
`lsb_sdk::SandboxConfig`, the SDK starts a dedicated VM owner thread, prepares
storage and optional networking, builds an `lsb_vm::Sandbox`, starts the
platform VM, and then returns an `AsyncSandbox` handle to JavaScript.

Today the Node runtime path is intentionally macOS-only. The package metadata,
build script, and native binding all restrict positive VM support to Darwin
arm64 and x64. Non-supported builds expose enough API shape to install and fail
with a clear unsupported-platform error.

One startup semantic matters for future platform work: plain
`Sandbox.start()` resolves after the hypervisor start and host-side setup, but
it does not always prove the guest control agent is accepting vsock
connections. Guest readiness is forced during startup only when startup needs a
guest operation, such as installing the proxy CA for secret placeholders. In
other cases, the first later sandbox operation performs the first control-vsock
connection attempt.

### Ordered Call Graph

1. JavaScript calls `Sandbox.start(opts)`, exported as an async N-API factory.
   - `bindings/nodejs/src/sandbox.rs:39`
   - `bindings/nodejs/src/sandbox.rs:40`

2. The build script enables `lsb_nodejs_supported` only for macOS on
   `aarch64` or `x86_64`.
   - `bindings/nodejs/build.rs:1`
   - `bindings/nodejs/build.rs:7`

3. Unsupported targets return `unsupported_platform_error()`.
   - `bindings/nodejs/src/sandbox.rs:52`
   - `bindings/nodejs/src/error.rs:5`

4. Supported targets call `build_sandbox_config(opts.unwrap_or_default())`.
   - `bindings/nodejs/src/sandbox.rs:43`
   - `bindings/nodejs/src/config.rs:42`

5. `build_sandbox_config()` starts from `lsb_sdk::SandboxConfig::default()` and
   maps Node-facing options into SDK fields.
   - `bindings/nodejs/src/config.rs:43`
   - `bindings/nodejs/src/config.rs:45`
   - `bindings/nodejs/src/config.rs:49`
   - `bindings/nodejs/src/types.rs:66`
   - `crates/lsb-sdk/src/types.rs:7`

6. Startup options are validated before VM boot.
   - Ports must fit in `u16`.
   - Mount guest paths must be absolute.
   - Mount host paths must exist and are canonicalized.
   - Overlay mounts reject direct flags.
   - Direct mounts require non-negative safe-integer flags.
   - Secrets require non-empty values and non-empty host allowlists.
   - `bindings/nodejs/src/config.rs:101`
   - `bindings/nodejs/src/config.rs:109`
   - `bindings/nodejs/src/config.rs:116`
   - `bindings/nodejs/src/config.rs:139`
   - `bindings/nodejs/src/config.rs:151`
   - `bindings/nodejs/src/config.rs:174`

7. The binding calls `lsb_sdk::AsyncSandbox::boot(config).await`.
   - `bindings/nodejs/src/sandbox.rs:44`
   - `crates/lsb-sdk/src/runtime.rs:109`

8. `AsyncSandbox::boot()` creates a readiness oneshot, a command channel, and a
   dedicated OS thread named `lsb-vm`.
   - `crates/lsb-sdk/src/runtime.rs:110`
   - `crates/lsb-sdk/src/runtime.rs:111`
   - `crates/lsb-sdk/src/runtime.rs:113`

9. The VM thread calls `boot_vm(config)`. On success it sends the instance dir
   back to the async caller, then enters `run_vm_loop()`.
   - `crates/lsb-sdk/src/runtime.rs:115`
   - `crates/lsb-sdk/src/runtime.rs:124`
   - `crates/lsb-sdk/src/runtime.rs:127`
   - `crates/lsb-sdk/src/runtime.rs:615`

10. `boot_vm()` resolves the data dir and runtime asset paths.
    - `crates/lsb-sdk/src/runtime.rs:443`
    - `crates/lsb-platform/src/lib.rs:135`
    - `crates/lsb-platform/src/lib.rs:154`

11. Startup validates required assets and rejects mutually exclusive
    checkpoint/base-version options.
    - `crates/lsb-sdk/src/runtime.rs:450`
    - `crates/lsb-sdk/src/runtime.rs:457`

12. Storage is prepared. Default storage uses CAS-backed NBD; setting
    `LSB_STORAGE=direct` uses direct rootfs copying.
    - `crates/lsb-sdk/src/runtime.rs:461`
    - `crates/lsb-sdk/src/runtime.rs:468`
    - `crates/lsb-sdk/src/storage.rs:46`
    - `crates/lsb-sdk/src/storage.rs:51`
    - `crates/lsb-sdk/src/storage.rs:61`

13. The SDK computes a per-sandbox instance directory. Explicit `instanceId`
    values are rejected if empty or path-like; otherwise the default is
    `{instances_dir}/sdk-{pid}-{counter}`.
    - `crates/lsb-sdk/src/runtime.rs:471`
    - `crates/lsb-sdk/src/runtime.rs:473`
    - `crates/lsb-sdk/src/runtime.rs:481`
    - `crates/lsb-sdk/src/runtime.rs:483`

14. The SDK removes any previous instance dir with that name, recreates it, and
    prepares `{instance_dir}/rootfs.ext4`.
    - Direct storage uses `lsb_platform::copy_file_cow()`.
    - NBD storage creates an empty placeholder file.
    - `crates/lsb-sdk/src/runtime.rs:493`
    - `crates/lsb-sdk/src/runtime.rs:495`
    - `crates/lsb-sdk/src/runtime.rs:497`
    - `crates/lsb-sdk/src/runtime.rs:499`

15. Disk size is validated against the selected base image or CAS logical size.
    Direct storage extends the working file when requested size is larger.
    - `crates/lsb-sdk/src/runtime.rs:502`
    - `crates/lsb-sdk/src/runtime.rs:509`
    - `crates/lsb-sdk/src/runtime.rs:516`

16. Optional initramfs is included if the initialized asset exists.
    - `crates/lsb-sdk/src/runtime.rs:521`

17. If Node supplied `network`, `build_sandbox_config()` sets `allow_net = true`.
    The SDK creates `ProxyConfig`, a Unix socketpair, and starts `lsb-proxy`.
    - `bindings/nodejs/src/config.rs:67`
    - `crates/lsb-sdk/src/runtime.rs:527`
    - `crates/lsb-sdk/src/runtime.rs:528`
    - `crates/lsb-proxy/src/lib.rs:43`
    - `crates/lsb-proxy/src/lib.rs:84`

18. If CAS/NBD storage is active, the SDK starts a host NBD server and captures
    its URI for the VM block device.
    - `crates/lsb-sdk/src/runtime.rs:540`
    - `crates/lsb-store/src/lib.rs:106`
    - `crates/lsb-store/src/lib.rs:28`

19. The SDK configures `lsb_vm::Sandbox::builder()` with kernel, rootfs, cpus,
    memory, console mode, optional network fd, optional NBD URI, optional initrd,
    and requested mounts.
    - `crates/lsb-sdk/src/runtime.rs:554`
    - `crates/lsb-sdk/src/runtime.rs:561`
    - `crates/lsb-sdk/src/runtime.rs:564`
    - `crates/lsb-sdk/src/runtime.rs:567`
    - `crates/lsb-sdk/src/runtime.rs:570`

20. `VmConfigBuilder::build()` converts VM memory to bytes and splits mount
    config into platform shared directories plus pending guest mount requests.
    - `crates/lsb-vm/src/sandbox.rs:125`
    - `crates/lsb-vm/src/sandbox.rs:129`
    - `crates/lsb-vm/src/sandbox.rs:130`
    - `crates/lsb-vm/src/sandbox.rs:157`

21. `lsb_platform::create_vm(PlatformVmConfig { ... })` builds the platform VM.
    - `crates/lsb-vm/src/sandbox.rs:132`
    - `crates/lsb-vm/src/sandbox.rs:133`
    - `crates/lsb-platform/src/lib.rs:219`

22. The macOS backend validates Virtualization.framework support and builds the
    VM configuration.
    - Linux bootloader with kernel/initrd and command line.
    - Serial console attachment.
    - Virtio block device from disk image or NBD.
    - Optional file-handle Virtio network device.
    - Optional VirtioFS directory sharing devices.
    - Virtio socket device.
    - Entropy and memory balloon devices.
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:107`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:112`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:117`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:127`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:139`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:155`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:162`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:171`
    - `crates/lsb-platform/src/macos_aarch64/mod.rs:174`

23. `sandbox.start()` delegates to `PlatformVm::start()`.
    - `crates/lsb-sdk/src/runtime.rs:581`
    - `crates/lsb-vm/src/sandbox.rs:205`
    - `crates/lsb-platform/src/lib.rs:201`

24. The macOS backend calls `VZVirtualMachine.startWithCompletionHandler()` on
    its serial dispatch queue and waits for the completion result.
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:160`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:165`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:177`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:182`
    - `crates/lsb-platform/src/macos_aarch64/vm.rs:184`

25. If Node supplied host-to-guest port forwards, the SDK starts host
    `127.0.0.1:{host}` listeners after VM start.
    - `crates/lsb-sdk/src/runtime.rs:583`
    - `crates/lsb-vm/src/sandbox.rs:694`
    - `crates/lsb-vm/src/sandbox.rs:699`

26. If proxy secret placeholders exist, the SDK writes the generated CA
    certificate into the guest and runs `update-ca-certificates`. This path
    requires the first control-vsock connection during startup.
    - `crates/lsb-sdk/src/runtime.rs:589`
    - `crates/lsb-sdk/src/runtime.rs:591`
    - `crates/lsb-sdk/src/runtime.rs:595`
    - `crates/lsb-vm/src/sandbox.rs:313`
    - `crates/lsb-vm/src/sandbox.rs:751`

27. `boot_vm()` returns the sandbox and host-side handles. The Node-visible
    `AsyncSandbox` stores the command sender and instance dir.
    - `crates/lsb-sdk/src/runtime.rs:603`
    - `crates/lsb-sdk/src/runtime.rs:605`
    - `crates/lsb-sdk/src/runtime.rs:142`
    - `crates/lsb-sdk/src/runtime.rs:144`
    - `bindings/nodejs/src/sandbox.rs:47`

28. `run_vm_loop()` owns the VM and handles all later Node operations by sending
    commands over the SDK channel. On `Stop`, it calls `sandbox.stop()` and exits.
    - `crates/lsb-sdk/src/runtime.rs:631`
    - `crates/lsb-sdk/src/runtime.rs:735`
    - `crates/lsb-sdk/src/runtime.rs:742`

29. Dropping `AsyncSandbox` sends `Stop` and removes the instance directory.
    - `crates/lsb-sdk/src/runtime.rs:425`
    - `crates/lsb-sdk/src/runtime.rs:427`
    - `crates/lsb-sdk/src/runtime.rs:429`

### Important Structs and Enums

- `Sandbox`
  - Public Node class. Supported builds store `Arc<lsb_sdk::AsyncSandbox>`.
  - `bindings/nodejs/src/sandbox.rs:28`

- `StartOptions`
  - Node-facing startup object: `instanceId`, `from`, `cpus`, `memoryMb`,
    `diskSizeMb`, `dataDir`, `baseVersion`, `ports`, `mounts`, and `network`.
  - `bindings/nodejs/src/types.rs:66`

- `MountConfig`, `NetworkConfig`, `PortMappingConfig`, `ExposeHostConfig`,
  `SecretConfig`
  - Node-facing configuration shapes that are parsed into SDK and proxy types.
  - `bindings/nodejs/src/types.rs:7`
  - `bindings/nodejs/src/types.rs:17`
  - `bindings/nodejs/src/types.rs:27`
  - `bindings/nodejs/src/types.rs:39`
  - `bindings/nodejs/src/types.rs:49`

- `SandboxConfig`
  - SDK-level boot config. Carries runtime asset location, VM resources, mounts,
    network policy, port forwards, checkpoint/base selection, and instance ID.
  - `crates/lsb-sdk/src/types.rs:7`

- `AsyncSandbox`
  - Async SDK wrapper around a VM owner thread. Node methods enqueue
    `SandboxCmd` values to this thread.
  - `crates/lsb-sdk/src/runtime.rs:97`

- `SandboxCmd`
  - Internal SDK command enum for exec, filesystem operations, streaming process
    opens, watch opens, shell opens, checkpoint, and stop.
  - `crates/lsb-sdk/src/runtime.rs:22`

- `StoragePrepareOptions`, `PreparedStorage`, `NbdSource`
  - Storage resolution and selected direct or CAS/NBD source.
  - `crates/lsb-sdk/src/storage.rs:3`
  - `crates/lsb-sdk/src/storage.rs:14`
  - `crates/lsb-sdk/src/storage.rs:40`

- `NbdHandle`
  - Host NBD server lifetime handle. Produces the NBD URI and can save CAS
    checkpoints.
  - `crates/lsb-store/src/lib.rs:21`

- `lsb_vm::MountConfig`, `VmConfigBuilder`, `Sandbox`
  - VM-layer builder and high-level host VM API.
  - `crates/lsb-vm/src/sandbox.rs:24`
  - `crates/lsb-vm/src/sandbox.rs:39`
  - `crates/lsb-vm/src/sandbox.rs:152`

- `PlatformSpec`, `PlatformStatus`, `PlatformVmConfig`, `PlatformVm`,
  `PlatformSharedDir`
  - Platform metadata and runtime backend contract.
  - `crates/lsb-platform/src/lib.rs:17`
  - `crates/lsb-platform/src/lib.rs:143`
  - `crates/lsb-platform/src/lib.rs:178`
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`

- `MountRequest`, `MountResponse`, `ExecRequest`, `PortMapping`,
  `ForwardRequest`, `ForwardResponse`
  - Host/guest protocol payloads for mounts, commands, and port forwarding.
  - `crates/lsb-proto/src/lib.rs:13`
  - `crates/lsb-proto/src/lib.rs:30`
  - `crates/lsb-proto/src/lib.rs:37`
  - `crates/lsb-proto/src/lib.rs:51`

- `VSOCK_PORT`, `VSOCK_PORT_FORWARD`
  - Guest control and port-forward listener ports: `1024` and `1025`.
  - `crates/lsb-proto/src/lib.rs:192`

### Host/Guest Boundary Points

- Hypervisor lifecycle boundary:
  - Host calls `PlatformVm::start()`, which maps to Apple
    Virtualization.framework on macOS.
  - `crates/lsb-vm/src/sandbox.rs:205`
  - `crates/lsb-platform/src/macos_aarch64/vm.rs:160`

- VM device boundary:
  - Kernel, initramfs, root block device, optional network fd, optional VirtioFS
    directories, and virtio socket device cross from host config into the VM.
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:112`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:139`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:155`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:162`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:171`

- Block device boundary:
  - Direct mode attaches a writable disk image. Default mode starts a host NBD
    server and attaches an NBD block device over a Unix socket URI.
  - `crates/lsb-platform/src/macos_aarch64/storage.rs:73`
  - `crates/lsb-platform/src/macos_aarch64/storage.rs:101`
  - `crates/lsb-store/src/lib.rs:28`
  - `crates/lsb-store/src/nbd.rs:76`

- Network boundary:
  - With networking enabled, host creates a Unix datagram socketpair. The VM end
    is passed to Virtualization.framework, while the host end is consumed by the
    proxy network stack.
  - `crates/lsb-proxy/src/lib.rs:43`
  - `crates/lsb-proxy/src/lib.rs:80`
  - `crates/lsb-platform/src/macos_aarch64/network.rs:20`

- VirtioFS mount boundary:
  - Host mount config becomes platform shared dirs tagged `mount0`, `mount1`,
    and so on. The guest later receives `MOUNT_REQ` over control vsock and
    mounts the tag as overlay or direct VirtioFS.
  - `crates/lsb-vm/src/sandbox.rs:157`
  - `crates/lsb-vm/src/sandbox.rs:219`
  - `crates/lsb-guest/src/main.rs:72`
  - `crates/lsb-guest/src/main.rs:112`
  - `crates/lsb-guest/src/main.rs:148`

- Control vsock boundary:
  - Host connects to guest vsock port `1024`. Guest PID 1 binds AF_VSOCK,
    accepts connections, decodes binary frames, and dispatches request types.
  - `crates/lsb-vm/src/sandbox.rs:751`
  - `crates/lsb-vm/src/sandbox.rs:764`
  - `crates/lsb-guest/src/main.rs:251`
  - `crates/lsb-guest/src/main.rs:337`
  - `crates/lsb-guest/src/main.rs:1378`

- Port-forward vsock boundary:
  - Host local TCP listeners relay through guest vsock port `1025`; the guest
    connects to `127.0.0.1:{guest_port}` inside the VM.
  - `crates/lsb-vm/src/sandbox.rs:694`
  - `crates/lsb-vm/src/sandbox.rs:804`
  - `crates/lsb-guest/src/main.rs:1254`
  - `crates/lsb-guest/src/main.rs:1269`

- Protocol framing boundary:
  - All control traffic uses `[u32 BE length][u8 type][payload...]`, with a 1 MiB
    max frame size.
  - `crates/lsb-proto/src/frame.rs:48`
  - `crates/lsb-proto/src/frame.rs:55`
  - `crates/lsb-proto/src/frame.rs:67`

### Files and Line References

- Node public API and startup entry:
  - `bindings/nodejs/src/sandbox.rs:39`
  - `bindings/nodejs/src/types.rs:66`
  - `bindings/nodejs/src/config.rs:42`

- Node platform gating and package support:
  - `bindings/nodejs/build.rs:7`
  - `bindings/nodejs/src/error.rs:5`
  - `bindings/nodejs/package.json:8`
  - `bindings/nodejs/package.json:36`
  - `bindings/nodejs/README.md:26`
  - `bindings/nodejs/README.md:253`

- SDK boot and VM owner thread:
  - `crates/lsb-sdk/src/runtime.rs:109`
  - `crates/lsb-sdk/src/runtime.rs:433`
  - `crates/lsb-sdk/src/runtime.rs:615`
  - `crates/lsb-sdk/src/types.rs:7`

- Storage:
  - `crates/lsb-sdk/src/storage.rs:46`
  - `crates/lsb-store/src/lib.rs:106`
  - `crates/lsb-store/src/nbd.rs:76`

- VM layer:
  - `crates/lsb-vm/src/lib.rs:3`
  - `crates/lsb-vm/src/sandbox.rs:125`
  - `crates/lsb-vm/src/sandbox.rs:205`
  - `crates/lsb-vm/src/sandbox.rs:751`

- Platform layer:
  - `crates/lsb-platform/src/lib.rs:17`
  - `crates/lsb-platform/src/lib.rs:186`
  - `crates/lsb-platform/src/lib.rs:201`
  - `crates/lsb-platform/src/macos_aarch64/mod.rs:107`
  - `crates/lsb-platform/src/macos_x86_64/mod.rs:107`
  - `crates/lsb-platform/src/windows_x86_64/mod.rs:3`
  - `crates/lsb-platform/src/windows_aarch64/mod.rs:3`

- Host/guest protocol and guest agent:
  - `crates/lsb-proto/src/lib.rs:13`
  - `crates/lsb-proto/src/lib.rs:192`
  - `crates/lsb-proto/src/frame.rs:48`
  - `crates/lsb-guest/src/main.rs:251`
  - `crates/lsb-guest/src/main.rs:330`
  - `crates/lsb-guest/src/main.rs:1347`
  - `crates/lsb-guest/src/main.rs:1378`

### Contracts and Invariants

- `Sandbox.start()` must keep JavaScript option validation before boot for
  errors that can be found without starting a VM.

- `StartOptions.from` and `StartOptions.baseVersion` remain mutually exclusive
  through the SDK storage path.

- Runtime assets are not downloaded implicitly by `Sandbox.start()`. Assets must
  already exist through `initSandbox()` or `lsb init`.

- `instanceId` must not allow filesystem traversal or path separators.

- Each sandbox receives an isolated instance directory and working rootfs. Drop
  and explicit stop both attempt cleanup.

- Disk size cannot be smaller than the selected source image or CAS logical
  size.

- Default storage mode is CAS/NBD unless `LSB_STORAGE=direct` is set.

- Mount order determines generated tags. Tags are internal and are not supplied
  by JavaScript callers.

- Overlay mount semantics are read-only host lowerdir plus guest tmpfs upperdir.
  Direct mount semantics preserve caller-supplied mount flags.

- `allow_net = false` means no network fd, no proxy, no proxy CA installation,
  and no secret placeholder env injection.

- Real secret values remain host-side. Guest commands receive only generated
  placeholder env values.

- The SDK VM owner thread serializes operations because current macOS
  Virtualization.framework objects are not freely Send/Sync across async tasks.

- The public `AsyncSandbox` object must not expose platform VM objects directly
  to Node.

- Guest control protocol uses vsock port `1024`; port forwarding uses vsock port
  `1025`.

- Binary frame format, message type constants, JSON payload shapes, and
  big-endian numeric payloads are cross-layer contracts.

- Startup success currently means "VM start plus host-side setup completed", not
  necessarily "guest control agent definitely accepted a connection" for every
  option combination.

### Windows Support Invariants

Windows support for `Sandbox.start()` must preserve:

- The same Node API shape and error behavior where possible, including
  pre-start validation for ports, mounts, secrets, and unsupported options.

- Runtime asset expectations: kernel, rootfs, initramfs, checkpoints, instances,
  and base-version metadata remain discoverable from a data dir.

- Correct Windows default data-dir resolution. Current platform metadata says
  `AppData/Local/lsb`, while `default_data_dir()` currently uses `HOME` plus the
  platform subdir.

- Per-instance disk isolation and cleanup, including stable `instanceId`
  validation that rejects `/`, `\`, NUL, and `..`.

- Storage behavior equivalent to direct rootfs copy or Windows qcow2 checkpoint
  artifacts: consistent logical size, durable flush, and no shrink below source
  size. CAS/NBD checkpoints remain macOS-only.

- A copy-on-write or equivalent copy primitive for direct mode. macOS uses APFS
  `clonefile`; Windows must provide an equivalent correctness story even if the
  implementation falls back to a full copy.

- A platform VM backend implementing the current lifecycle and connection
  contract: start, stop, state channel, and guest control stream connection.

- A vsock-like bidirectional byte stream for control and port-forward channels,
  or a deliberately abstracted transport that preserves the same protocol
  semantics.

- Equivalent product semantics for directory mounts: Windows no-suffix and
  CLI `:ro` mounts are snapshot imports with isolated guest writes, while
  explicit direct mounts use SMB/CIFS with flags `0` for read-write and
  `MS_RDONLY` for read-only.

- Equivalent guest networking security model: no network device when disabled;
  proxy-backed networking when enabled; real secrets never enter the guest.

- Host port forwarding semantics: host loopback listener to guest loopback port
  through the guest forwarding agent.

- Node async behavior: `Sandbox.start()` must not block the Node event loop while
  VM work proceeds.

- Platform support indicators must be updated consistently. Windows x64 uses
  QEMU/WHPX and has a Node platform package; Windows ARM64 remains planned.

### Questions and Unknowns

- Which Windows backend should provide `PlatformVm`: resolved for Windows x64
  as QEMU with WHPX.

- Does the selected Windows backend provide virtio-vsock, VirtioFS, NBD, and
  raw-frame networking equivalents, or does `PlatformVm` need a more abstract
  transport/storage/directory-sharing interface? Current Windows x64 uses
  virtio-serial for control/forwarding, qcow2 checkpoint artifacts instead of
  NBD/CAS, snapshot imports for overlay mounts, SMB/CIFS for direct mounts, and
  proxy-owned networking.

- Should `Sandbox.start()` be changed to always wait for guest-agent readiness
  on every platform and option combination?

- What should replace Unix-domain NBD sockets on Windows: resolved for the
  current backend as qcow2 checkpoint artifacts. CAS/NBD remains future work.

- Should direct mount `flags: number` remain part of the stable Node API for
  Windows, or should the public API become a portable mount-mode enum? Current
  behavior preserves the stable API: `flags: 0` maps to read-write SMB/CIFS and
  `flags: MS_RDONLY` maps to read-only SMB/CIFS.

- How should Windows host paths be represented in persisted CAS index fallback
  paths and in mount configuration without breaking current path validation?

- Should the Node package continue to omit Windows npm targets until runtime
  support is complete, or publish unsupported Windows artifacts that fail at
  runtime like other unsupported builds? Resolved for Windows x64 by publishing
  the `win32-x64-msvc` platform package.
