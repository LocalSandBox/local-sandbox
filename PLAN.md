# Windows Direct Directory Mounts over SMB/CIFS

This plan is for a future implementation agent adding Windows direct directory
mounts to LocalSandbox. It is intentionally implementation-oriented, but it does
not contain code.

## Maintainer Decisions

- Windows direct directory mounts use SMB/CIFS.
- Preserve macOS-like direct mount semantics, including writable `:rw`.
- The CLI must run as Administrator for Windows SMB direct mounts.
- Use the existing LocalSandbox controlled proxy path.
- Do not use QEMU user networking, `hostfwd`, TAP, bridge, NAT, or public
  listener paths.
- LocalSandbox creates ephemeral Windows SMB shares.
- LocalSandbox creates ephemeral Windows users and generated SMB credentials.
- Recursive validation for direct mounts is required.
- Keep CLI `:ro` as overlay, not direct read-only.
- Do not enable SMB encryption by default.
- Use one ephemeral Windows user per sandbox.
- Update both kernel configs for CIFS support.

## Goals

1. Make `MountConfig::Direct { flags: 0 }` work on Windows as a live writable
   SMB/CIFS mount.
2. Preserve existing overlay behavior on Windows.
3. Preserve public CLI, SDK, and Node API shape unless a later review explicitly
   approves a public change.
4. Keep Windows backend as QEMU plus WHPX.
5. Keep Windows default networking disabled when no direct SMB mount or explicit
   network access is requested.
6. When networking is needed only for SMB mounts, attach only a mount-local proxy
   mode that does not imply arbitrary outbound `allow_net`.
7. Ensure generated credentials never appear in guest environment, diagnostics,
   logs, QEMU argv, error messages, snapshots, or test artifacts.
8. Clean up ephemeral users, shares, and ACL changes on normal stop and
   best-effort after failures.

## Non-Goals

- Do not implement QEMU 9p, VirtioFS, QEMU user-mode SMB, `hostfwd`, TAP,
  bridge, or NAT for this feature.
- Do not expose a new CLI direct-read-only syntax in the first implementation.
- Do not make SMB mounts imply general outbound network access.
- Do not support direct mounts with arbitrary Linux mount flags.
- Do not support reparse points, symlinks, junctions, hardlinks, or
  case-insensitive path collisions inside direct mount roots in v1.

## Current Repo Context

Read these files before implementing:

- `AGENTS.md`
- `docs/windows-port/AGENTS.md`
- `docs/windows-port/README.md`
- `docs/windows-port/mvp-handoff.md`
- `docs/windows-port/decisions.md`
- `docs/windows-port/architecture.md`
- `docs/windows-port/security-checklist.md`
- `docs/windows-port/future-work.md`

Key existing behavior:

- `crates/lsb-vm/src/sandbox.rs` defines `MountConfig::Overlay` and
  `MountConfig::Direct { flags }`.
- Non-Windows direct mounts currently map to VirtioFS shared dirs and
  `MountRequest::Direct`.
- Windows mount planning currently rejects direct mounts in
  `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`.
- Windows overlay mounts are staged copy imports into the guest and then mounted
  as guest overlayfs. Preserve that behavior.
- Windows QEMU currently defaults to `-nic none`.
- Windows network attachment currently uses QEMU `-netdev stream` to connect to
  the LocalSandbox proxy on host loopback.
- `lsb-proxy` already models the guest gateway as `10.0.0.1`, maps
  `host.lsb.internal` to that address, and supports host loopback exposure.
- `crates/lsb-guest/src/main.rs` currently treats direct mounts as VirtioFS.
- Both kernel configs currently have CIFS disabled.
- `xtask/src/rootfs.rs` does not currently include `cifs-utils`.

## Upstream References

Primary sources to consult while implementing:

- Microsoft `New-SmbShare`:
  https://learn.microsoft.com/en-us/powershell/module/smbshare/new-smbshare
- Microsoft `Remove-SmbShare`:
  https://learn.microsoft.com/en-us/powershell/module/smbshare/remove-smbshare
- Microsoft `Grant-SmbShareAccess`:
  https://learn.microsoft.com/en-us/powershell/module/smbshare/grant-smbshareaccess
- Microsoft `Revoke-SmbShareAccess`:
  https://learn.microsoft.com/en-us/powershell/module/smbshare/revoke-smbshareaccess
- Microsoft SMB direct hosting over TCP port 445:
  https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip
- Microsoft SMB firewall ports:
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/best-practices-analyzer/smb-open-file-sharing-ports
- Microsoft `NetShareAdd`, `NetShareDel`, share functions, and
  `SHARE_INFO_502`:
  https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd
  https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsharedel
  https://learn.microsoft.com/en-us/windows/win32/netmgmt/share-functions
- Microsoft `NetUserAdd`, `NetUserDel`, and local user constraints:
  https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
  https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserdel
- Microsoft admin-token check:
  https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
- Microsoft ACL APIs:
  https://learn.microsoft.com/en-us/windows/win32/secauthz/creating-or-modifying-an-acl
- Linux kernel CIFS docs:
  https://www.kernel.org/doc/html/latest/admin-guide/cifs/index.html
- Debian `mount.cifs` manpage:
  https://manpages.debian.org/testing/cifs-utils/mount.cifs.8.en.html
- Debian package content for `/sbin/mount.cifs`:
  https://packages.debian.org/file:mount.cifs
- QEMU invocation docs:
  https://qemu-project.gitlab.io/qemu/system/invocation.html

## Mount Semantics

| Public input | Windows behavior | Host changes visible in guest | Guest changes visible on host | Notes |
| --- | --- | --- | --- | --- |
| CLI no suffix | Overlay copy import | No live sync | No | Preserve existing behavior. |
| CLI `:ro` | Overlay copy import | No live sync | No | Maintainer decision: keep `:ro` as overlay. |
| CLI `:rw` plus `--allow-host-writes` | SMB/CIFS direct rw | Yes | Yes | Requires Administrator. |
| SDK/Node `Direct { flags: 0 }` | SMB/CIFS direct rw | Yes | Yes | Requires Administrator. |
| SDK/Node `Direct { flags: MS_RDONLY }` | SMB/CIFS direct ro | Yes | No | Public API can express this already. |
| SDK/Node `Direct` with any other flags | Reject | No | No | Do not silently ignore flags. |
| `Overlay` | Existing Windows copy import | No live sync | No | No SMB resources needed. |

Only these Windows direct flags are supported:

- `0`: read-write SMB direct mount.
- `MS_RDONLY`: read-only SMB direct mount.

Reject all other flags, including `MS_NOSUID`, `MS_NODEV`, `MS_NOEXEC`,
`MS_SYNCHRONOUS`, bind/remount flags, and combinations beyond exactly
`MS_RDONLY`.

## System Architecture

```text
CLI / SDK / Node
  -> parse MountConfig
  -> detect Windows direct mounts
  -> start lsb-proxy in MountOnlySmb mode if allow_net is false
  -> build Sandbox
  -> Windows mount planner creates overlay imports plus SMB direct specs
  -> Windows SMB lifecycle manager creates host user/share/ACL resources
  -> QEMU starts with stream netdev to lsb-proxy
  -> lsb-vm sends MountRequest::Smb over guest control channel
  -> lsb-guest invokes mount.cifs
  -> guest accesses host path via //<host-computer-name>/<share>
     with CIFS ip=10.0.0.1 for proxy transport
```

```text
Guest TCP 10.0.0.1:445
  -> virtio-net
  -> QEMU -netdev stream to 127.0.0.1:<proxy-port>
  -> lsb-proxy MountOnlySmb policy
  -> host 127.0.0.1:445
  -> Windows SMB server
  -> temporary SMB share
  -> validated host directory
```

## Crate and Module Plan

### `crates/lsb-cli/src/vm.rs`

- Preserve current mount syntax:
  - no suffix or `:ro` maps to `Overlay`.
  - `:rw` maps to `Direct { flags: 0 }`.
- Preserve the existing `--allow-host-writes` requirement for writable direct
  mounts.
- On Windows, detect whether the parsed mount list contains a direct mount.
- If direct mounts exist and `--allow-net` is false, start `lsb-proxy` in
  mount-only SMB mode and pass its `PlatformNetworkAttachment::QemuStream` into
  sandbox construction.
- If `--allow-net` is true, merge SMB gateway access into the normal proxy
  config instead of starting a second proxy.
- CLI error for non-elevated direct SMB mount should be actionable:
  `Windows direct mounts require an elevated Administrator shell`.
- Do not include generated usernames, passwords, share names, or raw host paths
  in errors unless the path was already user-provided and non-secret.

### `crates/lsb-sdk/src/runtime.rs`

- Mirror CLI behavior for SDK callers:
  - `allow_net=false` plus Windows direct mount starts mount-only SMB proxy.
  - `allow_net=true` merges SMB gateway handling into the regular proxy.
- Preserve `SandboxConfig` public shape.
- Ensure SDK artifacts and diagnostics redact SMB credentials.
- Add tests that direct SMB mount does not set `allow_net` semantics and does
  not enable arbitrary outbound traffic.

### `bindings/nodejs/`

- Preserve public Node API shape.
- Existing Node `MountConfig` direct flags should map to SDK direct flags.
- Add tests for:
  - `Direct { flags: 0 }` accepted on Windows planning path.
  - `Direct { flags: MS_RDONLY }` accepted.
  - unsupported flags rejected.
- Update docs only after implementation and smoke tests pass.

### `crates/lsb-vm/src/sandbox.rs`

- Change Windows mount planning storage from only copy imports to a combined
  Windows mount plan:
  - `overlay_imports: Vec<WindowsMountImport>`
  - `smb_directs: Vec<WindowsSmbMountSpec>`
  - guest `MountRequest`s for overlays
- During `Sandbox::start`:
  1. Prepare overlay imports as today.
  2. Prepare SMB resources before sending guest mount requests.
  3. Start the VM with the already configured network attachment.
  4. Send overlay and SMB mount requests over guest control.
  5. On failure, stop the VM if needed and clean up SMB resources.
- During `Sandbox::stop`:
  1. Best-effort ask guest to `sync` and unmount SMB direct targets.
  2. Stop the VM.
  3. Remove SMB shares.
  4. Revoke NTFS ACL grants.
  5. Delete ephemeral user.
  6. Drop credentials from memory.
- If no explicit unmount protocol exists yet, implement either:
  - a new guest control request for unmount, or
  - best-effort `sync` plus VM stop before host cleanup.
- Keep cleanup best-effort and continue after individual cleanup failures.
- Never derive or print `Debug` for credential-bearing values.

### `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`

- Replace `UnsupportedDirectMount` behavior with SMB direct planning.
- Preserve overlay planning exactly.
- Validate all direct mount target paths with the existing guest path rules.
- Reject duplicate guest targets across overlay and direct mounts.
- Reject targets under the reserved Windows staging root.
- For direct mounts, validate host source paths recursively:
  - canonical local path only.
  - reject UNC paths.
  - reject device namespace paths.
  - reject missing paths.
  - reject non-directory roots.
  - reject root reparse point.
  - recursively reject reparse points, symlinks, junctions, and hardlinks.
  - recursively reject case-insensitive collisions.
- Re-run validation immediately before share creation to reduce TOCTOU risk.

### `crates/lsb-platform/src/windows_x86_64/fs/smb/`

Add a new Windows-only SMB module with fakeable traits for unit tests.

Recommended submodules:

- `admin.rs`
  - `ensure_elevated_admin()`
  - Use `CheckTokenMembership` for the Administrators SID.
- `user.rs`
  - Create one local user per sandbox.
  - Use a short generated name such as `lsb_<12hex>` to fit Windows' 20
    character user-name limit.
  - Use `NetUserAdd` or `New-LocalUser` equivalent native API.
  - User is a normal local user, not Administrator.
  - Password never expires for the sandbox lifetime.
  - User cannot change password.
  - Delete with `NetUserDel`.
- `password.rs`
  - Generate password with OS CSPRNG.
  - Use password characters that satisfy common Windows complexity policies.
  - Avoid comma and whitespace even though `PASSWD_FD` is used.
  - Store in a redacted, zeroizing wrapper.
- `acl.rs`
  - Add a precise inheritable NTFS ACE for the generated user.
  - Read-only direct mount grants read/list/traverse/synchronize.
  - Read-write direct mount grants Modify-like access.
  - Use `GetNamedSecurityInfo`, `SetEntriesInAcl`, and
    `SetNamedSecurityInfo`.
  - Record enough non-secret information to remove the exact ACE later.
- `share.rs`
  - Create one temporary SMB share per direct mount.
  - Use share names like `lsb-<instance>-m<N>-<hex>`.
  - Do not encode the host path in the share name.
  - Grant only the generated user:
    - `Read` for direct read-only.
    - `Change` for direct read-write.
  - Prefer `NetShareAdd` with `SHARE_INFO_502` and a security descriptor.
  - `New-SmbShare` with `-Temporary` is acceptable as a fallback, but native API
    is preferred to avoid shell quoting and process diagnostics.
  - Delete with `NetShareDel` or `Remove-SmbShare -Force`.
- `lifecycle.rs`
  - Own the ordered setup and cleanup guards.
  - Produce `MountRequest::Smb` values for guest control.
  - Persist only a non-secret cleanup manifest in the instance dir:
    share names, user name, instance id, target paths, and ACL marker.
  - Never persist passwords.

### `crates/lsb-platform/src/windows_x86_64/backend.rs`

- Continue rejecting `shared_dirs` for Windows.
- Direct SMB mounts should not use `PlatformSharedDir`.
- Ensure VM startup still supports QEMU stream network attachment for
  mount-only proxy mode.
- Preserve Job Object cleanup behavior.

### `crates/lsb-platform/src/windows_x86_64/network/mod.rs`

- Preserve:
  - no network attachment -> `QemuNetworkConfig::None`.
  - QEMU stream attachment -> proxy stream network.
  - file descriptor network attachment rejected on Windows.
- Do not encode policy here. Policy belongs in `lsb-proxy`.
- Add tests showing direct SMB proxy attachment still uses loopback stream
  only.

### `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs`

- Preserve `-nic none` default.
- Preserve stream networking shape:
  `-netdev stream,id=...,addr.type=inet,addr.host=127.0.0.1,addr.port=...`.
- Add or update golden tests to assert SMB direct mounts never produce:
  - `-netdev user`
  - `hostfwd`
  - `tap`
  - `bridge`
  - `nat`
  - public listen addresses
- Ensure diagnostics redact proxy port and any mount-related identifiers that
  could become sensitive.

### `crates/lsb-proxy/src/config.rs`

- Add a mount-only SMB mode. Possible shape:

  ```rust
  enum ProxyMode {
      NetworkPolicy,
      MountOnlySmb,
      NetworkPolicyWithSmbMount,
  }
  ```

  The exact type shape should fit the existing config model.

- Mount-only SMB mode allows exactly:
  - TCP from guest to `10.0.0.1:445`, relayed to host `127.0.0.1:445`.
  - DNS answer for `host.lsb.internal` if DNS is queried.
- Mount-only SMB mode denies:
  - all other TCP destinations.
  - all arbitrary outbound DNS forwarding.
  - all TLS/SNI outbound proxying.
  - all arbitrary `expose_host` ports.
  - all secret placeholder handling.

### `crates/lsb-proxy/src/proxy.rs`

- Before any general outbound handling, check whether the connection is the SMB
  gateway flow:
  - guest destination IP `10.0.0.1`
  - guest destination port `445`
  - proxy config permits SMB mount relay
- If yes, relay to `127.0.0.1:445`.
- If mount-only mode and destination is anything else, close the connection and
  emit a sanitized policy-denied event.
- In combined `allow_net + SMB` mode, preserve current network policy behavior
  for allowed destinations and special-case SMB gateway relay.

### `crates/lsb-proxy/src/dns.rs`

- Keep `host.lsb.internal -> 10.0.0.1`.
- In mount-only mode, do not forward arbitrary DNS queries.
- Return a denial/no-answer for other names in mount-only mode.
- Guest mount implementation should use `10.0.0.1` directly, so DNS is a
  convenience, not a dependency.

### `crates/lsb-proxy/src/stack.rs`

- No architecture change expected.
- Add tests if necessary to ensure mount-only denied TCP flows are surfaced to
  proxy policy and not accidentally tunneled.

### `crates/lsb-proto/src/lib.rs`

- Add a new mount request variant instead of overloading VirtioFS `Direct`:

  ```text
  MountRequest::Smb {
      server: "10.0.0.1",
      share: "<non-secret share name>",
      target: "<guest absolute target>",
      username: "<ephemeral local user>",
      password: "<generated password, serialized only on control channel>",
      domain: "<Windows computer name>",
      read_only: bool,
      uid: u32,
      gid: u32,
      file_mode: u32,
      dir_mode: u32,
      options: Vec<String>,
  }
  ```

- Do not use free-form mount options that can include secrets.
- Add capability constant, for example `cifs_mount`.
- Update guest-ready validation to allow and require `cifs_mount` before sending
  SMB mount requests.
- Implement custom redacted debug/display for `MountRequest::Smb`.
- Add JSON roundtrip tests and redaction tests.

### `crates/lsb-guest/src/main.rs`

- Advertise `cifs_mount` capability after kernel/rootfs support exists.
- Add `process_mount` handling for `MountRequest::Smb`.
- Create target directory as current mount handling does.
- Build `mount.cifs` invocation:
  - service: `//<host-computer-name>/<share>`
  - target: guest target path
  - options include:
    - `vers=3.1.1`
    - `sec=ntlmssp`
    - `ip=10.0.0.1`
    - `domain=<host-computer-name>`
    - `port=445`
    - `uid=0`
    - `gid=0`
    - `forceuid`
    - `forcegid`
    - `cache=strict`
    - `actimeo=1`
    - `iocharset=utf8`
    - `serverino`
    - `ro` or `rw`
    - `file_mode=0644,dir_mode=0755` for read-only
    - `file_mode=0666,dir_mode=0777` for read-write
- Pass the password through `PASSWD_FD`, not:
  - command-line args.
  - `PASSWD`.
  - `PASSWD_FILE`.
  - `credentials=`.
  - logs.
  - guest environment.
- The environment may contain only `PASSWD_FD=<fd-number>` if required by
  `mount.cifs`.
- Sanitize all errors returned in `MountResponse`.
- Do not enable `mfsymlinks`.
- Do not enable `noperm` in v1.

### `kernel/lsb_x86_64_defconfig`

- Enable built-in CIFS support.
- Minimum expected change:
  - `CONFIG_CIFS=y`
- Consider enabling only required CIFS client options after checking kernel
  config dependencies.
- Do not enable SMB server support.

### `kernel/lsb_defconfig`

- Apply the same CIFS client support decision as `lsb_x86_64_defconfig`.
- Maintainer decision: update both kernels.

### `xtask/src/rootfs.rs`

- Add `cifs-utils` to the Debian package list so `/sbin/mount.cifs` exists.
- Add a rootfs verification test or assertion if the project has a suitable
  rootfs smoke path.

### Documentation

After implementation and smoke tests:

- Update `docs/windows-port/decisions.md` with a new decision superseding D011.
- Update `docs/windows-port/mvp-handoff.md`.
- Update `docs/windows-port/security-checklist.md`.
- Update `docs/windows-port/README.md`.
- Update `bindings/nodejs/README.md`.
- Update top-level README mount examples if applicable.

## Admin and Host Preflight

Preflight should run before creating any host resources.

Required checks:

1. Process is elevated Administrator.
2. Host source paths pass recursive direct validation.
3. Windows SMB server is available on host loopback.
4. `127.0.0.1:445` is reachable from the host process.
5. No generated user/share name collision.
6. Password generation succeeds and satisfies Windows policy.

Do not open Windows firewall rules by default. The guest reaches SMB through
the LocalSandbox proxy, and the proxy reaches the SMB server via host loopback.

If SMB service is disabled or port 445 is unavailable, fail with a sanitized
actionable error. Do not attempt broad system reconfiguration automatically.

## Resource Naming

Sandbox user:

- One per sandbox.
- Format: `lsb_<12hex>` or similarly short.
- Maximum 20 characters.
- No invalid Windows user-name characters.
- No path or tenant material.

SMB share:

- One per direct mount.
- Format: `lsb-<instance-short>-m<N>-<hex>`.
- Maximum 80 characters.
- Avoid reserved share names such as `IPC$`, `ADMIN$`, drive admin shares, and
  names `pipe` / `mailslot`.
- Do not include host path material.

Description/comment:

- Include a short LocalSandbox marker and instance id when supported.
- Keep within Windows field length limits.
- Do not include password or full host path.

## ACL Strategy

Share ACL:

- Grant only the generated local user.
- Read-only direct mount: SMB share `Read`.
- Read-write direct mount: SMB share `Change`.
- Do not grant `Everyone`, `Users`, or `Authenticated Users`.
- Do not rely on inherited permissive share ACLs.

NTFS ACL:

- Add an explicit inheritable allow ACE for the generated user on the source
  root.
- Read-only: read data, list directory, read attributes, read extended
  attributes, read permissions, traverse, synchronize.
- Read-write: read-only permissions plus create/write/append/delete child and
  delete where necessary for Modify-like behavior.
- Remove the exact ACE at cleanup.
- Do not take ownership.
- Do not replace the full DACL.
- If adding the ACE fails, clean up already-created resources and fail.

## Credential Handling

Generated SMB password lifetime:

1. Generated on host during SMB lifecycle setup.
2. Stored in host memory in a redacted, zeroizing wrapper.
3. Serialized only into the private guest-control mount request.
4. Passed by `lsb-guest` to `mount.cifs` through `PASSWD_FD`.
5. Dropped from host memory after guest mounts complete or cleanup runs.

Credential must never appear in:

- CLI output.
- SDK or Node errors.
- Rust `Debug` or `Display`.
- QEMU argv.
- guest process argv.
- guest environment, except fd number.
- proxy diagnostics.
- mount response errors.
- cleanup manifest.
- test snapshots.
- logs.

Security note: the generated password is necessarily available to the guest
mount agent and kernel during mount. The protection is least privilege,
short lifetime, generated-only credentials, and cleanup. The password is not a
host user credential.

## Guest Mount Behavior

Guest service path:

- Use `//<host-computer-name>/<share>` for the mount service path.
- Use `ip=10.0.0.1` to force the TCP connection through the LocalSandbox SMB
  proxy.
- Keep `host.lsb.internal` as a stable name for other local-host semantics, but
  SMB mounting should not depend on DNS.

Read-write mount:

- Windows share access: `Change`.
- NTFS ACL: Modify-like grant.
- CIFS options include `rw`.

Read-only mount:

- Windows share access: `Read`.
- NTFS ACL: read/list/traverse grant.
- CIFS options include `ro`.
- Guest writes must fail even if client-side permissions are permissive.

Cache/coherency:

- Use `cache=strict`.
- Use `actimeo=1` initially to reduce stale metadata.
- Do not use SMB encryption by default.
- Keep default SMB locking behavior.
- Do not use `nobrl` or `forcemand` in v1.

Case sensitivity:

- Windows host path validation rejects case-insensitive collisions before share
  creation.
- Document that Windows SMB semantics remain case-insensitive by default.
- Do not attempt to emulate Linux case-sensitive directories in v1.

Symlink/reparse/hardlink behavior:

- Recursive validation rejects these in v1.
- Do not enable CIFS `mfsymlinks`.
- Do not follow reparse points during validation.

## Cleanup and Failure Handling

Creation order:

1. Admin preflight.
2. Generate user name, share names, and password.
3. Create local user.
4. Grant NTFS ACLs.
5. Create SMB shares.
6. Start VM if not already started.
7. Send guest mount requests.

Cleanup order:

1. Best-effort guest `sync`.
2. Best-effort guest unmount of SMB targets.
3. Stop VM if needed.
4. Remove SMB shares.
5. Revoke NTFS ACL grants.
6. Delete local user.
7. Drop password memory.
8. Stop proxy handle.

Failure rules:

- Every setup step must have a cleanup guard before the next step begins.
- Cleanup must continue after individual failures.
- If guest mount fails, do not leave shares/users/ACLs behind.
- If cleanup fails, return or log only sanitized resource identifiers.
- Keep a non-secret cleanup manifest to support recovery after process crash.

Stale cleanup:

- On future startup, scan for LocalSandbox-marked stale shares/users.
- Use prefix plus manifest/marker checks.
- Do not delete resources that are not clearly LocalSandbox-owned.
- Avoid deleting resources that appear to belong to a live instance lock.

## Diagnostics and Redaction

Add explicit tests for redaction. Sensitive values include:

- SMB password.
- Any future credential handle.
- Full serialized mount request containing password.
- Raw `mount.cifs` error if it includes credential-bearing options.

Non-secret but still minimize in general diagnostics:

- generated username.
- share name.
- target path.
- host source path.
- proxy port.

Error examples:

- Good: `Windows direct mounts require an elevated Administrator shell`.
- Good: `failed to mount Windows direct directory at /work: authentication failed`.
- Good: `SMB server is unavailable on host loopback port 445`.
- Bad: includes password, full `mount.cifs -o ...`, generated username, or share
  name.

## Test Plan

### Unit Tests

- Windows direct planning accepts `flags=0`.
- Windows direct planning accepts exactly `MS_RDONLY`.
- Windows direct planning rejects unsupported flags.
- CLI `:ro` still maps to overlay.
- CLI `:rw` maps to direct and still requires `--allow-host-writes`.
- Duplicate guest targets rejected across overlay and direct mounts.
- Reserved staging targets rejected.
- Recursive validation rejects:
  - reparse points.
  - symlinks.
  - junctions.
  - hardlinks.
  - case-insensitive collisions.
  - UNC paths.
  - device namespace paths.
- User/share name generation respects length and invalid character rules.
- SMB lifecycle cleanup order with fake managers.
- Partial setup failure cleans previous resources.
- Redacted debug/display for SMB mount requests and lifecycle state.

### Proxy Tests

- No network and no direct mounts still produces `-nic none`.
- Direct SMB mount with `allow_net=false` starts mount-only proxy.
- Mount-only proxy allows only `10.0.0.1:445`.
- Mount-only proxy denies arbitrary TCP.
- Mount-only proxy does not forward arbitrary DNS.
- `host.lsb.internal` still resolves to `10.0.0.1`.
- Combined `allow_net=true` plus SMB direct mount preserves existing allowlist
  behavior.
- QEMU argv contains `-netdev stream`.
- QEMU argv never contains `-netdev user`, `hostfwd`, TAP, bridge, NAT, or public
  listener addresses.

### Protocol Tests

- `MountRequest::Smb` JSON roundtrip.
- Password serializes only in the actual control payload.
- Password is redacted from debug output.
- Host refuses SMB mount requests if guest lacks `cifs_mount` capability.
- Old overlay/direct protocol tests remain stable.

### Guest Tests

- `mount.cifs` command builder does not place password in argv.
- Password is passed by `PASSWD_FD`.
- Environment contains only fd number, not password.
- Read-only and read-write option sets are correct.
- Guest mount errors are sanitized.
- Guest unmount/sync path is best-effort.

### Windows CI and Smoke Tests

Use the existing Windows hardware test guidance:

- `./scripts/win-gh-test check` after portability changes.
- `./scripts/win-gh-test unit` before PR for Windows code.
- `./scripts/win-gh-test smoke` after QEMU, WHPX, VM lifecycle, transport, or
  guest-control changes.

Smoke scenarios:

1. Non-admin direct SMB mount fails preflight with actionable error.
2. Admin rw direct mount writes from guest and host sees the file.
3. Admin rw direct mount observes host-side file changes.
4. Admin direct read-only mount from SDK/Node denies guest writes.
5. CLI `:ro` remains overlay and does not live-sync.
6. Direct SMB mount with `allow_net=false` cannot reach arbitrary internet.
7. Cleanup leaves no `lsb-*` shares, users, or ACL grants.
8. Failure during share creation cleans user and ACL.
9. Failure during guest mount cleans shares, ACL, and user.
10. Artifact scan finds no generated password.

## Risk Register

SMB service disabled:

- Preflight loopback port 445 and service availability.
- Fail with actionable sanitized error.

Firewall/profile issues:

- Do not rely on inbound firewall rules because proxy connects to loopback.
- If loopback SMB is blocked by local policy, fail preflight.

Port 445 conflict:

- Windows SMB normally owns 445.
- If another service or policy prevents expected SMB behavior, fail preflight.

Windows Home/Pro differences:

- Use local user and SMB APIs available on supported Windows versions.
- Smoke test on the supported Windows SKU used by CI.

Path traversal/reparse points:

- Canonicalize and recursively validate before sharing.
- Revalidate immediately before share creation.
- Reject reparse/symlink/junction roots and descendants.

Hardlinks:

- Recursively reject files with link count greater than one.
- This prevents modifying data reachable outside the requested tree by hardlink.

NTFS ACL mismatch:

- Add explicit ACE for generated user.
- Keep share ACL and NTFS ACL aligned.
- Remove exact ACE on cleanup.

Credential leakage:

- Redacted wrappers, no derived debug, `PASSWD_FD`, artifact scans.

Concurrent mounts of same path:

- One share per mount, one user per sandbox.
- Recursive validation and ACL grants may overlap.
- Cleanup must remove only ACEs owned by the current sandbox.

Case-insensitive collisions:

- Reject during recursive validation.
- Document Windows case-insensitive behavior.

Performance and coherency:

- Recursive validation can be expensive.
- `cache=strict,actimeo=1` trades performance for safer live behavior.
- Revisit cache settings only after smoke/performance data.

Forced share removal data loss:

- Attempt guest sync and unmount before removing shares.
- Remove shares after VM stop when guest is unresponsive.

## Documentation Updates After Implementation

- Update the accepted Windows SMB/CIFS direct-mount decision with any
  implementation or validation evidence that changes the decision record.
- Document Administrator requirement.
- Document `:rw` live direct behavior.
- Document `:ro` remains overlay.
- Document no general network access is implied by SMB direct mounts.
- Document unsupported path features:
  - symlinks.
  - junctions.
  - reparse points.
  - hardlinks.
  - case-insensitive collisions.
- Document cleanup behavior and troubleshooting for stale resources.

## Suggested Implementation Order

1. Add/update Windows decision docs for this feature.
2. Add CIFS kernel config to both kernel configs.
3. Add `cifs-utils` to rootfs package list.
4. Add `MountRequest::Smb` and `cifs_mount` capability with redaction tests.
5. Add guest `mount.cifs` implementation using `PASSWD_FD`.
6. Add mount-only SMB proxy mode.
7. Add CLI/SDK detection to start mount-only proxy for Windows direct mounts.
8. Add Windows SMB planning for direct mounts.
9. Add Windows SMB lifecycle manager with fakeable tests.
10. Wire lifecycle into `Sandbox::start` and cleanup into `Sandbox::stop`.
11. Add QEMU argv/proxy golden tests.
12. Add Windows unit tests for validation and cleanup.
13. Add Windows WHPX smoke tests.
14. Update public docs and Node README after validation passes.

## Recommended Agent Slicing

Do not implement this feature as one large agent run. It crosses protocol,
guest init, rootfs assets, proxy policy, Windows host APIs, lifecycle cleanup,
and hardware smoke tests. Use small milestone agents with explicit file
boundaries, and have each agent update `STATE.md` before handing off.

Each slice should end at a reviewable checkpoint with targeted validation. If a
slice needs to change boundaries, record the reason in `STATE.md` before making
the change.

### Slice 1: Decisions and Planning Docs

Goal:

- Record the accepted Windows SMB direct-mount decision.
- Supersede the old Windows "no direct rw mounts" decision.
- Keep this as documentation only.

Allowed files:

- `docs/windows-port/decisions.md`
- `docs/windows-port/README.md`
- `docs/windows-port/mvp-handoff.md`
- `docs/windows-port/security-checklist.md`
- `docs/windows-port/future-work.md`
- `PLAN.md`
- `STATE.md`

Disallowed work:

- No code changes.
- No tests except markdown or docs checks if available.

Exit criteria:

- Docs clearly state that Windows direct mounts use SMB/CIFS.
- Docs clearly state CLI `:ro` remains overlay.
- Docs clearly state Administrator is required for Windows direct SMB mounts.
- `STATE.md` records docs validation.

Suggested agent prompt:

```text
Implement Slice 1 from PLAN.md. Only update Windows port planning/decision docs
and STATE.md. Do not edit code. Keep the public API unchanged.
```

### Slice 2: Protocol, Guest, Kernel, and Rootfs Foundation

Goal:

- Add the guest-visible SMB mount protocol and guest support.
- Add CIFS support to both kernel configs.
- Add `cifs-utils` to the rootfs.
- Establish credential redaction rules at the protocol boundary.

Allowed files:

- `crates/lsb-proto/src/lib.rs`
- `crates/lsb-guest/src/main.rs`
- `kernel/lsb_x86_64_defconfig`
- `kernel/lsb_defconfig`
- `xtask/src/rootfs.rs`
- Directly related tests in the same crates.
- `STATE.md`

Disallowed work:

- No Windows SMB user/share/ACL lifecycle.
- No CLI/SDK proxy startup changes.
- No `lsb-proxy` policy changes.
- No public CLI/SDK/Node API shape changes.

Required implementation boundaries:

- Add a new `MountRequest::Smb` variant instead of overloading
  `MountRequest::Direct`.
- Add a `cifs_mount` guest capability.
- Password-bearing protocol structures must have redacted debug/display output.
- Guest `mount.cifs` path must use `PASSWD_FD`.
- Password must not appear in guest argv, logs, or mount response errors.

Exit criteria:

- Protocol roundtrip tests pass.
- Redaction tests pass.
- Guest mount command construction tests pass.
- Both kernel configs enable CIFS client support.
- Rootfs includes `cifs-utils`.
- `STATE.md` records validation and any missing host-side integration.

Suggested agent prompt:

```text
Implement Slice 2 from PLAN.md. Only touch lsb-proto, lsb-guest, kernel configs,
rootfs packaging, directly related tests, and STATE.md. Do not implement Windows
SMB lifecycle, proxy policy, or CLI/SDK startup.
```

### Slice 3: Mount-Only SMB Proxy

Goal:

- Add a LocalSandbox proxy mode that permits only SMB mount traffic when
  `allow_net` is false.
- Preserve existing allowlist behavior when `allow_net` is true.

Allowed files:

- `crates/lsb-proxy/src/config.rs`
- `crates/lsb-proxy/src/proxy.rs`
- `crates/lsb-proxy/src/dns.rs`
- `crates/lsb-proxy/src/stack.rs`
- Directly related proxy tests.
- `STATE.md`

Disallowed work:

- No Windows SMB host lifecycle.
- No guest protocol changes beyond adapting to Slice 2 types if required.
- No QEMU argv changes except tests that consume existing stream attachment
  behavior.
- No CLI/SDK startup changes unless a tiny type exposure is required for this
  proxy config to be usable by the next slice.

Required implementation boundaries:

- Mount-only mode allows only guest `10.0.0.1:445` to host
  `127.0.0.1:445`.
- Mount-only mode may answer `host.lsb.internal` as `10.0.0.1`.
- Mount-only mode must not forward arbitrary DNS.
- Mount-only mode must not allow arbitrary outbound TCP.
- Mount-only mode must not enable secret placeholder or TLS/SNI outbound proxy
  behavior.

Exit criteria:

- Proxy policy tests prove only SMB gateway traffic is allowed.
- Tests prove arbitrary TCP and DNS are denied in mount-only mode.
- Combined network-plus-SMB mode preserves existing network policy behavior.
- `STATE.md` records validation.

Suggested agent prompt:

```text
Implement Slice 3 from PLAN.md. Only touch lsb-proxy, directly related tests,
and STATE.md. Add mount-only SMB proxy mode that allows only 10.0.0.1:445 to
127.0.0.1:445. Do not implement Windows SMB lifecycle or CLI/SDK detection.
```

### Slice 4: CLI, SDK, and QEMU Attachment Integration

Goal:

- Detect Windows direct mounts and attach the mount-only SMB proxy without
  enabling arbitrary `allow_net`.
- Preserve public CLI/SDK/Node behavior.
- Prove QEMU still uses stream networking, not user networking.

Allowed files:

- `crates/lsb-cli/src/vm.rs`
- `crates/lsb-sdk/src/runtime.rs`
- `crates/lsb-sdk/src/types.rs` only if an internal-compatible type addition is
  unavoidable.
- `crates/lsb-platform/src/windows_x86_64/network/mod.rs`
- `crates/lsb-platform/src/windows_x86_64/qemu/config.rs`
- `crates/lsb-platform/src/windows_x86_64/qemu/argv.rs`
- Node binding files only for compatibility tests, not API redesign.
- Directly related tests.
- `STATE.md`

Disallowed work:

- No SMB user/share/ACL lifecycle.
- No mount planner direct support beyond minimal feature detection if needed.
- No guest mount implementation changes.
- No new CLI syntax for direct read-only.

Required implementation boundaries:

- CLI `:ro` remains overlay.
- CLI `:rw` remains direct and still requires `--allow-host-writes`.
- Direct Windows mount plus `allow_net=false` starts mount-only SMB proxy.
- Direct Windows mount plus `allow_net=true` merges SMB gateway handling into
  the normal proxy path.
- Default no-network/no-direct-mount Windows VM remains `-nic none`.
- QEMU argv must not contain `-netdev user`, `hostfwd`, TAP, bridge, NAT, or
  public listener paths.

Exit criteria:

- CLI/SDK unit tests cover direct mount proxy attachment.
- Golden argv tests cover default no NIC and SMB stream netdev.
- Tests prove mount-only proxy does not toggle `allow_net` semantics.
- `STATE.md` records validation.

Suggested agent prompt:

```text
Implement Slice 4 from PLAN.md. Only wire CLI/SDK detection and QEMU stream
attachment for Windows direct SMB mounts. Preserve :ro as overlay and do not add
new public API shape. Do not implement SMB user/share/ACL lifecycle.
```

### Slice 5: Windows SMB Host Lifecycle

Goal:

- Implement the Windows host resource manager for direct SMB mounts.
- Keep it fakeable and heavily unit-tested before integrating with sandbox
  startup.

Allowed files:

- `crates/lsb-platform/src/windows_x86_64/fs/smb/`
- `crates/lsb-platform/src/windows_x86_64/fs/mod.rs`
- Windows-specific support modules needed for path, ACL, user, or share APIs.
- Directly related Windows unit tests.
- `Cargo.toml` files only if new Windows API crate features are needed.
- `STATE.md`

Disallowed work:

- No sandbox startup integration beyond exposing clean APIs.
- No CLI/SDK changes.
- No proxy changes.
- No guest changes.

Required implementation boundaries:

- One ephemeral local Windows user per sandbox.
- One temporary SMB share per direct mount.
- Generated password uses OS CSPRNG and a redacted, zeroizing wrapper.
- Admin preflight happens before resource creation.
- Share ACL grants only the generated user.
- NTFS ACL grants are explicit and reversible.
- Cleanup order is share removal, ACL revoke, user deletion.
- Cleanup continues best-effort after individual failures.
- No passwords in debug/display/errors/logs.

Exit criteria:

- Fake-manager tests cover success and partial-failure cleanup.
- Name generation tests cover Windows limits and invalid characters.
- Redaction tests cover all credential-bearing structs.
- Admin preflight maps non-admin state to actionable sanitized error.
- `STATE.md` records validation.

Suggested agent prompt:

```text
Implement Slice 5 from PLAN.md. Add the Windows SMB host lifecycle manager with
fakeable user/share/ACL/admin/password components and unit tests. Do not wire it
into Sandbox::start yet. Do not touch proxy, CLI, SDK, or guest code except for
shared types strictly required by this slice.
```

### Slice 6: Mount Planning and Sandbox Lifecycle Integration

Goal:

- Enable Windows direct mount planning.
- Run recursive direct path validation.
- Wire SMB lifecycle into sandbox start/stop and guest mount request sending.

Allowed files:

- `crates/lsb-vm/src/sandbox.rs`
- `crates/lsb-platform/src/windows_x86_64/fs/mount_plan.rs`
- `crates/lsb-platform/src/windows_x86_64/fs/copy.rs` only if shared
  validation helpers must be extracted.
- `crates/lsb-platform/src/windows_x86_64/fs/smb/` only for integration fixes.
- Directly related tests.
- `STATE.md`

Disallowed work:

- No new CLI syntax.
- No proxy policy redesign.
- No protocol redesign beyond small integration fixes.
- No docs finalization beyond `STATE.md`.

Required implementation boundaries:

- Windows `Direct { flags: 0 }` maps to SMB rw.
- Windows `Direct { flags: MS_RDONLY }` maps to SMB ro.
- Other direct flags are rejected.
- Overlay planning remains unchanged.
- Recursive direct validation rejects reparse points, symlinks, junctions,
  hardlinks, UNC/device paths, non-directory roots, and case-insensitive
  collisions.
- SMB resources are cleaned up if VM start or guest mount fails.
- Normal stop attempts guest sync/unmount before host cleanup.

Exit criteria:

- Planner tests cover semantics matrix.
- Sandbox tests cover direct mount setup/cleanup with fake lifecycle manager.
- Existing overlay tests still pass.
- Windows direct no longer fails with `UnsupportedDirectMount`.
- `STATE.md` records validation.

Suggested agent prompt:

```text
Implement Slice 6 from PLAN.md. Wire Windows direct mount planning and SMB
lifecycle into Sandbox start/stop using the Slice 5 lifecycle manager. Preserve
overlay behavior and reject unsupported flags. Do not add CLI syntax or redesign
proxy/protocol.
```

### Slice 7: Windows Smoke Tests, Recovery, and Docs Finalization

Goal:

- Prove the full feature on Windows WHPX.
- Add stale cleanup/recovery coverage.
- Finalize user-facing docs after behavior is verified.

Allowed files:

- Windows smoke test files and scripts.
- Cleanup/recovery tests.
- `docs/windows-port/*`
- `README.md`
- `bindings/nodejs/README.md`
- Any test-only fixtures or helpers.
- Small bug fixes in implementation files if required by smoke results.
- `STATE.md`

Disallowed work:

- No broad refactors.
- No behavior changes outside smoke-discovered bug fixes.
- No public API shape changes.

Required implementation boundaries:

- Run Windows unit tests before smoke tests.
- Run Windows smoke tests for rw direct, SDK/Node ro direct, CLI `:ro` overlay,
  no arbitrary outbound network, cleanup, failure cleanup, and password scan.
- Docs must reflect final verified behavior.
- `STATE.md` must contain final validation commands and results.

Exit criteria:

- `./scripts/win-gh-test unit` passes for the pushed commit.
- `./scripts/win-gh-test smoke` passes for the pushed commit.
- Artifact scan finds no generated SMB password.
- Docs match implemented behavior.
- `STATE.md` marks all relevant checklist items complete.

Suggested agent prompt:

```text
Implement Slice 7 from PLAN.md. Focus on Windows unit/smoke coverage, stale
cleanup/recovery validation, redaction artifact scans, and final docs. Avoid
behavior changes except smoke-discovered bug fixes.
```

## Acceptance Criteria

- `:rw` direct mount on Windows works from an elevated Administrator shell.
- `:ro` CLI still creates overlay behavior.
- SDK/Node direct read-only works with `MS_RDONLY`.
- Unsupported direct flags fail early.
- Direct SMB mount does not enable arbitrary outbound network.
- QEMU argv uses stream networking only and never user networking or hostfwd.
- Guest mounts with CIFS and does not expose password in argv/env/logs.
- Generated Windows user and SMB shares are removed on normal stop.
- Partial failures clean up all created resources best-effort.
- Recursive validation rejects unsupported path structures.
- Both kernel configs include CIFS client support.
- `cifs-utils` is present in the guest rootfs.
- Windows CI and smoke tests cover rw, ro, overlay compatibility, no-network
  policy, cleanup, and redaction.
