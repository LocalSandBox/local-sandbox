# Windows SMB Direct Mounts Implementation State

This file is for implementation agents to keep progress, decisions, blockers,
and validation results synchronized while implementing `PLAN.md`.

## Current Status

- Overall status: Not started
- Current owner:
- Current branch:
- Last updated:
- Latest validated commit:

## Active Focus

- Current task:
- Relevant files:
- Immediate next step:
- Blockers:

## Maintainer Decisions

- [x] Use SMB/CIFS for Windows direct directory mounts.
- [x] Preserve macOS-like direct semantics, including `:rw`.
- [x] Require Administrator for Windows SMB direct mounts.
- [x] Use the LocalSandbox controlled proxy path.
- [x] Do not use QEMU user networking, `hostfwd`, TAP, bridge, NAT, or public
  listener paths.
- [x] Create ephemeral Windows SMB shares.
- [x] Create ephemeral Windows users and generated SMB credentials.
- [x] Recursive validation for direct mounts is required.
- [x] Keep CLI `:ro` as overlay.
- [x] Do not enable SMB encryption by default.
- [x] Use one ephemeral Windows user per sandbox.
- [x] Update both kernel configs.

## Progress Checklist

- [ ] Update Windows decision docs to supersede the old no-direct-rw decision.
- [ ] Enable CIFS client support in both kernel configs.
- [ ] Add `cifs-utils` to the rootfs package list.
- [ ] Add `MountRequest::Smb`.
- [ ] Add `cifs_mount` guest capability.
- [ ] Add protocol redaction tests for SMB credentials.
- [ ] Implement guest `mount.cifs` path using `PASSWD_FD`.
- [ ] Add mount-only SMB proxy mode.
- [ ] Add CLI detection/startup for mount-only SMB proxy.
- [ ] Add SDK detection/startup for mount-only SMB proxy.
- [ ] Preserve Node API shape and direct flag mapping.
- [ ] Add Windows direct SMB mount planning.
- [ ] Add recursive direct path validation.
- [ ] Add Windows admin preflight.
- [ ] Add ephemeral user manager.
- [ ] Add generated password wrapper and redaction.
- [ ] Add NTFS ACL grant/revoke manager.
- [ ] Add temporary SMB share manager.
- [ ] Add SMB lifecycle setup/cleanup guard.
- [ ] Wire SMB lifecycle into `Sandbox::start`.
- [ ] Wire cleanup into `Sandbox::stop`.
- [ ] Add stale cleanup manifest/recovery.
- [ ] Add QEMU argv golden tests.
- [ ] Add proxy policy tests.
- [ ] Add guest mount tests.
- [ ] Add Windows unit tests.
- [ ] Add Windows WHPX smoke tests.
- [ ] Update user-facing docs after validation.

## Validation Log

| Date | Commit | Command | Result | Notes |
| --- | --- | --- | --- | --- |
| | | | | |

## Open Blockers

| Date | Area | Blocker | Owner | Resolution |
| --- | --- | --- | --- | --- |
| | | | | |

## Follow-Up Decisions Needed

| Date | Question | Options | Decision | Owner |
| --- | --- | --- | --- | --- |
| | | | | |

## Changed Files Tracker

Use this section to summarize intentional changes. Do not include generated
artifacts unless they are intentionally checked in.

| File | Status | Notes |
| --- | --- | --- |
| | | |

## Cleanup/Redaction Audit

- [ ] Generated SMB passwords absent from CLI output.
- [ ] Generated SMB passwords absent from SDK/Node errors.
- [ ] Generated SMB passwords absent from Rust `Debug`/`Display`.
- [ ] Generated SMB passwords absent from QEMU argv.
- [ ] Generated SMB passwords absent from guest process argv.
- [ ] Generated SMB passwords absent from guest environment except fd number.
- [ ] Generated SMB passwords absent from proxy diagnostics.
- [ ] Generated SMB passwords absent from mount response errors.
- [ ] Generated SMB passwords absent from cleanup manifests.
- [ ] Generated SMB passwords absent from test snapshots.
- [ ] Generated SMB passwords absent from logs.

## Smoke Test State

- Non-admin preflight failure:
- Admin rw direct mount guest-to-host write:
- Admin rw direct mount host-to-guest visibility:
- SDK/Node direct read-only write denial:
- CLI `:ro` overlay compatibility:
- Mount-only proxy no arbitrary outbound network:
- Cleanup leaves no LocalSandbox shares:
- Cleanup leaves no LocalSandbox users:
- Cleanup removes NTFS ACL grants:
- Failure injection cleanup:
- Artifact password scan:

## Notes

- Keep this file current during implementation.
- Link back to `PLAN.md` for design details.
- Record deviations from `PLAN.md` in "Follow-Up Decisions Needed" before
  implementing them.
