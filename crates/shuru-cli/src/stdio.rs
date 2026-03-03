use std::io::{self, BufRead, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use shuru_vm::Sandbox;

use crate::vm::{self, PreparedVm};

#[derive(Deserialize)]
struct Request {
    id: String,
    #[serde(flatten)]
    cmd: Command,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Command {
    Exec { argv: Vec<String> },
    Checkpoint { name: String },
}

#[derive(Serialize)]
struct ReadyMsg {
    r#type: &'static str,
}

#[derive(Serialize)]
struct ExecResponse {
    id: String,
    r#type: &'static str,
    stdout: String,
    stderr: String,
    exit_code: i32,
}

#[derive(Serialize)]
struct CheckpointResponse {
    id: String,
    r#type: &'static str,
    ok: bool,
}

#[derive(Serialize)]
struct ErrorResponse {
    id: String,
    r#type: &'static str,
    error: String,
}

fn send_json(w: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let line = serde_json::to_string(value)?;
    writeln!(w, "{}", line)?;
    w.flush()?;
    Ok(())
}

pub(crate) fn run_stdio(prepared: &PreparedVm) -> Result<i32> {
    let mut out = io::stdout().lock();

    let sandbox = build_sandbox(prepared)?;
    sandbox.start()?;

    let _fwd = if !prepared.forwards.is_empty() {
        Some(sandbox.start_port_forwarding(&prepared.forwards)?)
    } else {
        None
    };

    send_json(&mut out, &ReadyMsg { r#type: "ready" })?;

    let stdin = io::stdin().lock();
    for line in stdin.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ErrorResponse {
                    id: String::new(),
                    r#type: "error",
                    error: format!("invalid request: {}", e),
                };
                send_json(&mut out, &resp)?;
                continue;
            }
        };

        match req.cmd {
            Command::Exec { argv } => {
                handle_exec(&sandbox, &req.id, &argv, &mut out)?;
            }
            Command::Checkpoint { name } => {
                handle_checkpoint(&sandbox, prepared, &req.id, &name, &mut out)?;
                let _ = sandbox.stop();
                return Ok(0);
            }
        }
    }

    let _ = sandbox.stop();
    Ok(0)
}

fn build_sandbox(prepared: &PreparedVm) -> Result<Sandbox> {
    let mut builder = Sandbox::builder()
        .kernel(&prepared.kernel_path)
        .rootfs(&prepared.work_rootfs)
        .cpus(prepared.cpus)
        .memory_mb(prepared.memory)
        .allow_net(prepared.allow_net)
        .console(false);

    if let Some(initrd) = &prepared.initrd_path {
        builder = builder.initrd(initrd);
    }

    for m in &prepared.mounts {
        builder = builder.mount(m.clone());
    }

    builder.build()
}

fn handle_exec(
    sandbox: &Sandbox,
    id: &str,
    argv: &[String],
    out: &mut impl Write,
) -> Result<()> {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    let exit_code = match sandbox.exec(argv, &mut stdout_buf, &mut stderr_buf) {
        Ok(code) => code,
        Err(e) => {
            return send_json(
                out,
                &ErrorResponse {
                    id: id.to_string(),
                    r#type: "error",
                    error: format!("exec failed: {}", e),
                },
            );
        }
    };

    send_json(
        out,
        &ExecResponse {
            id: id.to_string(),
            r#type: "exec",
            stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
            exit_code,
        },
    )
}

fn handle_checkpoint(
    sandbox: &Sandbox,
    prepared: &PreparedVm,
    id: &str,
    name: &str,
    out: &mut impl Write,
) -> Result<()> {
    let mut discard_out = Vec::new();
    let mut discard_err = Vec::new();
    if let Err(e) = sandbox.exec(&["sync"], &mut discard_out, &mut discard_err) {
        return send_json(
            out,
            &ErrorResponse {
                id: id.to_string(),
                r#type: "error",
                error: format!("checkpoint sync failed: {}", e),
            },
        );
    }

    let data_dir = shuru_vm::default_data_dir();
    let checkpoints_dir = format!("{}/checkpoints", data_dir);
    let checkpoint_path = format!("{}/{}.ext4", checkpoints_dir, name);

    if let Err(e) = std::fs::create_dir_all(&checkpoints_dir) {
        return send_json(
            out,
            &ErrorResponse {
                id: id.to_string(),
                r#type: "error",
                error: format!("failed to create checkpoints dir: {}", e),
            },
        );
    }

    if let Err(e) = vm::clone_file(&prepared.work_rootfs, &checkpoint_path) {
        return send_json(
            out,
            &ErrorResponse {
                id: id.to_string(),
                r#type: "error",
                error: format!("checkpoint clone failed: {}", e),
            },
        );
    }

    send_json(
        out,
        &CheckpointResponse {
            id: id.to_string(),
            r#type: "checkpoint",
            ok: true,
        },
    )
}
