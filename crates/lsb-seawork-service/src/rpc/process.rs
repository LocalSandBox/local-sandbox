use std::collections::HashMap;
use std::time::Duration;

use lsb_service_proto::{ErrorCode, ResponseValue, ServiceCommand};

use crate::resource::process::GuestProcessResource;
use crate::resource::vm::ManagedExecSpec;
use crate::session::{ClientIdentityKey, ResourceHandle, SessionManager};

#[allow(clippy::too_many_arguments)]
pub async fn exec(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    command: ServiceCommand,
    cwd: Option<String>,
    env: std::collections::BTreeMap<String, String>,
    deadline_ms: Option<u32>,
) -> Result<ResponseValue, ErrorCode> {
    let handle = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let spec = managed_spec(command, cwd, env);
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .exec_managed_vm(session_id, &identity, handle, spec, timeout)
            .and_then(|result| result.ok_or_else(|| anyhow::anyhow!("resource not found")))
            .map(|result| ResponseValue::ExecCompleted {
                stdout: String::from_utf8_lossy(&result.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&result.stderr).into_owned(),
                exit_code: result.exit_code,
            })
            .map_err(|error| {
                if error.to_string().contains("output limit") {
                    ErrorCode::OutputLimit
                } else if error.to_string().contains("deadline") {
                    ErrorCode::DeadlineExceeded
                } else if error.to_string() == "resource not found" {
                    ErrorCode::ResourceNotFound
                } else {
                    ErrorCode::InternalError
                }
            })
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

#[allow(clippy::too_many_arguments)]
pub async fn spawn(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    command: ServiceCommand,
    cwd: Option<String>,
    env: std::collections::BTreeMap<String, String>,
    deadline_ms: Option<u32>,
) -> Result<GuestProcessResource, ErrorCode> {
    let sandbox_id = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let spec = managed_spec(command, cwd, env);
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .spawn_managed_process(session_id, &identity, sandbox_id, spec, timeout)
            .and_then(|result| result.ok_or_else(|| anyhow::anyhow!("resource not found")))
            .map_err(map_process_error)
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

pub async fn kill(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    process_id: String,
) -> Result<ResponseValue, ErrorCode> {
    let process_id = ResourceHandle::parse(&process_id).map_err(|_| ErrorCode::InvalidRequest)?;
    tokio::task::spawn_blocking(move || {
        sessions
            .kill_managed_process(session_id, &identity, process_id)
            .and_then(|found| {
                found
                    .then_some(())
                    .ok_or_else(|| anyhow::anyhow!("resource not found"))
            })
            .map(|()| ResponseValue::Empty {})
            .map_err(map_process_error)
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

fn managed_spec(
    command: ServiceCommand,
    cwd: Option<String>,
    env: std::collections::BTreeMap<String, String>,
) -> ManagedExecSpec {
    let argv = match command {
        ServiceCommand::Argv(command) => command.argv,
        ServiceCommand::Shell(command) => {
            vec!["/bin/sh".to_string(), "-lc".to_string(), command.shell]
        }
    };
    ManagedExecSpec {
        argv,
        env: env.into_iter().collect::<HashMap<_, _>>(),
        cwd,
    }
}

fn map_process_error(error: anyhow::Error) -> ErrorCode {
    let message = error.to_string();
    if message.contains("quota exceeded") {
        ErrorCode::QuotaExceeded
    } else if message.contains("deadline") {
        ErrorCode::DeadlineExceeded
    } else if message == "resource not found" {
        ErrorCode::ResourceNotFound
    } else {
        ErrorCode::InternalError
    }
}
