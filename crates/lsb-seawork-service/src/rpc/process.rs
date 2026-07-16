use std::collections::HashMap;
use std::time::Duration;

use lsb_service_proto::{ErrorCode, ResponseValue, ServiceCommand};

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
    let argv = match command {
        ServiceCommand::Argv(command) => command.argv,
        ServiceCommand::Shell(command) => {
            vec!["/bin/sh".to_string(), "-lc".to_string(), command.shell]
        }
    };
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .exec_managed_vm(
                session_id,
                &identity,
                handle,
                ManagedExecSpec {
                    argv,
                    env: env.into_iter().collect::<HashMap<_, _>>(),
                    cwd,
                },
                timeout,
            )
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
