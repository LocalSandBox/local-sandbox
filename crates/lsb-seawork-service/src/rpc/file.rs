use std::time::Duration;

use lsb_service_proto::{ErrorCode, ResponseValue, ServiceDirEntry, ServiceFileStat};

use crate::resource::vm::{ManagedFileOp, ManagedFileResult};
use crate::session::{CancellationToken, ClientIdentityKey, ResourceHandle, SessionManager};

pub async fn run(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    op: ManagedFileOp,
    deadline_ms: Option<u32>,
    cancellation: CancellationToken,
) -> Result<ResponseValue, ErrorCode> {
    let handle = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .file_managed_vm(session_id, &identity, handle, op, timeout, cancellation)
            .map_err(map_file_error)?
            .ok_or(ErrorCode::ResourceNotFound)
            .map(to_response)
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

pub async fn read(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    path: String,
    deadline_ms: Option<u32>,
    cancellation: CancellationToken,
) -> Result<Vec<u8>, ErrorCode> {
    let handle = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .file_managed_vm(
                session_id,
                &identity,
                handle,
                ManagedFileOp::ReadFile { path },
                timeout,
                cancellation,
            )
            .map_err(|error| {
                if error.to_string().contains("cancelled") {
                    ErrorCode::Cancelled
                } else if error.to_string().contains("initial stream credit") {
                    ErrorCode::OutputLimit
                } else {
                    ErrorCode::InternalError
                }
            })?
            .ok_or(ErrorCode::ResourceNotFound)
            .and_then(|result| match result {
                ManagedFileResult::Bytes(bytes) => Ok(bytes),
                _ => Err(ErrorCode::InternalError),
            })
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

fn map_file_error(error: anyhow::Error) -> ErrorCode {
    if error.to_string().contains("cancelled") {
        ErrorCode::Cancelled
    } else if error.to_string().contains("deadline") {
        ErrorCode::DeadlineExceeded
    } else {
        ErrorCode::InternalError
    }
}

fn to_response(result: ManagedFileResult) -> ResponseValue {
    match result {
        ManagedFileResult::Empty => ResponseValue::Empty {},
        ManagedFileResult::Directory(entries) => ResponseValue::Directory {
            entries: entries
                .into_iter()
                .map(|entry| ServiceDirEntry {
                    name: entry.name,
                    entry_type: entry.entry_type,
                    size: entry.size,
                })
                .collect(),
        },
        ManagedFileResult::Stat(stat) => ResponseValue::FileStat {
            stat: ServiceFileStat {
                size: stat.size,
                mode: stat.mode,
                mtime: stat.mtime,
                is_dir: stat.is_dir,
                is_file: stat.is_file,
                is_symlink: stat.is_symlink,
            },
        },
        ManagedFileResult::Exists(exists) => ResponseValue::Exists { exists },
        ManagedFileResult::Bytes(_) => ResponseValue::Empty {},
    }
}
