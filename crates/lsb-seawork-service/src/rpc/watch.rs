use std::time::Duration;

use lsb_service_proto::{ErrorCode, ResponseValue};

use crate::resource::watch::WatchResource;
use crate::session::{ClientIdentityKey, ResourceHandle, SessionManager};

#[allow(clippy::too_many_arguments)]
pub async fn start(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    sandbox_id: String,
    path: String,
    recursive: bool,
    deadline_ms: Option<u32>,
) -> Result<WatchResource, ErrorCode> {
    let sandbox_id = ResourceHandle::parse(&sandbox_id).map_err(|_| ErrorCode::InvalidRequest)?;
    let timeout = Duration::from_millis(u64::from(deadline_ms.unwrap_or(30_000)));
    tokio::task::spawn_blocking(move || {
        sessions
            .start_managed_watch(session_id, &identity, sandbox_id, path, recursive, timeout)
            .and_then(|result| result.ok_or_else(|| anyhow::anyhow!("resource not found")))
            .map_err(map_watch_error)
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

pub async fn stop(
    sessions: SessionManager,
    session_id: ResourceHandle,
    identity: ClientIdentityKey,
    watch_id: String,
) -> Result<ResponseValue, ErrorCode> {
    let watch_id = ResourceHandle::parse(&watch_id).map_err(|_| ErrorCode::InvalidRequest)?;
    tokio::task::spawn_blocking(move || {
        sessions
            .stop_managed_watch(session_id, &identity, watch_id)
            .and_then(|found| {
                found
                    .then_some(())
                    .ok_or_else(|| anyhow::anyhow!("resource not found"))
            })
            .map(|()| ResponseValue::Empty {})
            .map_err(map_watch_error)
    })
    .await
    .map_err(|_| ErrorCode::InternalError)?
}

fn map_watch_error(error: anyhow::Error) -> ErrorCode {
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
