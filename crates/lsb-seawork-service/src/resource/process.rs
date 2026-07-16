use crate::session::ResourceHandle;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProcessResource {
    pub id: ResourceHandle,
    pub sandbox_id: ResourceHandle,
    pub stdout_stream: ResourceHandle,
    pub stderr_stream: ResourceHandle,
}

impl GuestProcessResource {
    pub fn new(sandbox_id: ResourceHandle) -> anyhow::Result<Self> {
        Ok(Self {
            id: ResourceHandle::random()?,
            sandbox_id,
            stdout_stream: ResourceHandle::random()?,
            stderr_stream: ResourceHandle::random()?,
        })
    }
}
