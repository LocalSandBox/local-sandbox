use crate::session::ResourceHandle;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchResource {
    pub id: ResourceHandle,
    pub sandbox_id: ResourceHandle,
    pub guest_path: String,
}

impl WatchResource {
    pub fn new(sandbox_id: ResourceHandle, guest_path: String) -> anyhow::Result<Self> {
        Ok(Self {
            id: ResourceHandle::random()?,
            sandbox_id,
            guest_path,
        })
    }
}
