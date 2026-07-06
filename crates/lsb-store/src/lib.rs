mod backend;
mod base;
pub mod cas;
mod nbd;
mod windows_checkpoint;

pub use backend::FlatFileBackend;
pub use base::{
    pin_base_version, pin_rootfs, read_data_dir_version, resolve_base_version, BaseVersionRecord,
    PinnedRootfs,
};
pub use cas::{CasBackend, ChunkIndex, ChunkStore, LocalChunkStore};
pub use nbd::NbdBackend;
pub use windows_checkpoint::{
    QemuImg, QemuImgInvocation, WindowsCheckpointEntry, WindowsCheckpointError,
    WindowsCheckpointLayout, WindowsCheckpointMetadata, WindowsCheckpointPaths,
    WindowsCheckpointSource, WindowsCheckpointSourceKind, WindowsCheckpointSourceMetadata,
    WindowsCheckpointSourceMetadataKind, WindowsCheckpointStore, WindowsDiskImageFormat,
    WINDOWS_CHECKPOINT_SCHEMA_VERSION,
};

#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
#[cfg(unix)]
use tracing::{debug, info, warn};

pub struct NbdHandle {
    socket_path: String,
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    cas_backend: Option<Arc<CasBackend>>,
}

impl NbdHandle {
    pub fn uri(&self) -> String {
        format!("nbd+unix:///export?socket={}", self.socket_path)
    }

    pub fn save_checkpoint(&self, index_path: &str) -> Result<()> {
        let backend = self
            .cas_backend
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("save_checkpoint requires CAS backend"))?;
        backend.save_index(index_path)
    }
}

impl Drop for NbdHandle {
    fn drop(&mut self) {
        if let Some(ref backend) = self.cas_backend {
            let _ = backend.flush();
        }
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        #[cfg(unix)]
        let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(unix)]
fn start_nbd_with_backend(
    backend: Arc<dyn NbdBackend>,
    socket_path: &str,
    cas_backend: Option<Arc<CasBackend>>,
) -> Result<NbdHandle> {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind NBD socket: {}", socket_path))?;
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let socket_path_owned = socket_path.to_string();

    let thread = std::thread::Builder::new()
        .name("lsb-nbd".into())
        .spawn(move || {
            info!("NBD server listening on {}", socket_path_owned);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if shutdown_rx.try_recv().is_ok() {
                            debug!("NBD server shutting down");
                            break;
                        }
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        info!("NBD client connected");
                        if let Err(e) = nbd::handle_client(stream, backend.clone()) {
                            warn!("NBD client session ended: {:#}", e);
                        }
                        debug!("NBD client disconnected, waiting for reconnect...");
                    }
                    Err(e) => {
                        if shutdown_rx.try_recv().is_ok() {
                            break;
                        }
                        warn!("NBD accept error: {}", e);
                    }
                }
            }
            info!("NBD server stopped");
        })?;

    Ok(NbdHandle {
        socket_path: socket_path.to_string(),
        shutdown: Some(shutdown_tx),
        thread: Some(thread),
        cas_backend,
    })
}

#[cfg(unix)]
pub fn start_cas_nbd_server(
    rootfs_path: &str,
    cas_dir: &str,
    index_path: &str,
    socket_path: &str,
    disk_size: u64,
) -> Result<NbdHandle> {
    let store: Box<dyn ChunkStore> = Box::new(LocalChunkStore::open(cas_dir)?);

    let (index, fallback, source_idx) = if Path::new(index_path).exists() {
        info!("loading CAS index from {}", index_path);
        let idx = ChunkIndex::load(index_path)?;
        let fallback =
            match idx.fallback_path.as_ref() {
                Some(path) => Some(FlatFileBackend::open(path).with_context(|| {
                    format!("failed to open CAS index fallback rootfs: {}", path)
                })?),
                None => None,
            };
        (idx, fallback, Some(index_path.to_string()))
    } else {
        let fallback = FlatFileBackend::open(rootfs_path).with_context(|| {
            format!("failed to open rootfs for lazy ingestion: {}", rootfs_path)
        })?;
        let disk_size = fallback.size();
        info!("CAS: lazy mode, {} MB rootfs", disk_size / (1024 * 1024));
        (ChunkIndex::new(disk_size), Some(fallback), None)
    };

    let mut backend = if let Some(fallback) = fallback {
        CasBackend::with_fallback(store, index, fallback)?
    } else {
        CasBackend::new(store, index)?
    };
    backend.source_index_path = source_idx;
    if disk_size > 0 {
        backend.set_disk_size(disk_size);
    }

    let cas = Arc::new(backend);
    start_nbd_with_backend(cas.clone(), socket_path, Some(cas))
}

#[cfg(not(unix))]
pub fn start_cas_nbd_server(
    _rootfs_path: &str,
    _cas_dir: &str,
    _index_path: &str,
    _socket_path: &str,
    _disk_size: u64,
) -> Result<NbdHandle> {
    Err(anyhow::anyhow!(
        "NBD/CAS storage transport is not available on Windows; Windows uses qcow2/raw checkpoint disk artifacts instead of Unix-socket NBD/CAS"
    ))
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn nbd_stub_reports_windows_checkpoint_mode() {
        let message = match start_cas_nbd_server("rootfs.ext4", "cas", "index.idx", "nbd.sock", 0) {
            Ok(_) => panic!("NBD should be unsupported"),
            Err(error) => error.to_string(),
        };

        assert!(message.contains("NBD/CAS storage transport"));
        assert!(message.contains("qcow2/raw checkpoint disk artifacts"));
    }
}
