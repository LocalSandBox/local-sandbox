use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, Result};

pub const CHUNK_SIZE: usize = 64 * 1024;

pub trait ChunkStore: Send + Sync {
    fn put(&self, data: &[u8]) -> Result<String>;
    fn get(&self, hash: &str) -> Result<Option<Vec<u8>>>;
}

pub struct LocalChunkStore {
    chunks_dir: PathBuf,
}

impl LocalChunkStore {
    pub fn open(cas_dir: &str) -> Result<Self> {
        let chunks_dir = Path::new(cas_dir).join("chunks");
        fs::create_dir_all(&chunks_dir)
            .with_context(|| format!("failed to create chunks dir: {}", chunks_dir.display()))?;
        Ok(Self { chunks_dir })
    }

    fn chunk_path(&self, hash: &str) -> PathBuf {
        self.chunks_dir.join(hash)
    }
}

impl ChunkStore for LocalChunkStore {
    fn put(&self, data: &[u8]) -> Result<String> {
        let hash = blake3::hash(data);
        let hex = hash.to_hex().to_string();
        let path = self.chunk_path(&hex);
        match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut f) => f
                .write_all(data)
                .with_context(|| format!("failed to write chunk {}", hex))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("failed to create chunk {}", hex)),
        }
        Ok(hex)
    }

    fn get(&self, hash: &str) -> Result<Option<Vec<u8>>> {
        let path = self.chunk_path(hash);
        match fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("failed to read chunk {}", hash)),
        }
    }
}

pub struct ChunkIndex {
    hashes: Vec<String>,
    disk_size: u64,
    pub parent_path: Option<String>,
    pub fallback_path: Option<String>,
}

const ZERO_CHUNK_HASH: &str = "ZERO";

impl ChunkIndex {
    pub fn new(disk_size: u64) -> Self {
        let num_chunks = disk_chunks(disk_size);
        Self {
            hashes: vec![ZERO_CHUNK_HASH.to_string(); num_chunks],
            disk_size,
            parent_path: None,
            fallback_path: None,
        }
    }

    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    pub fn num_chunks(&self) -> usize {
        self.hashes.len()
    }

    pub fn get_hash(&self, chunk_idx: usize) -> Option<&str> {
        self.hashes.get(chunk_idx).map(|s| s.as_str())
    }

    pub fn set_hash(&mut self, chunk_idx: usize, hash: String) {
        if chunk_idx < self.hashes.len() {
            self.hashes[chunk_idx] = hash;
        }
    }

    pub fn save(&self, path: &str) -> Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f =
            fs::File::create(path).with_context(|| format!("failed to create index: {}", path))?;
        f.write_all(&self.disk_size.to_le_bytes())?;
        f.write_all(&(self.hashes.len() as u64).to_le_bytes())?;

        let parent_bytes = self.parent_path.as_deref().unwrap_or("").as_bytes();
        f.write_all(&(parent_bytes.len() as u32).to_le_bytes())?;
        f.write_all(parent_bytes)?;

        let fallback_bytes = self.fallback_path.as_deref().unwrap_or("").as_bytes();
        f.write_all(&(fallback_bytes.len() as u32).to_le_bytes())?;
        f.write_all(fallback_bytes)?;

        for hash in &self.hashes {
            let bytes = hash.as_bytes();
            f.write_all(&(bytes.len() as u32).to_le_bytes())?;
            f.write_all(bytes)?;
        }

        Ok(())
    }

    pub fn load(path: &str) -> Result<Self> {
        let mut f = fs::File::open(path).with_context(|| format!("failed to open index: {}", path))?;

        let mut buf8 = [0u8; 8];
        f.read_exact(&mut buf8)?;
        let disk_size = u64::from_le_bytes(buf8);
        f.read_exact(&mut buf8)?;
        let num_chunks = u64::from_le_bytes(buf8) as usize;

        let mut buf4 = [0u8; 4];
        f.read_exact(&mut buf4)?;
        let parent_len = u32::from_le_bytes(buf4) as usize;
        let parent_path = if parent_len > 0 {
            let mut parent_bytes = vec![0u8; parent_len];
            f.read_exact(&mut parent_bytes)?;
            Some(String::from_utf8(parent_bytes)?)
        } else {
            None
        };

        f.read_exact(&mut buf4)?;
        let fallback_len = u32::from_le_bytes(buf4) as usize;
        let fallback_path = if fallback_len > 0 {
            let mut fallback_bytes = vec![0u8; fallback_len];
            f.read_exact(&mut fallback_bytes)?;
            Some(String::from_utf8(fallback_bytes)?)
        } else {
            None
        };

        let mut hashes = Vec::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            f.read_exact(&mut buf4)?;
            let len = u32::from_le_bytes(buf4) as usize;
            let mut hash_bytes = vec![0u8; len];
            f.read_exact(&mut hash_bytes)?;
            hashes.push(String::from_utf8(hash_bytes)?);
        }

        Ok(Self {
            hashes,
            disk_size,
            parent_path,
            fallback_path,
        })
    }
}

pub struct CasBackend {
    store: Box<dyn ChunkStore>,
    index: RwLock<ChunkIndex>,
    dirty: RwLock<HashMap<usize, Vec<u8>>>,
    parents: RwLock<Vec<ChunkIndex>>,
    fallback: Option<crate::backend::FlatFileBackend>,
    pub source_index_path: Option<String>,
}

impl CasBackend {
    pub fn new(store: Box<dyn ChunkStore>, index: ChunkIndex) -> Self {
        let parents = Self::load_parent_chain(&index);
        Self {
            store,
            index: RwLock::new(index),
            dirty: RwLock::new(HashMap::new()),
            parents: RwLock::new(parents),
            fallback: None,
            source_index_path: None,
        }
    }

    pub fn with_fallback(
        store: Box<dyn ChunkStore>,
        index: ChunkIndex,
        fallback: crate::backend::FlatFileBackend,
    ) -> Self {
        let parents = Self::load_parent_chain(&index);
        Self {
            store,
            index: RwLock::new(index),
            dirty: RwLock::new(HashMap::new()),
            parents: RwLock::new(parents),
            fallback: Some(fallback),
            source_index_path: None,
        }
    }

    fn load_parent_chain(index: &ChunkIndex) -> Vec<ChunkIndex> {
        let mut chain = Vec::new();
        let mut current_parent = index.parent_path.clone();
        while let Some(path) = current_parent {
            match ChunkIndex::load(&path) {
                Ok(parent) => {
                    current_parent = parent.parent_path.clone();
                    chain.push(parent);
                }
                Err(e) => {
                    tracing::warn!("failed to load parent index {}: {}", path, e);
                    break;
                }
            }
        }
        chain
    }

    pub fn size(&self) -> u64 {
        self.index.read().unwrap().disk_size()
    }

    pub fn set_disk_size(&mut self, new_size: u64) {
        let mut index = self.index.write().unwrap();
        if new_size > index.disk_size() {
            let new_num_chunks = disk_chunks(new_size);
            while index.num_chunks() < new_num_chunks {
                index.hashes.push(ZERO_CHUNK_HASH.to_string());
            }
            index.disk_size = new_size;
        }
    }

    pub fn read(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut pos = 0usize;
        let mut file_offset = offset;

        while pos < buf.len() {
            let chunk_idx = (file_offset / CHUNK_SIZE as u64) as usize;
            let offset_in_chunk = (file_offset % CHUNK_SIZE as u64) as usize;
            let remaining_in_chunk = CHUNK_SIZE - offset_in_chunk;
            let to_read = remaining_in_chunk.min(buf.len() - pos);

            let chunk_data = self.read_chunk(chunk_idx)?;
            let available = chunk_data.len().saturating_sub(offset_in_chunk);
            let copy_len = to_read.min(available);

            if copy_len > 0 {
                buf[pos..pos + copy_len]
                    .copy_from_slice(&chunk_data[offset_in_chunk..offset_in_chunk + copy_len]);
            }
            if copy_len < to_read {
                buf[pos + copy_len..pos + to_read].fill(0);
            }

            pos += to_read;
            file_offset += to_read as u64;
        }

        Ok(buf.len())
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        let mut pos = 0usize;
        let mut file_offset = offset;

        while pos < data.len() {
            let chunk_idx = (file_offset / CHUNK_SIZE as u64) as usize;
            let offset_in_chunk = (file_offset % CHUNK_SIZE as u64) as usize;
            let remaining_in_chunk = CHUNK_SIZE - offset_in_chunk;
            let to_write = remaining_in_chunk.min(data.len() - pos);

            let mut chunk_data = self.read_chunk(chunk_idx)?;
            if chunk_data.len() < offset_in_chunk + to_write {
                chunk_data.resize(offset_in_chunk + to_write, 0);
            }
            chunk_data[offset_in_chunk..offset_in_chunk + to_write]
                .copy_from_slice(&data[pos..pos + to_write]);

            self.dirty.write().unwrap().insert(chunk_idx, chunk_data);

            pos += to_write;
            file_offset += to_write as u64;
        }

        Ok(data.len())
    }

    pub fn flush(&self) -> std::io::Result<()> {
        let mut dirty = self.dirty.write().unwrap();
        let mut index = self.index.write().unwrap();

        for (chunk_idx, data) in dirty.drain() {
            let hash = self
                .store
                .put(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
            index.set_hash(chunk_idx, hash);
        }

        Ok(())
    }

    pub fn save_index(&self, path: &str) -> Result<()> {
        self.flush().map_err(|e| anyhow::anyhow!(e))?;
        let mut index = self.index.write().unwrap();
        index.parent_path = self.source_index_path.clone();
        if index.fallback_path.is_none() {
            if let Some(ref fallback) = self.fallback {
                index.fallback_path = Some(fallback.path().to_string());
            }
        }
        index.save(path)
    }

    fn read_chunk(&self, chunk_idx: usize) -> std::io::Result<Vec<u8>> {
        if let Some(data) = self.dirty.read().unwrap().get(&chunk_idx) {
            return Ok(data.clone());
        }

        let hash = {
            let index = self.index.read().unwrap();
            index
                .get_hash(chunk_idx)
                .unwrap_or(ZERO_CHUNK_HASH)
                .to_string()
        };
        if hash != ZERO_CHUNK_HASH {
            return self.fetch_chunk(&hash);
        }

        for parent in self.parents.read().unwrap().iter() {
            let parent_hash = parent.get_hash(chunk_idx).unwrap_or(ZERO_CHUNK_HASH);
            if parent_hash != ZERO_CHUNK_HASH {
                return self.fetch_chunk(parent_hash);
            }
        }

        if let Some(ref fallback) = self.fallback {
            let offset = chunk_idx as u64 * CHUNK_SIZE as u64;
            if offset < fallback.size() {
                let read_len = CHUNK_SIZE.min((fallback.size() - offset) as usize);
                let mut buf = vec![0u8; read_len];
                fallback.read(offset, &mut buf)?;

                if buf.iter().all(|&b| b == 0) {
                    return Ok(vec![0u8; CHUNK_SIZE]);
                }

                let new_hash = self
                    .store
                    .put(&buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                self.index.write().unwrap().set_hash(chunk_idx, new_hash);
                return Ok(buf);
            }
        }

        Ok(vec![0u8; CHUNK_SIZE])
    }

    fn fetch_chunk(&self, hash: &str) -> std::io::Result<Vec<u8>> {
        match self.store.get(hash) {
            Ok(Some(data)) => Ok(data),
            Ok(None) => {
                tracing::warn!("chunk {} not found in store, returning zeros", hash);
                Ok(vec![0u8; CHUNK_SIZE])
            }
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        }
    }
}

fn disk_chunks(disk_size: u64) -> usize {
    ((disk_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_store_put_get() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = LocalChunkStore::open(tmp.path().to_str().expect("path")).expect("store");

        let data = b"hello world";
        let hash = store.put(data).expect("put");
        let retrieved = store.get(&hash).expect("get").expect("chunk");
        assert_eq!(retrieved, data);
    }

    #[test]
    fn index_save_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let idx_path = tmp.path().join("test.idx");

        let mut index = ChunkIndex::new(1024 * 1024);
        index.set_hash(0, "abc123".to_string());
        index.set_hash(5, "def456".to_string());
        index.save(idx_path.to_str().expect("path")).expect("save");

        let loaded = ChunkIndex::load(idx_path.to_str().expect("path")).expect("load");
        assert_eq!(loaded.disk_size(), 1024 * 1024);
        assert_eq!(loaded.get_hash(0).expect("hash"), "abc123");
        assert_eq!(loaded.get_hash(5).expect("hash"), "def456");
    }
}
