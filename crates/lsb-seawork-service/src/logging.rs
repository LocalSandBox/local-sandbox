use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

const MAX_LOG_FILES: usize = 10;
const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Event<'a> {
    pub event_id: u32,
    pub timestamp_unix_ms: u128,
    pub phase: &'a str,
    pub stable_code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<&'a str>,
}

pub struct JsonLogger {
    path: PathBuf,
}

impl JsonLogger {
    pub fn new(log_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(log_dir)?;
        Ok(Self {
            path: log_dir.join("service.jsonl"),
        })
    }

    pub fn write(&self, event_id: u32, phase: &str, stable_code: &str) -> Result<()> {
        self.rotate()?;
        let event = Event {
            event_id,
            timestamp_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            phase,
            stable_code,
            correlation_id: None,
        };
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, &event)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn rotate(&self) -> Result<()> {
        if self.path.metadata().map(|value| value.len()).unwrap_or(0) < MAX_LOG_SIZE {
            return Ok(());
        }
        for index in (1..MAX_LOG_FILES).rev() {
            let source = self.path.with_extension(format!("jsonl.{index}"));
            let target = self.path.with_extension(format!("jsonl.{}", index + 1));
            if source.exists() {
                std::fs::rename(source, target)?;
            }
        }
        std::fs::rename(&self.path, self.path.with_extension("jsonl.1"))?;
        Ok(())
    }
}
