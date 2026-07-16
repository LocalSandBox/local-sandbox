use std::collections::VecDeque;

use anyhow::{bail, Result};

pub const MAX_WRITER_FRAMES: usize = 128;
pub const MAX_WRITER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct WriterQueue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}

impl WriterQueue {
    pub fn enqueue(&mut self, frame: Vec<u8>) -> Result<()> {
        let next_bytes = self
            .bytes
            .checked_add(frame.len())
            .ok_or_else(|| anyhow::anyhow!("writer queue byte count overflow"))?;
        if self.frames.len() >= MAX_WRITER_FRAMES || next_bytes > MAX_WRITER_BYTES {
            bail!("writer queue capacity exceeded");
        }
        self.bytes = next_bytes;
        self.frames.push_back(frame);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let frame = self.frames.pop_front()?;
        self.bytes -= frame.len();
        Some(frame)
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_frames_and_bytes_without_losing_accounting() {
        let mut queue = WriterQueue::default();
        for _ in 0..MAX_WRITER_FRAMES {
            queue.enqueue(vec![0]).unwrap();
        }
        assert!(queue.enqueue(vec![0]).is_err());
        assert_eq!(queue.len(), MAX_WRITER_FRAMES);
        while queue.pop().is_some() {}
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
        assert!(queue.enqueue(vec![0; MAX_WRITER_BYTES + 1]).is_err());
    }
}
