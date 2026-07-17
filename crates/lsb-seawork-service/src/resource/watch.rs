use std::collections::VecDeque;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use lsb_service_proto::WatchChange;
use serde::{Deserialize, Serialize};

use crate::session::ResourceHandle;

const WATCH_QUEUE_EVENTS: usize = 256;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedWatchEvent {
    pub path: String,
    pub change: WatchChange,
}

#[derive(Default)]
struct WatchQueueState {
    events: VecDeque<ManagedWatchEvent>,
    closed: bool,
}

#[derive(Default)]
struct WatchQueue {
    state: Mutex<WatchQueueState>,
    ready: Condvar,
}

impl WatchQueue {
    fn push(&self, event: ManagedWatchEvent, root: &str) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.closed {
            return;
        }
        if let Some(queued) = state
            .events
            .iter_mut()
            .find(|queued| queued.path == event.path)
        {
            queued.change = event.change;
        } else if state.events.len() < WATCH_QUEUE_EVENTS {
            state.events.push_back(event);
        } else {
            state.events.clear();
            state.events.push_back(ManagedWatchEvent {
                path: root.to_string(),
                change: WatchChange::Overflow,
            });
        }
        self.ready.notify_one();
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            self.ready.notify_all();
        }
    }

    fn discard_and_close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.events.clear();
            state.closed = true;
            self.ready.notify_all();
        }
    }

    fn next(&self, timeout: Duration) -> Result<Option<ManagedWatchEvent>> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("guest watch queue poisoned"))?;
        loop {
            if let Some(event) = state.events.pop_front() {
                return Ok(Some(event));
            }
            if state.closed {
                return Ok(None);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let (next, wait) = self
                .ready
                .wait_timeout(state, remaining)
                .map_err(|_| anyhow::anyhow!("guest watch queue poisoned"))?;
            state = next;
            if wait.timed_out() && state.events.is_empty() {
                return Ok(None);
            }
        }
    }
}

#[derive(Clone)]
pub struct ManagedWatchController {
    queue: Arc<WatchQueue>,
    stopped: Arc<AtomicBool>,
    cancel: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for ManagedWatchController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedWatchController")
            .finish_non_exhaustive()
    }
}

pub struct ManagedWatch {
    controller: ManagedWatchController,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for ManagedWatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedWatch")
            .finish_non_exhaustive()
    }
}

impl ManagedWatch {
    pub fn start<R, F>(mut reader: R, root: String, cancel: F) -> Result<Self>
    where
        R: Read + Send + 'static,
        F: Fn() + Send + Sync + 'static,
    {
        let queue = Arc::new(WatchQueue::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let cancel: Arc<dyn Fn() + Send + Sync> = Arc::new(cancel);
        let controller = ManagedWatchController {
            queue: queue.clone(),
            stopped: stopped.clone(),
            cancel,
        };
        let thread = std::thread::Builder::new()
            .name("lsbsw-guest-watch".to_string())
            .spawn(move || {
                watch_event_loop(&mut reader, &root, &queue, &stopped);
                queue.close();
            })
            .context("spawn bounded guest watch pump")?;
        Ok(Self {
            controller,
            thread: Some(thread),
        })
    }

    pub fn controller(&self) -> ManagedWatchController {
        self.controller.clone()
    }
}

impl ManagedWatchController {
    pub fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            (self.cancel)();
            self.queue.discard_and_close();
        }
    }

    pub fn next(&self, timeout: Duration) -> Result<Option<ManagedWatchEvent>> {
        self.queue.next(timeout)
    }

    pub fn is_closed(&self) -> bool {
        self.queue
            .state
            .lock()
            .map(|state| state.closed && state.events.is_empty())
            .unwrap_or(true)
    }
}

impl Drop for ManagedWatch {
    fn drop(&mut self) {
        self.controller.stop();
        if self
            .thread
            .as_ref()
            .is_some_and(|thread| thread.is_finished())
        {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GuestWatchEvent {
    path: String,
    event: String,
}

fn watch_event_loop(reader: &mut impl Read, root: &str, queue: &WatchQueue, stopped: &AtomicBool) {
    while !stopped.load(Ordering::Acquire) {
        let event = match lsb_vm::frame::read_frame(reader) {
            Ok(Some((lsb_vm::frame::WATCH_EVENT, payload))) => {
                serde_json::from_slice::<GuestWatchEvent>(&payload)
                    .ok()
                    .and_then(map_guest_event)
            }
            Ok(Some((lsb_vm::frame::ERROR, _))) | Ok(None) | Err(_) => break,
            Ok(Some(_)) => continue,
        };
        if let Some(event) = event {
            queue.push(event, root);
        }
    }
}

fn map_guest_event(event: GuestWatchEvent) -> Option<ManagedWatchEvent> {
    let change = match event.event.as_str() {
        "create" => WatchChange::Created,
        "modify" => WatchChange::Modified,
        "delete" => WatchChange::Removed,
        "rename" => WatchChange::Renamed,
        _ => return None,
    };
    Some(ManagedWatchEvent {
        path: event.path,
        change,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[test]
    fn guest_events_are_mapped_and_repeated_paths_are_coalesced() {
        let queue = WatchQueue::default();
        queue.push(
            ManagedWatchEvent {
                path: "/workspace/file".to_string(),
                change: WatchChange::Created,
            },
            "/workspace",
        );
        queue.push(
            ManagedWatchEvent {
                path: "/workspace/file".to_string(),
                change: WatchChange::Modified,
            },
            "/workspace",
        );
        assert_eq!(
            queue.next(Duration::ZERO).unwrap(),
            Some(ManagedWatchEvent {
                path: "/workspace/file".to_string(),
                change: WatchChange::Modified,
            })
        );
        assert_eq!(queue.next(Duration::ZERO).unwrap(), None);
    }

    #[test]
    fn saturation_collapses_to_one_overflow_event() {
        let queue = WatchQueue::default();
        for index in 0..=WATCH_QUEUE_EVENTS {
            queue.push(
                ManagedWatchEvent {
                    path: format!("/workspace/{index}"),
                    change: WatchChange::Created,
                },
                "/workspace",
            );
        }
        assert_eq!(
            queue.next(Duration::ZERO).unwrap(),
            Some(ManagedWatchEvent {
                path: "/workspace".to_string(),
                change: WatchChange::Overflow,
            })
        );
        assert_eq!(queue.next(Duration::ZERO).unwrap(), None);
    }

    #[test]
    fn watch_reads_guest_frames_and_stop_is_idempotent() {
        let mut frames = Cursor::new(Vec::new());
        lsb_vm::frame::send_json(
            &mut frames,
            lsb_vm::frame::WATCH_EVENT,
            &GuestWatchEvent {
                path: "/workspace/new".to_string(),
                event: "create".to_string(),
            },
        )
        .unwrap();
        frames.set_position(0);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = cancellations.clone();
        let watch = ManagedWatch::start(frames, "/workspace".to_string(), move || {
            cancel_count.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        let controller = watch.controller();
        assert_eq!(
            controller.next(Duration::from_secs(1)).unwrap(),
            Some(ManagedWatchEvent {
                path: "/workspace/new".to_string(),
                change: WatchChange::Created,
            })
        );
        controller.stop();
        controller.stop();
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    }
}
