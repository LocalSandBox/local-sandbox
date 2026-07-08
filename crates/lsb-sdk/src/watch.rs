use std::io::BufReader;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::time::Duration;

use anyhow::Result;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use lsb_platform::windows_x86_64::fs::{
    join_guest_watch_event_path, WindowsHostDirectoryWatch, WindowsHostWatchError,
    WindowsHostWatchEvent,
};
use tokio::sync::mpsc;

use crate::session::BoxedControlSession;
use crate::WatchEvent;

/// Handle to a file watch stream in the VM.
pub struct WatchHandle {
    events_rx: Option<mpsc::UnboundedReceiver<Result<WatchEvent>>>,
    cancel_session: Option<WatchCancelSession>,
}

#[derive(Clone)]
struct WatchCancelSession {
    inner: Arc<Mutex<Option<BoxedControlSession>>>,
}

impl WatchCancelSession {
    fn new(session: BoxedControlSession) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(session))),
        }
    }

    fn close(&self) {
        let Ok(mut session) = self.inner.lock() else {
            return;
        };
        if let Some(mut session) = session.take() {
            let _ = session.close_session();
        }
    }

    fn detach(self) {}
}

impl WatchHandle {
    pub async fn next(&mut self) -> Option<Result<WatchEvent>> {
        self.events_rx.as_mut()?.recv().await
    }

    pub fn into_events(mut self) -> mpsc::UnboundedReceiver<Result<WatchEvent>> {
        if let Some(cancel_session) = self.cancel_session.take() {
            // Keep the underlying session owned by the reader thread. Returning
            // Tokio's receiver directly leaves no place to store a cancel guard.
            cancel_session.detach();
        }
        self.events_rx
            .take()
            .expect("watch event receiver should be present")
    }

    #[cfg(all(test, target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn try_next(
        &mut self,
    ) -> std::result::Result<Option<Result<WatchEvent>>, mpsc::error::TryRecvError> {
        let Some(events_rx) = self.events_rx.as_mut() else {
            return Err(mpsc::error::TryRecvError::Disconnected);
        };
        match events_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        if let Some(session) = self.cancel_session.take() {
            session.close();
        }
    }
}

pub(crate) fn spawn_watch_thread(stream: BoxedControlSession) -> WatchHandle {
    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let cancel_session = stream.try_clone_session().ok().map(WatchCancelSession::new);
    let reader_cancel_session = cancel_session.clone();

    let _ = std::thread::Builder::new()
        .name("lsb-watch".into())
        .spawn(move || {
            let _reader_cancel_session = reader_cancel_session;
            let mut reader = BufReader::new(stream);
            loop {
                match lsb_proto::frame::read_frame(&mut reader) {
                    Ok(Some((lsb_proto::frame::WATCH_EVENT, payload))) => {
                        let result = serde_json::from_slice::<lsb_proto::WatchEvent>(&payload)
                            .map(|event| WatchEvent {
                                path: event.path,
                                event: event.event,
                            })
                            .map_err(anyhow::Error::from);
                        if events_tx.send(result).is_err() {
                            break;
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        let _ = events_tx.send(Err(error.into()));
                        break;
                    }
                }
            }
        });

    WatchHandle {
        events_rx: Some(events_rx),
        cancel_session,
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) fn spawn_windows_smb_host_watch_thread<R>(
    watch: WindowsHostDirectoryWatch,
    platform_events: std::sync::mpsc::Receiver<
        Result<WindowsHostWatchEvent, WindowsHostWatchError>,
    >,
    guest_root: String,
    event_filter: Option<String>,
    registration: R,
) -> WatchHandle
where
    R: Send + 'static,
{
    let (events_tx, events_rx) = mpsc::unbounded_channel();

    let _ = std::thread::Builder::new()
        .name("lsb-windows-smb-watch-events".into())
        .spawn(move || {
            let _watch = watch;
            let _registration = registration;
            loop {
                if events_tx.is_closed() {
                    break;
                }

                match platform_events.recv_timeout(Duration::from_millis(200)) {
                    Ok(Ok(event)) => {
                        let relative_path =
                            normalize_windows_host_relative_path(&event.relative_path);
                        if event_filter
                            .as_deref()
                            .is_some_and(|filter| relative_path != filter)
                        {
                            continue;
                        }
                        let event = WatchEvent {
                            path: join_guest_watch_event_path(&guest_root, &relative_path),
                            event: event.kind.as_watch_event().to_string(),
                        };
                        if events_tx.send(Ok(event)).is_err() {
                            break;
                        }
                    }
                    Ok(Err(error)) => {
                        let _ = events_tx.send(Err(anyhow::anyhow!(error.to_string())));
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });

    WatchHandle {
        events_rx: Some(events_rx),
        cancel_session: None,
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn normalize_windows_host_relative_path(path: &str) -> String {
    path.split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::session::test_support::memory_session_pair;
    use crate::session::ControlSession;

    #[test]
    fn watch_forwards_watch_event_frames() {
        let (host, mut guest) = memory_session_pair();
        let handle = spawn_watch_thread(Box::new(host));
        let mut events = handle.into_events();

        lsb_proto::frame::send_json(
            &mut guest,
            lsb_proto::frame::WATCH_EVENT,
            &lsb_proto::WatchEvent {
                path: "/tmp/file.txt".to_string(),
                event: "modify".to_string(),
            },
        )
        .expect("watch event frame should write");

        let event = events
            .blocking_recv()
            .expect("watch event should arrive")
            .expect("watch event should parse");
        assert_eq!(event.path, "/tmp/file.txt");
        assert_eq!(event.event, "modify");
    }

    #[derive(Clone)]
    struct DropTrackingSession<S> {
        inner: S,
        drops: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }

    impl<S> Drop for DropTrackingSession<S> {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl<S: Read> Read for DropTrackingSession<S> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<S: Write> Write for DropTrackingSession<S> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.inner.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl<S> ControlSession for DropTrackingSession<S>
    where
        S: ControlSession + Clone,
    {
        fn try_clone_session(&self) -> io::Result<BoxedControlSession> {
            Ok(Box::new(self.clone()))
        }

        fn close_session(&mut self) -> io::Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            self.inner.close_session()
        }

        fn reset_session(&mut self) -> io::Result<()> {
            self.inner.reset_session()
        }
    }

    #[test]
    fn into_events_keeps_guest_watch_session_alive() {
        let (host, mut guest) = memory_session_pair();
        let drops = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));
        let tracked_host = DropTrackingSession {
            inner: host,
            drops: Arc::clone(&drops),
            closes: Arc::clone(&closes),
        };
        let handle = spawn_watch_thread(Box::new(tracked_host));

        let mut events = handle.into_events();

        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "into_events must not drop the cancellation session clone"
        );
        assert_eq!(closes.load(Ordering::SeqCst), 0);

        lsb_proto::frame::send_json(
            &mut guest,
            lsb_proto::frame::WATCH_EVENT,
            &lsb_proto::WatchEvent {
                path: "/tmp/later.txt".to_string(),
                event: "modify".to_string(),
            },
        )
        .expect("later watch event frame should write");

        let event = events
            .blocking_recv()
            .expect("watch event should arrive after into_events")
            .expect("watch event should parse");
        assert_eq!(event.path, "/tmp/later.txt");
        assert_eq!(event.event, "modify");

        drop(events);
        drop(guest);

        let deadline = Instant::now() + Duration::from_secs(2);
        while drops.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(drops.load(Ordering::SeqCst), 2);
    }

    #[derive(Clone)]
    struct CloseTrackingSession {
        closes: Arc<AtomicUsize>,
    }

    impl Read for CloseTrackingSession {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for CloseTrackingSession {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ControlSession for CloseTrackingSession {
        fn try_clone_session(&self) -> io::Result<BoxedControlSession> {
            Ok(Box::new(self.clone()))
        }

        fn close_session(&mut self) -> io::Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn reset_session(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn dropping_watch_handle_closes_control_session() {
        let closes = Arc::new(AtomicUsize::new(0));
        let session = CloseTrackingSession {
            closes: Arc::clone(&closes),
        };
        let handle = spawn_watch_thread(Box::new(session));

        drop(handle);

        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }
}
