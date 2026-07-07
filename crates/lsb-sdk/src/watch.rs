use std::io::BufReader;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::sync::mpsc::RecvTimeoutError;
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
    events_rx: mpsc::UnboundedReceiver<Result<WatchEvent>>,
}

impl WatchHandle {
    pub async fn next(&mut self) -> Option<Result<WatchEvent>> {
        self.events_rx.recv().await
    }

    pub fn into_events(self) -> mpsc::UnboundedReceiver<Result<WatchEvent>> {
        self.events_rx
    }

    #[cfg(all(test, target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn try_next(
        &mut self,
    ) -> std::result::Result<Option<Result<WatchEvent>>, mpsc::error::TryRecvError> {
        match self.events_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn spawn_watch_thread(stream: BoxedControlSession) -> WatchHandle {
    let (events_tx, events_rx) = mpsc::unbounded_channel();

    let _ = std::thread::Builder::new()
        .name("lsb-watch".into())
        .spawn(move || {
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

    WatchHandle { events_rx }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) fn spawn_windows_smb_host_watch_thread<R>(
    watch: WindowsHostDirectoryWatch,
    platform_events: std::sync::mpsc::Receiver<
        Result<WindowsHostWatchEvent, WindowsHostWatchError>,
    >,
    guest_root: String,
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
                        let event = WatchEvent {
                            path: join_guest_watch_event_path(&guest_root, &event.relative_path),
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

    WatchHandle { events_rx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::test_support::memory_session_pair;

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
}
