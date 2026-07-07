use std::io::BufReader;

use anyhow::Result;
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
