use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::config::QemuQmpEndpoint;
use super::hang::{QemuQmpQuery, QemuQmpSnapshot};

const QMP_QUERIES: &[&str] = &[
    "query-status",
    "query-cpus-fast",
    "query-block",
    "query-iothreads",
];
const MAX_QMP_LINE_BYTES: usize = 32 * 1024;
const MAX_QMP_MESSAGES_PER_REQUEST: usize = 32;
const MAX_QMP_RESPONSE_BYTES: usize = 16 * 1024;
const QMP_CONNECT_DEADLINE: Duration = Duration::from_secs(2);
const QMP_CAPTURE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QmpEndpoint {
    pipe_name: String,
    pipe_path: PathBuf,
}

impl QmpEndpoint {
    pub(crate) fn for_incident(incident_id: &str) -> io::Result<Self> {
        if incident_id.len() != 32
            || !incident_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QMP incident ID must be 32 lowercase hexadecimal characters",
            ));
        }
        let pipe_name = format!("lsb-{incident_id}-qmp");
        Ok(Self {
            pipe_path: PathBuf::from(format!(r"\\.\pipe\{pipe_name}")),
            pipe_name,
        })
    }

    pub(crate) fn qemu_config(&self) -> QemuQmpEndpoint {
        QemuQmpEndpoint::named_pipe(self.pipe_name.clone())
    }

    #[cfg(test)]
    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) fn capture(&self, timeline_elapsed: Duration) -> QemuQmpSnapshot {
        capture_endpoint(&self.pipe_path, timeline_elapsed)
    }
}

#[cfg(windows)]
fn capture_endpoint(path: &Path, timeline_elapsed: Duration) -> QemuQmpSnapshot {
    use std::sync::mpsc;

    let stream = match open_with_deadline(path, QMP_CONNECT_DEADLINE) {
        Ok(stream) => stream,
        Err(error) => {
            return QemuQmpSnapshot {
                error: Some(bounded_error(&error.to_string())),
                ..QemuQmpSnapshot::default()
            };
        }
    };
    let cancellation = stream.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = run_protocol(stream, timeline_elapsed);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(QMP_CAPTURE_DEADLINE) {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(error)) => QemuQmpSnapshot {
            connected: true,
            error: Some(bounded_error(&error.to_string())),
            ..QemuQmpSnapshot::default()
        },
        Err(_) => {
            let _ = cancellation.close();
            QemuQmpSnapshot {
                connected: true,
                error: Some("QMP capture exceeded its fixed deadline".to_string()),
                ..QemuQmpSnapshot::default()
            }
        }
    }
}

#[cfg(windows)]
fn open_with_deadline(
    path: &Path,
    timeout: Duration,
) -> io::Result<crate::windows_named_pipe::WindowsNamedPipeStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match crate::windows_named_pipe::WindowsNamedPipeStream::open(path) {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(error.raw_os_error(), Some(2 | 231)) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(windows))]
fn capture_endpoint(_path: &Path, _timeline_elapsed: Duration) -> QemuQmpSnapshot {
    QemuQmpSnapshot {
        error: Some("QMP named pipes are available only on Windows".to_string()),
        ..QemuQmpSnapshot::default()
    }
}

fn run_protocol<S>(mut stream: S, timeline_elapsed: Duration) -> io::Result<QemuQmpSnapshot>
where
    S: Read + Write,
{
    let capture_started_at = Instant::now();
    let greeting = read_json_line(&mut stream)?;
    if greeting.get("QMP").is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "QMP greeting is missing the QMP object",
        ));
    }
    send_request(&mut stream, "qmp_capabilities", "capabilities")?;
    read_response(&mut stream, "capabilities")?;

    let mut snapshot = QemuQmpSnapshot {
        connected: true,
        responsive: true,
        ..QemuQmpSnapshot::default()
    };
    for &name in QMP_QUERIES {
        let start = timeline_elapsed
            .saturating_add(capture_started_at.elapsed())
            .as_millis();
        let id = format!("lsb-{name}");
        let result =
            send_request(&mut stream, name, &id).and_then(|()| read_response(&mut stream, &id));
        let end = timeline_elapsed
            .saturating_add(capture_started_at.elapsed())
            .as_millis();
        match result {
            Ok(response) => snapshot.queries.push(QemuQmpQuery {
                request_name: name.to_string(),
                start_monotonic_ms: start,
                end_monotonic_ms: end,
                status: "success".to_string(),
                response: Some(sanitize_response(response)),
                error: None,
            }),
            Err(error) => {
                snapshot.responsive = false;
                snapshot.queries.push(QemuQmpQuery {
                    request_name: name.to_string(),
                    start_monotonic_ms: start,
                    end_monotonic_ms: end,
                    status: "failure".to_string(),
                    response: None,
                    error: Some(bounded_error(&error.to_string())),
                });
                break;
            }
        }
    }
    Ok(snapshot)
}

fn send_request(stream: &mut impl Write, execute: &str, id: &str) -> io::Result<()> {
    let mut request =
        serde_json::to_vec(&json!({"execute": execute, "id": id})).map_err(io::Error::other)?;
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request)?;
    stream.flush()
}

fn read_response(stream: &mut impl Read, expected_id: &str) -> io::Result<Value> {
    for _ in 0..MAX_QMP_MESSAGES_PER_REQUEST {
        let value = read_json_line(stream)?;
        if value.get("id").and_then(Value::as_str) == Some(expected_id) {
            if let Some(error) = value.get("error") {
                return Err(io::Error::other(format!(
                    "QMP returned {}",
                    bounded_error(&error.to_string())
                )));
            }
            return value.get("return").cloned().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "QMP response omitted return")
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "QMP response message bound exceeded",
    ))
}

fn read_json_line(stream: &mut impl Read) -> io::Result<Value> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if bytes.len() >= MAX_QMP_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QMP line exceeds its fixed bound",
            ));
        }
        match stream.read(&mut byte)? {
            0 if bytes.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "QMP channel closed",
                ));
            }
            0 => break,
            _ if byte[0] == b'\n' => break,
            _ if byte[0] == b'\r' => {}
            _ => bytes.push(byte[0]),
        }
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn sanitize_response(mut value: Value) -> Value {
    sanitize_value(&mut value);
    if serde_json::to_vec(&value).map_or(true, |encoded| encoded.len() > MAX_QMP_RESPONSE_BYTES) {
        json!({"truncated": true})
    } else {
        value
    }
}

fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(text) if looks_path_like(text) => {
            *text = "<redacted-path>".to_string();
        }
        Value::Array(values) => values.iter_mut().for_each(sanitize_value),
        Value::Object(values) => values.values_mut().for_each(sanitize_value),
        _ => {}
    }
}

fn looks_path_like(value: &str) -> bool {
    value.contains('\\')
        || value.starts_with('/')
        || value.as_bytes().get(1) == Some(&b':')
        || value.starts_with("pipe:")
}

fn bounded_error(value: &str) -> String {
    value.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptedStream {
        reads: VecDeque<u8>,
        writes: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(lines: &[Value]) -> Self {
            let reads = lines
                .iter()
                .flat_map(|line| {
                    let mut encoded = serde_json::to_vec(line).unwrap();
                    encoded.push(b'\n');
                    encoded
                })
                .collect();
            Self {
                reads,
                writes: Vec::new(),
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let Some(byte) = self.reads.pop_front() else {
                return Ok(0);
            };
            buffer[0] = byte;
            Ok(1)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.writes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn endpoint_is_unpredictable_private_and_validated() {
        let endpoint = QmpEndpoint::for_incident("0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(
            endpoint.pipe_name(),
            "lsb-0123456789abcdef0123456789abcdef-qmp"
        );
        assert!(QmpEndpoint::for_incident("../caller-selected").is_err());
        assert!(QmpEndpoint::for_incident("ABCDEF0123456789ABCDEF0123456789").is_err());
    }

    #[test]
    fn successful_protocol_is_bounded_and_redacts_paths() {
        let mut lines = vec![
            json!({"QMP": {"version": {"qemu": {"major": 11}}}}),
            json!({"return": {}, "id": "capabilities"}),
        ];
        for name in QMP_QUERIES {
            lines.push(json!({
                "return": {"status": "running", "filename": r"C:\secret\root.qcow2"},
                "id": format!("lsb-{name}")
            }));
        }
        let stream = ScriptedStream::new(&lines);
        let snapshot = run_protocol(stream, Duration::ZERO).unwrap();
        assert!(snapshot.connected);
        assert!(snapshot.responsive);
        assert_eq!(snapshot.queries.len(), QMP_QUERIES.len());
        assert!(snapshot
            .queries
            .iter()
            .all(|query| query.status == "success"));
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.contains("secret"));
        assert!(encoded.contains("<redacted-path>"));
    }

    #[test]
    fn malformed_and_oversized_lines_fail_closed() {
        let mut malformed = ScriptedStream {
            reads: b"not-json\n".iter().copied().collect(),
            writes: Vec::new(),
        };
        assert_eq!(
            read_json_line(&mut malformed).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut oversized = ScriptedStream {
            reads: std::iter::repeat_n(b'x', MAX_QMP_LINE_BYTES + 1).collect(),
            writes: Vec::new(),
        };
        assert_eq!(
            read_json_line(&mut oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
