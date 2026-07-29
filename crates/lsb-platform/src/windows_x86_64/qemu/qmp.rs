use std::io::{self, Read, Write};
#[cfg(windows)]
use std::net::TcpStream;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{Arc, Mutex};
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
const QMP_STARTUP_CONNECT_DEADLINE: Duration = Duration::from_secs(30);
const QMP_STARTUP_PROTOCOL_DEADLINE: Duration = Duration::from_secs(15);
const QMP_CAPTURE_DEADLINE: Duration = Duration::from_secs(5);
const QMP_QUIT_DEADLINE: Duration = Duration::from_secs(2);

#[cfg(windows)]
type QmpStream = TcpStream;

#[derive(Debug, Clone)]
pub(crate) struct QmpEndpoint {
    port: u16,
    listener: Arc<Mutex<Option<TcpListener>>>,
    #[cfg(windows)]
    stream: Arc<Mutex<Option<QmpStream>>>,
}

impl PartialEq for QmpEndpoint {
    fn eq(&self, other: &Self) -> bool {
        self.port == other.port
    }
}

impl Eq for QmpEndpoint {}

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
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        Ok(Self {
            port,
            listener: Arc::new(Mutex::new(Some(listener))),
            #[cfg(windows)]
            stream: Arc::new(Mutex::new(None)),
        })
    }

    pub(crate) fn qemu_config(&self) -> QemuQmpEndpoint {
        QemuQmpEndpoint::loopback_tcp(self.port)
    }

    #[cfg(test)]
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn capture(&self, timeline_elapsed: Duration) -> QemuQmpSnapshot {
        let (snapshot, _retained_stream) =
            capture_endpoint(self.take_connected_stream(), timeline_elapsed);
        #[cfg(windows)]
        if let Some(stream) = _retained_stream {
            self.restore_connected_stream(stream);
        }
        snapshot
    }

    pub(crate) fn request_quit(&self) -> io::Result<()> {
        let (result, _retained_stream) = request_quit_endpoint(self.take_connected_stream()?);
        #[cfg(windows)]
        if let Some(stream) = _retained_stream {
            self.restore_connected_stream(stream);
        }
        result
    }

    #[cfg(windows)]
    pub(crate) fn connect(&self) -> io::Result<()> {
        use std::sync::mpsc;

        // The listener is reserved before QEMU starts and accepts exactly one
        // loopback client. QEMU was launched with `-S`, so its vCPUs remain
        // stopped while the greeting, capabilities, and acknowledged `cont`
        // exchange completes.
        let listener = self
            .listener
            .lock()
            .map_err(|_| io::Error::other("QMP listener lock was poisoned"))?
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "QMP listener is closed"))?;
        let stream = accept_with_deadline(listener, QMP_STARTUP_CONNECT_DEADLINE)?;
        let deadline = Instant::now() + QMP_STARTUP_PROTOCOL_DEADLINE;
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = negotiate_and_resume(stream);
            let _ = sender.send(result);
        });
        let stream = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            Ok(result) => {
                let _ = worker.join();
                result?
            }
            Err(_) => {
                cancel_synchronous_worker(&worker);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QMP startup negotiation exceeded its fixed deadline",
                ));
            }
        };
        *self
            .stream
            .lock()
            .map_err(|_| io::Error::other("QMP connection lock was poisoned"))? = Some(stream);
        Ok(())
    }

    #[cfg(not(windows))]
    pub(crate) fn connect(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QMP loopback transport is available only on Windows",
        ))
    }

    #[cfg(windows)]
    fn take_connected_stream(&self) -> io::Result<QmpStream> {
        self.stream
            .lock()
            .map_err(|_| io::Error::other("QMP connection lock was poisoned"))?
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "QMP is not connected"))
    }

    #[cfg(windows)]
    fn restore_connected_stream(&self, stream: QmpStream) {
        if let Ok(mut current) = self.stream.lock() {
            if current.is_none() {
                *current = Some(stream);
            }
        }
    }

    #[cfg(not(windows))]
    fn take_connected_stream(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QMP loopback transport is available only on Windows",
        ))
    }
}

#[cfg(windows)]
fn request_quit_endpoint(stream: QmpStream) -> (io::Result<()>, Option<QmpStream>) {
    use std::sync::mpsc;

    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut stream = stream;
        let result = run_connected_quit_protocol(&mut stream);
        let _ = sender.send((result, stream));
    });
    match receiver.recv_timeout(QMP_QUIT_DEADLINE) {
        Ok((result, stream)) => {
            let _ = worker.join();
            (result, Some(stream))
        }
        Err(_) => {
            cancel_synchronous_worker(&worker);
            (
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "QMP quit exceeded its fixed deadline",
                )),
                None,
            )
        }
    }
}

#[cfg(not(windows))]
fn request_quit_endpoint(_stream: ()) -> (io::Result<()>, Option<()>) {
    (
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "QMP loopback transport is available only on Windows",
        )),
        None,
    )
}

#[cfg(windows)]
fn capture_endpoint(
    stream: io::Result<QmpStream>,
    timeline_elapsed: Duration,
) -> (QemuQmpSnapshot, Option<QmpStream>) {
    use std::sync::mpsc;

    let stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            return (
                QemuQmpSnapshot {
                    error: Some(bounded_error(&error.to_string())),
                    ..QemuQmpSnapshot::default()
                },
                None,
            );
        }
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut stream = stream;
        let result = run_connected_protocol(&mut stream, timeline_elapsed);
        let _ = sender.send((result, stream));
    });
    match receiver.recv_timeout(QMP_CAPTURE_DEADLINE) {
        Ok((Ok(snapshot), stream)) => {
            let _ = worker.join();
            (snapshot, Some(stream))
        }
        Ok((Err(error), stream)) => {
            let _ = worker.join();
            (
                QemuQmpSnapshot {
                    connected: true,
                    error: Some(bounded_error(&error.to_string())),
                    ..QemuQmpSnapshot::default()
                },
                Some(stream),
            )
        }
        Err(_) => {
            cancel_synchronous_worker(&worker);
            (
                QemuQmpSnapshot {
                    connected: true,
                    error: Some("QMP capture exceeded its fixed deadline".to_string()),
                    ..QemuQmpSnapshot::default()
                },
                None,
            )
        }
    }
}

#[cfg(windows)]
fn accept_with_deadline(listener: TcpListener, timeout: Duration) -> io::Result<QmpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, peer)) if peer.ip().is_loopback() => {
                // Windows inherits the listener's nonblocking mode on accepted
                // sockets. QMP uses bounded synchronous workers, so restore
                // blocking mode before protocol negotiation.
                stream.set_nonblocking(false)?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Ok((_stream, _peer)) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "QMP client did not connect from loopback",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "QMP client did not connect before the fixed startup deadline",
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(windows)]
fn cancel_synchronous_worker(worker: &std::thread::JoinHandle<()>) {
    use std::os::windows::io::AsRawHandle;

    // SAFETY: JoinHandle exposes the live OS thread handle for this worker.
    // CancelSynchronousIo is best-effort and targets only pending synchronous
    // I/O issued by that thread.
    unsafe {
        windows_sys::Win32::System::IO::CancelSynchronousIo(
            worker.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
        );
    }
}

#[cfg(not(windows))]
fn capture_endpoint(
    _stream: io::Result<()>,
    _timeline_elapsed: Duration,
) -> (QemuQmpSnapshot, Option<()>) {
    (
        QemuQmpSnapshot {
            error: Some("QMP loopback transport is available only on Windows".to_string()),
            ..QemuQmpSnapshot::default()
        },
        None,
    )
}

#[cfg(test)]
fn run_protocol<S>(mut stream: S, timeline_elapsed: Duration) -> io::Result<QemuQmpSnapshot>
where
    S: Read + Write,
{
    stream = negotiate_and_resume(stream)?;
    run_connected_protocol(stream, timeline_elapsed)
}

fn run_connected_protocol<S>(stream: S, timeline_elapsed: Duration) -> io::Result<QemuQmpSnapshot>
where
    S: Read + Write,
{
    run_queries(stream, timeline_elapsed)
}

fn negotiate_and_resume<S>(mut stream: S) -> io::Result<S>
where
    S: Read + Write,
{
    read_greeting(&mut stream)?;
    send_capabilities_request(&mut stream)?;
    require_success_response(&mut stream, "capabilities", "QMP capabilities")?;
    send_request(&mut stream, "cont", "cont")?;
    require_success_response(&mut stream, "cont", "QMP cont")?;
    Ok(stream)
}

fn send_capabilities_request(stream: &mut impl Write) -> io::Result<()> {
    send_request(stream, "qmp_capabilities", "capabilities")?;
    Ok(())
}

fn read_greeting(mut stream: impl Read) -> io::Result<()> {
    for _ in 0..MAX_QMP_MESSAGES_PER_REQUEST {
        let value = read_json_line(&mut stream)?;
        if value.get("QMP").is_some() {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "QMP greeting message bound exceeded",
    ))
}

fn require_success_response(
    stream: &mut impl Read,
    expected_id: &str,
    operation: &str,
) -> io::Result<()> {
    match read_response(stream, expected_id)? {
        QmpResponse::Success(_) => Ok(()),
        QmpResponse::CommandError => {
            Err(io::Error::other(format!("{operation} returned an error")))
        }
    }
}

fn run_queries<S>(mut stream: S, timeline_elapsed: Duration) -> io::Result<QemuQmpSnapshot>
where
    S: Read + Write,
{
    let capture_started_at = Instant::now();
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
            Ok(QmpResponse::Success(response)) => snapshot.queries.push(QemuQmpQuery {
                request_name: name.to_string(),
                start_monotonic_ms: start,
                end_monotonic_ms: end,
                status: "success".to_string(),
                response: Some(sanitize_response(response)),
                error: None,
            }),
            Ok(QmpResponse::CommandError) => snapshot.queries.push(QemuQmpQuery {
                request_name: name.to_string(),
                start_monotonic_ms: start,
                end_monotonic_ms: end,
                status: "failure".to_string(),
                response: None,
                error: Some("QMP returned an error".to_string()),
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

#[cfg(test)]
fn run_quit_protocol<S>(mut stream: S) -> io::Result<()>
where
    S: Read + Write,
{
    stream = negotiate_and_resume(stream)?;
    run_connected_quit_protocol(stream)
}

fn run_connected_quit_protocol<S>(mut stream: S) -> io::Result<()>
where
    S: Read + Write,
{
    // QEMU may close the pipe as soon as quit is accepted, so successful delivery
    // of the bounded command is the acknowledgement used by the shutdown waiter.
    send_request(&mut stream, "quit", "quit")
}

fn send_request(stream: &mut impl Write, execute: &str, id: &str) -> io::Result<()> {
    let mut request =
        serde_json::to_vec(&json!({"execute": execute, "id": id})).map_err(io::Error::other)?;
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request)?;
    stream.flush()
}

#[derive(Debug, PartialEq)]
enum QmpResponse {
    Success(Value),
    CommandError,
}

fn read_response(stream: &mut impl Read, expected_id: &str) -> io::Result<QmpResponse> {
    for _ in 0..MAX_QMP_MESSAGES_PER_REQUEST {
        let value = read_json_line(stream)?;
        if value.get("id").and_then(Value::as_str) == Some(expected_id) {
            if value.get("error").is_some() {
                // QMP error objects may echo image paths or backend details. The four
                // reviewed queries need only a stable failure category; raw error
                // payloads must never enter the diagnostic archive.
                return Ok(QmpResponse::CommandError);
            }
            return value
                .get("return")
                .cloned()
                .map(QmpResponse::Success)
                .ok_or_else(|| {
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
    fn endpoint_reserves_an_ephemeral_loopback_listener_and_validates_identity() {
        let endpoint = QmpEndpoint::for_incident("0123456789abcdef0123456789abcdef").unwrap();
        assert_ne!(endpoint.port(), 0);
        assert_eq!(
            endpoint.qemu_config(),
            QemuQmpEndpoint::loopback_tcp(endpoint.port())
        );
        assert!(QmpEndpoint::for_incident("../caller-selected").is_err());
        assert!(QmpEndpoint::for_incident("ABCDEF0123456789ABCDEF0123456789").is_err());
    }

    #[test]
    fn distinct_endpoints_reserve_distinct_ports() {
        let first = QmpEndpoint::for_incident("0123456789abcdef0123456789abcdef").unwrap();
        let second = QmpEndpoint::for_incident("fedcba9876543210fedcba9876543210").unwrap();

        assert_ne!(first.port(), second.port());
    }

    #[test]
    fn successful_protocol_is_bounded_and_redacts_paths() {
        let mut lines = vec![
            json!({"QMP": {"version": {"qemu": {"major": 11}}}}),
            json!({"return": {}, "id": "capabilities"}),
            json!({"return": {}, "id": "cont"}),
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
    fn connected_protocol_uses_the_initialized_monitor_without_renegotiating() {
        let lines = QMP_QUERIES
            .iter()
            .map(|name| {
                json!({
                    "return": {"status": "running"},
                    "id": format!("lsb-{name}")
                })
            })
            .collect::<Vec<_>>();
        let mut stream = ScriptedStream::new(&lines);
        let snapshot = run_connected_protocol(&mut stream, Duration::ZERO).unwrap();
        assert!(snapshot.connected);
        assert!(snapshot.responsive);
        assert_eq!(snapshot.queries.len(), QMP_QUERIES.len());
        let writes = String::from_utf8(stream.writes).unwrap();
        assert!(!writes.contains(r#""execute":"qmp_capabilities""#));
        assert!(!writes.contains(r#""execute":"cont""#));
        assert!(writes.contains(r#""execute":"query-status""#));
    }

    #[test]
    fn startup_protocol_negotiates_resumes_then_requests_shutdown() {
        let stream = ScriptedStream::new(&[
            json!({"QMP": {"version": {"qemu": {"major": 11}}}}),
            json!({"return": {}, "id": "capabilities"}),
            json!({"return": {}, "id": "cont"}),
        ]);
        let mut inspect = stream;
        run_quit_protocol(&mut inspect).unwrap();
        let writes = String::from_utf8(inspect.writes).unwrap();
        let capabilities = writes.find(r#""execute":"qmp_capabilities""#).unwrap();
        let resume = writes.find(r#""execute":"cont""#).unwrap();
        let quit = writes.find(r#""execute":"quit""#).unwrap();
        assert!(capabilities < resume);
        assert!(resume < quit);
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

    #[test]
    fn qmp_error_objects_do_not_expose_arbitrary_details() {
        let mut stream = ScriptedStream::new(&[json!({
            "error": {
                "class": "GenericError",
                "desc": r"Could not open C:\secret\root.qcow2"
            },
            "id": "query"
        })]);

        let response = read_response(&mut stream, "query").unwrap();

        assert_eq!(response, QmpResponse::CommandError);
        assert!(!format!("{response:?}").contains("secret"));
    }

    #[test]
    fn command_errors_do_not_prevent_the_remaining_reviewed_queries() {
        let mut lines = vec![
            json!({"QMP": {"version": {"qemu": {"major": 11}}}}),
            json!({"return": {}, "id": "capabilities"}),
            json!({"return": {}, "id": "cont"}),
            json!({
                "error": {
                    "class": "GenericError",
                    "desc": r"Could not open C:\secret\root.qcow2"
                },
                "id": format!("lsb-{}", QMP_QUERIES[0])
            }),
        ];
        for name in &QMP_QUERIES[1..] {
            lines.push(json!({
                "return": {"status": "running"},
                "id": format!("lsb-{name}")
            }));
        }

        let snapshot = run_protocol(ScriptedStream::new(&lines), Duration::ZERO).unwrap();

        assert!(snapshot.connected);
        assert!(snapshot.responsive);
        assert_eq!(snapshot.queries.len(), QMP_QUERIES.len());
        assert_eq!(snapshot.queries[0].status, "failure");
        assert_eq!(
            snapshot.queries[0].error.as_deref(),
            Some("QMP returned an error")
        );
        assert!(snapshot.queries[1..]
            .iter()
            .all(|query| query.status == "success"));
        assert!(!serde_json::to_string(&snapshot).unwrap().contains("secret"));
    }
}
