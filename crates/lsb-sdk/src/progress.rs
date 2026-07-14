use std::io::{self, Read};

const REPORT_INTERVAL_BYTES: u64 = 1024 * 1024;

/// A distinct stage of sandbox runtime initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxInitProgressPhase {
    Checking,
    ApplyingFixes,
    DownloadingHostTools,
    VerifyingHostTools,
    ExtractingHostTools,
    ValidatingHostTools,
    DownloadingAndExtractingRuntimeAssets,
    PinningRuntimeAssets,
}

/// An observational update emitted while sandbox runtime initialization runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxInitProgress {
    pub phase: SandboxInitProgressPhase,
    /// Compressed response bytes consumed. Present only for download phases.
    pub downloaded_bytes: Option<u64>,
    /// A positive Content-Length supplied by the server, when available.
    pub total_bytes: Option<u64>,
}

impl SandboxInitProgress {
    pub(crate) fn phase(phase: SandboxInitProgressPhase) -> Self {
        Self {
            phase,
            downloaded_bytes: None,
            total_bytes: None,
        }
    }

    fn download(
        phase: SandboxInitProgressPhase,
        downloaded_bytes: u64,
        total_bytes: Option<u64>,
    ) -> Self {
        Self {
            phase,
            downloaded_bytes: Some(downloaded_bytes),
            total_bytes,
        }
    }
}

/// Receives progress synchronously on the initialization worker thread.
pub trait SandboxInitProgressReporter {
    fn report(&self, progress: SandboxInitProgress);
}

impl<F> SandboxInitProgressReporter for F
where
    F: Fn(SandboxInitProgress),
{
    fn report(&self, progress: SandboxInitProgress) {
        self(progress);
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NoopProgressReporter;

impl SandboxInitProgressReporter for NoopProgressReporter {
    fn report(&self, _progress: SandboxInitProgress) {}
}

/// Counts compressed bytes actually consumed from a response body.
pub(crate) struct ProgressReader<'a, R> {
    inner: R,
    phase: SandboxInitProgressPhase,
    total_bytes: Option<u64>,
    bytes_read: u64,
    last_reported_interval: u64,
    eof_reported: bool,
    reporter: &'a dyn SandboxInitProgressReporter,
}

impl<'a, R> ProgressReader<'a, R> {
    pub(crate) fn new(
        inner: R,
        phase: SandboxInitProgressPhase,
        total_bytes: Option<u64>,
        reporter: &'a dyn SandboxInitProgressReporter,
    ) -> Self {
        let total_bytes = total_bytes.filter(|total| *total > 0);
        reporter.report(SandboxInitProgress::download(phase, 0, total_bytes));
        Self {
            inner,
            phase,
            total_bytes,
            bytes_read: 0,
            last_reported_interval: 0,
            eof_reported: false,
            reporter,
        }
    }

    fn report_download(&self) {
        self.reporter.report(SandboxInitProgress::download(
            self.phase,
            self.bytes_read,
            self.total_bytes,
        ));
    }

    pub(crate) fn finish(&mut self) {
        if !self.eof_reported {
            self.eof_reported = true;
            self.report_download();
        }
    }
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read == 0 {
            self.finish();
            return Ok(0);
        }

        self.bytes_read += read as u64;
        let current_interval = self.bytes_read / REPORT_INTERVAL_BYTES;
        if current_interval > self.last_reported_interval {
            self.last_reported_interval = current_interval;
            // A known total must not look complete until the reader has observed EOF.
            if self.total_bytes.is_none_or(|total| self.bytes_read < total) {
                self.report_download();
            }
        }

        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::{Cursor, Error, ErrorKind};

    use super::*;

    const PHASE: SandboxInitProgressPhase =
        SandboxInitProgressPhase::DownloadingAndExtractingRuntimeAssets;

    fn read_events(
        bytes: Vec<u8>,
        total: Option<u64>,
        read_buffer_size: usize,
    ) -> Vec<SandboxInitProgress> {
        let events = RefCell::new(Vec::new());
        let reporter = |event| events.borrow_mut().push(event);
        let mut reader = ProgressReader::new(Cursor::new(bytes), PHASE, total, &reporter);
        let mut buffer = vec![0; read_buffer_size];
        while reader.read(&mut buffer).expect("read fixture") != 0 {}
        drop(reader);
        events.into_inner()
    }

    fn counts(events: &[SandboxInitProgress]) -> Vec<u64> {
        events
            .iter()
            .map(|event| event.downloaded_bytes.expect("download count"))
            .collect()
    }

    #[test]
    fn smaller_than_one_mib_reports_zero_and_eof() {
        let events = read_events(vec![0; 10], Some(10), 4);
        assert_eq!(counts(&events), vec![0, 10]);
        assert!(events.iter().all(|event| event.total_bytes == Some(10)));
    }

    #[test]
    fn exactly_one_mib_does_not_report_completion_before_eof() {
        let size = REPORT_INTERVAL_BYTES as usize;
        let events = read_events(vec![0; size], Some(REPORT_INTERVAL_BYTES), size);
        assert_eq!(counts(&events), vec![0, REPORT_INTERVAL_BYTES]);
    }

    #[test]
    fn large_read_crossing_multiple_intervals_is_throttled() {
        let size = (REPORT_INTERVAL_BYTES * 3 + 17) as usize;
        let events = read_events(vec![0; size], None, size);
        assert_eq!(counts(&events), vec![0, size as u64, size as u64]);
    }

    #[test]
    fn empty_input_reports_initial_zero_and_eof_zero() {
        let events = read_events(Vec::new(), Some(0), 8);
        assert_eq!(counts(&events), vec![0, 0]);
        assert!(events.iter().all(|event| event.total_bytes.is_none()));
    }

    #[test]
    fn counts_are_monotonic_and_never_exceed_consumed_bytes() {
        let size = (REPORT_INTERVAL_BYTES * 2 + 9) as usize;
        let events = read_events(vec![0; size], None, 300_000);
        let counts = counts(&events);
        assert!(counts.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(counts.iter().all(|count| *count <= size as u64));
        assert_eq!(counts.last(), Some(&(size as u64)));
        assert!(events.iter().all(|event| event.total_bytes.is_none()));
    }

    struct ErrorReader {
        returned_bytes: bool,
    }

    impl Read for ErrorReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.returned_bytes {
                self.returned_bytes = true;
                buffer[..4].copy_from_slice(b"data");
                return Ok(4);
            }
            Err(Error::new(ErrorKind::Other, "injected read failure"))
        }
    }

    #[test]
    fn read_error_does_not_emit_a_false_eof_event() {
        let events = RefCell::new(Vec::new());
        let reporter = |event| events.borrow_mut().push(event);
        let mut reader = ProgressReader::new(
            ErrorReader {
                returned_bytes: false,
            },
            PHASE,
            None,
            &reporter,
        );
        let error = std::io::copy(&mut reader, &mut std::io::sink()).expect_err("read must fail");
        assert_eq!(error.kind(), ErrorKind::Other);
        drop(reader);
        assert_eq!(counts(&events.into_inner()), vec![0]);
    }
}
