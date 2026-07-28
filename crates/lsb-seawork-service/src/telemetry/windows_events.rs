use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use anyhow::{Context, Result};
use serde::Serialize;
use windows_sys::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
    EvtRenderEventXml, EVT_HANDLE,
};

use super::{Attachment, PreviousRun};

const MAX_EVENTS: usize = 64;
const MAX_SCANNED_EVENTS: usize = 256;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;
const MAX_LOOKBACK_MS: i128 = 24 * 60 * 60 * 1_000;
const HYPERV_CHANNELS: &[&str] = &[
    "Microsoft-Windows-Hyper-V-Hypervisor-Operational",
    "Microsoft-Windows-Hyper-V-Hypervisor-Admin",
    "Microsoft-Windows-Hyper-V-VID-Admin",
];

#[derive(Serialize)]
struct Evidence<'a> {
    schema_version: u32,
    previous_run_id: &'a str,
    previous_started_utc: &'a str,
    captured_utc: String,
    lookback_ms: i128,
    truncated: bool,
    query_errors: Vec<QueryError>,
    events: Vec<Event>,
}

#[derive(Serialize)]
struct QueryError {
    channel: &'static str,
    win32_code: u32,
}

#[derive(Serialize)]
struct Event {
    channel: &'static str,
    xml: String,
}

#[derive(Serialize)]
struct HypervEvidence<'a> {
    schema_version: u32,
    incident_id: &'a str,
    qemu_creation_time_100ns: u64,
    captured_utc: String,
    truncated: bool,
    channels: Vec<HypervChannel>,
    events: Vec<HypervEvent>,
}

#[derive(Serialize)]
struct HypervChannel {
    channel: &'static str,
    scanned_count: usize,
    selected_count: usize,
    query_error: Option<u32>,
    truncated: bool,
}

#[derive(Serialize)]
struct HypervEvent {
    channel: &'static str,
    provider: Option<String>,
    level: Option<String>,
    timestamp_utc: Option<String>,
    record_id: Option<String>,
    rendered_xml: String,
}

struct EventHandle(EVT_HANDLE);

impl Drop for EventHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                EvtClose(self.0);
            }
        }
    }
}

pub(crate) fn capture_termination_evidence(previous: &PreviousRun) -> Result<Attachment> {
    let started = time::OffsetDateTime::parse(
        &previous.started_utc,
        &time::format_description::well_known::Rfc3339,
    )
    .context("parse previous service start for Windows event query")?;
    let now = time::OffsetDateTime::now_utc();
    let elapsed_ms = (now - started).whole_milliseconds().max(0);
    let lookback_ms = (elapsed_ms + 120_000).min(MAX_LOOKBACK_MS);
    let system_query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}] and \
         ((Provider[@Name='Service Control Manager'] and \
         (EventID=7031 or EventID=7034 or EventID=7035 or EventID=7036)) or \
         (Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or \
         (Provider[@Name='EventLog'] and \
         (EventID=6005 or EventID=6006 or EventID=6008)) or \
         (Provider[@Name='User32'] and EventID=1074))]]"
    );
    let application_query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}] and \
         ((Provider[@Name='Application Error'] and EventID=1000) or \
         (Provider[@Name='Windows Error Reporting'] and EventID=1001))]]"
    );

    let mut events = Vec::new();
    let mut query_errors = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    collect_channel(
        "System",
        &system_query,
        &mut events,
        &mut query_errors,
        &mut total_bytes,
        &mut truncated,
    );
    collect_channel(
        "Application",
        &application_query,
        &mut events,
        &mut query_errors,
        &mut total_bytes,
        &mut truncated,
    );

    let mut evidence = Evidence {
        schema_version: 1,
        previous_run_id: &previous.run_id,
        previous_started_utc: &previous.started_utc,
        captured_utc: now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        lookback_ms,
        truncated,
        query_errors,
        events,
    };
    while serde_json::to_vec_pretty(&evidence).is_ok_and(|bytes| bytes.len() > MAX_TOTAL_BYTES) {
        evidence.truncated = true;
        if evidence.events.pop().is_none() {
            anyhow::bail!("Windows termination evidence metadata exceeds compiled bound");
        }
    }
    let directory = previous
        .marker_path
        .parent()
        .context("previous run marker has no snapshot directory")?;
    let path = directory.join("windows-termination-events.json");
    crate::ledger::atomic::write_value(&path, &evidence)
        .context("write bounded Windows termination evidence")?;
    Ok(Attachment {
        path,
        filename: "windows-termination-events.json".to_string(),
        content_type: "application/json",
    })
}

pub(crate) fn capture_hyperv_evidence(
    incident: &lsb_platform::PlatformQemuLiveIncident,
) -> Result<()> {
    let lookback_ms = incident.snapshot_elapsed_ms.saturating_add(30_000);
    let query = format!("*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]");
    let mut events = Vec::new();
    let mut channels = Vec::new();
    let mut total_bytes = 0usize;
    let mut truncated = false;
    for channel in HYPERV_CHANNELS {
        channels.push(collect_hyperv_channel(
            channel,
            &query,
            &mut events,
            &mut total_bytes,
            &mut truncated,
        ));
    }
    let mut evidence = HypervEvidence {
        schema_version: 1,
        incident_id: &incident.incident_id,
        qemu_creation_time_100ns: incident.qemu_creation_time_100ns,
        captured_utc: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        truncated,
        channels,
        events,
    };
    while serde_json::to_vec_pretty(&evidence).is_ok_and(|bytes| bytes.len() > MAX_TOTAL_BYTES) {
        evidence.truncated = true;
        if evidence.events.pop().is_none() {
            anyhow::bail!("Hyper-V evidence metadata exceeds compiled bound");
        }
    }
    crate::ledger::atomic::write_value(
        &incident.artifact_directory.join("hyperv-events.json"),
        &evidence,
    )
    .context("write bounded Hyper-V evidence")
}

fn collect_hyperv_channel(
    channel: &'static str,
    query: &str,
    events: &mut Vec<HypervEvent>,
    total_bytes: &mut usize,
    overall_truncated: &mut bool,
) -> HypervChannel {
    let mut result = HypervChannel {
        channel,
        scanned_count: 0,
        selected_count: 0,
        query_error: None,
        truncated: false,
    };
    let channel_wide = wide(OsStr::new(channel));
    let query_wide = wide(OsStr::new(query));
    let handle = unsafe {
        EvtQuery(
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if handle == 0 {
        result.query_error = Some(last_error_code());
        return result;
    }
    let handle = EventHandle(handle);
    loop {
        if result.scanned_count >= MAX_SCANNED_EVENTS
            || events.len() >= MAX_EVENTS
            || *total_bytes >= MAX_TOTAL_BYTES
        {
            result.truncated = true;
            *overall_truncated = true;
            break;
        }
        let mut raw_event = 0;
        let mut returned = 0;
        if unsafe { EvtNext(handle.0, 1, &mut raw_event, 0, 0, &mut returned) } == 0 {
            let code = last_error_code();
            if code != 259 {
                result.query_error = Some(code);
            }
            break;
        }
        if returned != 1 || raw_event == 0 {
            break;
        }
        result.scanned_count += 1;
        let raw_event = EventHandle(raw_event);
        let Ok(xml) = render_xml(raw_event.0) else {
            continue;
        };
        if total_bytes.saturating_add(xml.len()) > MAX_TOTAL_BYTES {
            result.truncated = true;
            *overall_truncated = true;
            break;
        }
        *total_bytes += xml.len();
        result.selected_count += 1;
        events.push(HypervEvent {
            channel,
            provider: xml_attribute(&xml, "Provider Name"),
            level: xml_element(&xml, "Level"),
            timestamp_utc: xml_attribute(&xml, "TimeCreated SystemTime"),
            record_id: xml_element(&xml, "EventRecordID"),
            rendered_xml: xml,
        });
    }
    result
}

fn xml_element(xml: &str, name: &str) -> Option<String> {
    let start = format!("<{name}>");
    let end = format!("</{name}>");
    let value = xml.split_once(&start)?.1.split_once(&end)?.0;
    Some(value.chars().take(256).collect())
}

fn xml_attribute(xml: &str, marker: &str) -> Option<String> {
    let (element, attribute) = marker.split_once(' ')?;
    let start = xml.find(&format!("<{element} "))?;
    let fragment = &xml[start..xml[start..].find('>')?.saturating_add(start)];
    for quote in ['\'', '"'] {
        let prefix = format!("{attribute}={quote}");
        if let Some(value) = fragment.split_once(&prefix).map(|(_, tail)| tail) {
            return value
                .split_once(quote)
                .map(|(value, _)| value.chars().take(256).collect());
        }
    }
    None
}

fn collect_channel(
    channel: &'static str,
    query: &str,
    events: &mut Vec<Event>,
    query_errors: &mut Vec<QueryError>,
    total_bytes: &mut usize,
    truncated: &mut bool,
) {
    if events.len() >= MAX_EVENTS || *total_bytes >= MAX_TOTAL_BYTES {
        *truncated = true;
        return;
    }
    let channel_wide = wide(OsStr::new(channel));
    let query_wide = wide(OsStr::new(query));
    let query_handle = unsafe {
        EvtQuery(
            0,
            channel_wide.as_ptr(),
            query_wide.as_ptr(),
            EvtQueryChannelPath | EvtQueryReverseDirection,
        )
    };
    if query_handle == 0 {
        query_errors.push(QueryError {
            channel,
            win32_code: last_error_code(),
        });
        return;
    }
    let query_handle = EventHandle(query_handle);
    let mut scanned = 0usize;
    loop {
        if events.len() >= MAX_EVENTS
            || scanned >= MAX_SCANNED_EVENTS
            || *total_bytes >= MAX_TOTAL_BYTES
        {
            *truncated = true;
            break;
        }
        let mut raw_event = 0;
        let mut returned = 0;
        let next = unsafe { EvtNext(query_handle.0, 1, &mut raw_event, 0, 0, &mut returned) };
        if next == 0 {
            let code = last_error_code();
            if code != 259 {
                query_errors.push(QueryError {
                    channel,
                    win32_code: code,
                });
            }
            break;
        }
        if returned != 1 || raw_event == 0 {
            break;
        }
        scanned += 1;
        let raw_event = EventHandle(raw_event);
        let Ok(xml) = render_xml(raw_event.0) else {
            continue;
        };
        if !relevant(channel, &xml) {
            continue;
        }
        let bytes = xml.len();
        if total_bytes.saturating_add(bytes) > MAX_TOTAL_BYTES {
            *truncated = true;
            break;
        }
        *total_bytes += bytes;
        events.push(Event { channel, xml });
    }
}

fn render_xml(event: EVT_HANDLE) -> Result<String> {
    let mut bytes_needed = 0;
    let mut properties = 0;
    unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut bytes_needed,
            &mut properties,
        );
    }
    if bytes_needed == 0 || bytes_needed as usize > MAX_EVENT_BYTES {
        anyhow::bail!("Windows event XML exceeds compiled bound");
    }
    let mut buffer = vec![0u16; (bytes_needed as usize).div_ceil(2)];
    if unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            bytes_needed,
            buffer.as_mut_ptr().cast(),
            &mut bytes_needed,
            &mut properties,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("render Windows event XML");
    }
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(buffer.len());
    Ok(String::from_utf16_lossy(&buffer[..length]))
}

fn relevant(channel: &str, xml: &str) -> bool {
    if channel == "Application" {
        return xml
            .to_ascii_lowercase()
            .contains("localsandbox-seawork-service.exe");
    }
    if xml.contains("Service Control Manager") {
        return xml.contains("LocalSandboxSeaWork") || xml.contains("LocalSandbox for SeaWork");
    }
    true
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn last_error_code() -> u32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, |code| code as u32)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;

    #[test]
    fn captures_bounded_native_event_log_evidence() {
        let root = std::env::temp_dir().join(format!(
            "localsandbox-windows-events-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let marker_path = root.join("run-marker.json");
        let previous = PreviousRun {
            run_id: "0123456789abcdef0123456789abcdef".to_string(),
            started_utc: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            last_updated_utc: "2026-07-27T00:00:00Z".to_string(),
            current_phase: "service.running".to_string(),
            last_completed_boundary: None,
            active_instances: BTreeMap::new(),
            marker_path,
            context_path: root.join("crash-context.json"),
            termination_intent: None,
            termination_intent_path: None,
        };

        let attachment = capture_termination_evidence(&previous).unwrap();
        assert_eq!(attachment.path.parent(), Some(root.as_path()));
        assert_eq!(attachment.filename, "windows-termination-events.json");
        assert_eq!(attachment.content_type, "application/json");
        let bytes = std::fs::read(&attachment.path).unwrap();
        assert!(bytes.len() <= MAX_TOTAL_BYTES);
        let evidence: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(evidence["schema_version"], 1);
        assert_eq!(evidence["previous_run_id"], previous.run_id);
        assert!(evidence["events"].is_array());
        assert!(evidence["query_errors"].is_array());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn captures_all_bounded_hyperv_channels_for_live_incident_window() {
        let root = std::env::temp_dir().join(format!(
            "localsandbox-hyperv-events-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let incident = lsb_platform::PlatformQemuLiveIncident {
            incident_id: "0123456789abcdef0123456789abcdef".to_string(),
            artifact_directory: root.clone(),
            qemu_creation_time_100ns: 42,
            snapshot_elapsed_ms: 1_000,
        };
        capture_hyperv_evidence(&incident).unwrap();
        let bytes = std::fs::read(root.join("hyperv-events.json")).unwrap();
        assert!(bytes.len() <= MAX_TOTAL_BYTES);
        let evidence: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(evidence["incident_id"], incident.incident_id);
        assert_eq!(
            evidence["channels"]
                .as_array()
                .map(Vec::len)
                .unwrap_or_default(),
            HYPERV_CHANNELS.len()
        );
        assert!(evidence["events"]
            .as_array()
            .is_some_and(|events| events.len() <= MAX_EVENTS));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reviewed_hyperv_xml_fields_are_bounded() {
        let xml = r#"<Event><System><Provider Name="Microsoft-Windows-Hyper-V-Hypervisor"/><EventID>1</EventID><Level>2</Level><TimeCreated SystemTime="2026-07-28T00:00:00.000Z"/><EventRecordID>42</EventRecordID></System></Event>"#;
        assert_eq!(
            xml_attribute(xml, "Provider Name").as_deref(),
            Some("Microsoft-Windows-Hyper-V-Hypervisor")
        );
        assert_eq!(xml_element(xml, "Level").as_deref(), Some("2"));
        assert_eq!(
            xml_attribute(xml, "TimeCreated SystemTime").as_deref(),
            Some("2026-07-28T00:00:00.000Z")
        );
        assert_eq!(xml_element(xml, "EventRecordID").as_deref(), Some("42"));
    }

    #[cfg(feature = "qemu-hang-test-hooks")]
    #[test]
    #[ignore = "requires artifacts from the Windows QEMU hang telemetry smoke"]
    fn windows_hyperv_evidence_smoke() {
        let source = std::path::PathBuf::from(
            std::env::var_os("LSB_QEMU_HANG_TEST_SOURCE_ARTIFACT_DIR")
                .expect("LSB_QEMU_HANG_TEST_SOURCE_ARTIFACT_DIR"),
        );
        let output = std::path::PathBuf::from(
            std::env::var_os("LSB_QEMU_HANG_TEST_HYPERV_ARTIFACT_DIR")
                .expect("LSB_QEMU_HANG_TEST_HYPERV_ARTIFACT_DIR"),
        );
        std::fs::create_dir_all(&output).unwrap();
        let hang: Value =
            serde_json::from_slice(&std::fs::read(source.join("qemu-hang.json")).unwrap()).unwrap();
        let incident = lsb_platform::PlatformQemuLiveIncident {
            incident_id: hang["incident_id"].as_str().unwrap().to_string(),
            artifact_directory: output.clone(),
            qemu_creation_time_100ns: hang["process"]["creation_time"].as_u64().unwrap(),
            snapshot_elapsed_ms: hang["elapsed_ms"].as_u64().unwrap(),
        };
        capture_hyperv_evidence(&incident).unwrap();
        let evidence: Value =
            serde_json::from_slice(&std::fs::read(output.join("hyperv-events.json")).unwrap())
                .unwrap();
        assert_eq!(
            evidence["channels"].as_array().map(Vec::len),
            Some(HYPERV_CHANNELS.len())
        );
        assert!(evidence["events"]
            .as_array()
            .is_some_and(|events| events.len() <= MAX_EVENTS));
    }
}
