#[cfg(all(windows, feature = "sentry-telemetry"))]
use std::collections::BTreeMap;

use serde::Serialize;

use crate::LEDGER_SCHEMA_VERSION;

pub const COMPONENT: &str = "local-sandbox-service";
pub const SERVICE_NAME: &str = "localsandbox-seawork-service";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommonContext {
    pub component: &'static str,
    pub service: ServiceContext,
    pub build: BuildContext,
    pub runtime: RuntimeContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceContext {
    pub name: &'static str,
    pub version: &'static str,
    pub protocol_version: String,
    pub ledger_schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildContext {
    pub commit: String,
    pub bundle_digest: Option<String>,
    pub installation_channel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeContext {
    pub architecture: &'static str,
    pub cpu_count: usize,
    pub total_physical_memory_bytes: Option<u64>,
    pub machine_name: Option<String>,
    pub windows_version: Option<String>,
    pub windows_edition_code: Option<u32>,
    pub qemu_version: String,
}

impl CommonContext {
    pub fn collect(
        build_commit: impl Into<String>,
        bundle_digest: Option<String>,
        installation_channel: Option<String>,
    ) -> Self {
        Self {
            component: COMPONENT,
            service: ServiceContext {
                name: SERVICE_NAME,
                version: env!("CARGO_PKG_VERSION"),
                protocol_version: format!(
                    "{}.{}",
                    lsb_service_proto::CURRENT.major,
                    lsb_service_proto::CURRENT.minor
                ),
                ledger_schema_version: LEDGER_SCHEMA_VERSION,
            },
            build: BuildContext {
                commit: bounded(build_commit.into(), 128),
                bundle_digest: bundle_digest.map(|value| bounded(value, 256)),
                installation_channel: installation_channel.map(|value| bounded(value, 64)),
            },
            runtime: runtime_context(),
        }
    }

    #[cfg(all(windows, feature = "sentry-telemetry"))]
    pub fn as_contexts(&self) -> BTreeMap<String, serde_json::Value> {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "service".to_string(),
            serde_json::to_value(&self.service).expect("service context is serializable"),
        );
        contexts.insert(
            "build".to_string(),
            serde_json::to_value(&self.build).expect("build context is serializable"),
        );
        contexts.insert(
            "runtime".to_string(),
            serde_json::to_value(&self.runtime).expect("runtime context is serializable"),
        );
        contexts
    }
}

fn runtime_context() -> RuntimeContext {
    let (total_physical_memory_bytes, machine_name, windows_version, windows_edition_code) =
        platform_context();
    RuntimeContext {
        architecture: std::env::consts::ARCH,
        cpu_count: std::thread::available_parallelism().map_or(1, usize::from),
        total_physical_memory_bytes,
        machine_name,
        windows_version,
        windows_edition_code,
        qemu_version: qemu_version(),
    }
}

#[cfg(windows)]
fn qemu_version() -> String {
    bounded(
        lsb_platform::windows_x86_64::host_tools::managed_qemu_package_metadata()
            .qemu_version
            .to_string(),
        64,
    )
}

#[cfg(not(windows))]
fn qemu_version() -> String {
    "unavailable".to_string()
}

#[cfg(windows)]
fn platform_context() -> (Option<u64>, Option<String>, Option<String>, Option<u32>) {
    use windows_sys::Win32::System::SystemInformation::{
        GetProductInfo, GetVersionExW, GlobalMemoryStatusEx, MEMORYSTATUSEX, OSVERSIONINFOW,
    };
    use windows_sys::Win32::System::WindowsProgramming::GetComputerNameW;

    let mut memory = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    let total_memory =
        (unsafe { GlobalMemoryStatusEx(&mut memory) } != 0).then_some(memory.ullTotalPhys);

    let mut hostname = [0u16; 256];
    let mut hostname_len = hostname.len() as u32;
    let machine_name = (unsafe { GetComputerNameW(hostname.as_mut_ptr(), &mut hostname_len) } != 0)
        .then(|| {
            bounded(
                String::from_utf16_lossy(&hostname[..hostname_len as usize]),
                256,
            )
        });

    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    let (windows_version, edition) = if unsafe { GetVersionExW(&mut version) } != 0 {
        let version_text = format!(
            "{}.{}.{}",
            version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber
        );
        let mut product = 0u32;
        let edition = (unsafe {
            GetProductInfo(
                version.dwMajorVersion,
                version.dwMinorVersion,
                0,
                0,
                &mut product,
            )
        } != 0)
            .then_some(product);
        (Some(version_text), edition)
    } else {
        (None, None)
    };
    (total_memory, machine_name, windows_version, edition)
}

#[cfg(not(windows))]
fn platform_context() -> (Option<u64>, Option<String>, Option<String>, Option<u32>) {
    (None, None, None, None)
}

fn bounded(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    while !value.is_char_boundary(max_bytes.min(value.len())) {
        value.pop();
    }
    value.truncate(max_bytes);
    value
}

#[cfg(test)]
mod tests {
    use super::{CommonContext, COMPONENT, SERVICE_NAME};

    #[test]
    fn common_context_is_deterministic_and_bounded() {
        let context = CommonContext::collect(
            "x".repeat(512),
            Some("digest".to_string()),
            Some("internal".to_string()),
        );
        assert_eq!(context.component, COMPONENT);
        assert_eq!(context.service.name, SERVICE_NAME);
        assert_eq!(context.build.commit.len(), 128);

        let first = serde_json::to_string(&context).unwrap();
        let second = serde_json::to_string(&context).unwrap();
        assert_eq!(first, second);
        assert!(first.len() < 2_048);
    }
}
