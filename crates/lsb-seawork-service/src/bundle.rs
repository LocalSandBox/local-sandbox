use std::path::Path;

use anyhow::{bail, Context, Result};
use lsb_seawork_update::{PackagePolicy, PackageVerification};

use crate::{LEDGER_SCHEMA_VERSION, PIPE_NAME, PIPE_SDDL, SERVICE_NAME};

pub const SERVICE_CONFIGURATION_REVISION: u32 = 2;

pub fn verify_adjacent_bundle() -> Result<PackageVerification> {
    let executable = std::env::current_exe().context("resolve service executable")?;
    let bin = executable
        .parent()
        .context("service executable has no bin directory")?;
    if bin.file_name().and_then(|name| name.to_str()) != Some("bin") {
        bail!("service executable is not installed below LocalSandbox/bin");
    }
    let root = bin.parent().context("bundle bin directory has no parent")?;
    verify_bundle_root(root)
}

fn verify_bundle_root(root: &Path) -> Result<PackageVerification> {
    lsb_seawork_update::verify_bundle_root(root, &compiled_policy())
}

fn compiled_policy() -> PackagePolicy<'static> {
    PackagePolicy {
        expected_version: env!("CARGO_PKG_VERSION"),
        supported_protocol: lsb_service_proto::SUPPORTED,
        ledger_writer_schema: LEDGER_SCHEMA_VERSION,
        service_configuration_revision: SERVICE_CONFIGURATION_REVISION,
        service_name: SERVICE_NAME,
        service_display_name: "LocalSandbox for SeaWork",
        service_account: "LocalSystem",
        service_type: "SERVICE_WIN32_OWN_PROCESS",
        pipe_name: PIPE_NAME,
        pipe_sddl: PIPE_SDDL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_policy_tracks_the_running_service_contract() {
        let policy = compiled_policy();
        assert_eq!(policy.expected_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(policy.service_name, SERVICE_NAME);
        assert_eq!(policy.pipe_name, PIPE_NAME);
        assert_eq!(policy.ledger_writer_schema, LEDGER_SCHEMA_VERSION);
        assert_eq!(
            policy.service_configuration_revision,
            SERVICE_CONFIGURATION_REVISION
        );
    }
}
