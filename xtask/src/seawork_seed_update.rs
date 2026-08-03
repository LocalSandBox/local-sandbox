use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    InitializeBaseline,
    SeedCandidate,
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    mode: Mode,
    archive: PathBuf,
    bundle: PathBuf,
    committed: PathBuf,
    publisher_subject: String,
    publisher_sha256: String,
    transaction_id: String,
    request: Option<PathBuf>,
    helper: Option<PathBuf>,
    final_version_root: Option<String>,
    created_utc: Option<String>,
    release_id: Option<u64>,
    asset_url: Option<String>,
}

pub fn run(args: &[String]) -> Result<()> {
    let options = parse(args)?;
    #[cfg(windows)]
    return run_windows(options);
    #[cfg(not(windows))]
    {
        let _ = options;
        bail!("seed-update-candidate is supported only on Windows")
    }
}

fn parse(args: &[String]) -> Result<Options> {
    let Some(mode) = args.first() else {
        bail!("seed-update-candidate requires initialize-baseline or seed-candidate");
    };
    let mode = match mode.as_str() {
        "initialize-baseline" => Mode::InitializeBaseline,
        "seed-candidate" => Mode::SeedCandidate,
        other => bail!("unknown seed-update-candidate mode: {other}"),
    };
    let mut values = BTreeMap::<String, String>::new();
    let mut index = 1;
    while index < args.len() {
        let key = &args[index];
        if !key.starts_with("--") || index + 1 >= args.len() {
            bail!("seed-update-candidate options must be --name value pairs");
        }
        if values
            .insert(key.clone(), args[index + 1].clone())
            .is_some()
        {
            bail!("duplicate seed-update-candidate option: {key}");
        }
        index += 2;
    }
    let archive = PathBuf::from(take(&mut values, "--archive")?);
    let bundle = PathBuf::from(take(&mut values, "--bundle")?);
    let committed = PathBuf::from(take(&mut values, "--committed")?);
    let publisher_subject = take(&mut values, "--publisher-subject")?;
    let publisher_sha256 = take(&mut values, "--publisher-sha256")?;
    let transaction_id = take(&mut values, "--transaction-id")?;
    let request = values.remove("--request").map(PathBuf::from);
    let helper = values.remove("--helper").map(PathBuf::from);
    let final_version_root = values.remove("--final-version-root");
    let created_utc = values.remove("--created-utc");
    let release_id = values
        .remove("--release-id")
        .map(|value| value.parse::<u64>().context("release ID is not an integer"))
        .transpose()?;
    let asset_url = values.remove("--asset-url");
    if let Some(name) = values.keys().next() {
        bail!("unknown seed-update-candidate option: {name}");
    }
    let candidate_values = [
        request.is_some(),
        helper.is_some(),
        final_version_root.is_some(),
        created_utc.is_some(),
        release_id.is_some(),
        asset_url.is_some(),
    ];
    if (mode == Mode::SeedCandidate && candidate_values.iter().any(|present| !present))
        || (mode == Mode::InitializeBaseline && candidate_values.iter().any(|present| *present))
    {
        bail!("candidate-only options must all be supplied only for seed-candidate");
    }
    Ok(Options {
        mode,
        archive,
        bundle,
        committed,
        publisher_subject,
        publisher_sha256,
        transaction_id,
        request,
        helper,
        final_version_root,
        created_utc,
        release_id,
        asset_url,
    })
}

fn take(values: &mut BTreeMap<String, String>, name: &str) -> Result<String> {
    values
        .remove(name)
        .with_context(|| format!("missing seed-update-candidate option: {name}"))
}

#[cfg(windows)]
fn run_windows(options: Options) -> Result<()> {
    use std::fs;

    use lsb_seawork_update::{
        load_json, verify_bundle_root, verify_windows_directory_protection, verify_windows_package,
        write_json_atomic, CommittedState, CommittedStateEnvelope, PackagePolicy,
        PreinstallRequest, PreinstallRequestEnvelope, ReleaseCandidate,
    };
    use lsb_service_proto::{PIPE_NAME, SERVICE_NAME, SUPPORTED};
    use sha2::{Digest, Sha256};

    const PIPE_SDDL: &str =
        "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)(A;;0x00000002;;;IU)S:(ML;;NW;;;ME)";

    let archive_size = fs::metadata(&options.archive)
        .context("read candidate archive metadata")?
        .len();
    let archive_sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&options.archive).context("read candidate archive")?)
    );
    let version = read_bundle_version(&options.bundle)?;
    let policy = PackagePolicy {
        expected_version: &version,
        supported_protocol: SUPPORTED,
        ledger_writer_schema: 1,
        service_configuration_revision: 3,
        service_name: SERVICE_NAME,
        service_display_name: "LocalSandbox for SeaWork",
        service_account: "LocalSystem",
        service_type: "SERVICE_WIN32_OWN_PROCESS",
        pipe_name: PIPE_NAME,
        pipe_sddl: PIPE_SDDL,
    };
    let verification = verify_bundle_root(&options.bundle, &policy)?;
    if verification.publisher.subject != options.publisher_subject
        || !verification
            .publisher
            .sha256_thumbprint
            .eq_ignore_ascii_case(&options.publisher_sha256)
    {
        bail!("verified bundle publisher differs from the descriptor binding");
    }
    verify_windows_directory_protection(&options.bundle)?;
    verify_windows_package(
        &options.bundle,
        &verification,
        std::slice::from_ref(&options.publisher_sha256),
    )?;
    if options.mode == Mode::SeedCandidate {
        verify_installed_helper(
            options.helper.as_ref().expect("validated candidate option"),
            &options.publisher_sha256,
            verification.required_helper_protocol,
        )?;
    }
    let identity = verification.bundle_identity(&archive_sha256)?;
    match options.mode {
        Mode::InitializeBaseline => {
            let state = CommittedStateEnvelope::new(CommittedState {
                highest_committed_version: identity.version.clone(),
                current: identity,
                previous_last_known_good: None,
                helper_protocol: verification.required_helper_protocol,
                last_completed_transaction_id: options.transaction_id,
            })?;
            write_json_atomic(&options.committed, &state)?;
        }
        Mode::SeedCandidate => {
            let committed: CommittedStateEnvelope = load_json(&options.committed)?;
            committed.validate()?;
            let request = PreinstallRequestEnvelope::new(PreinstallRequest {
                request_id: options.transaction_id,
                created_utc: options.created_utc.expect("validated candidate option"),
                candidate: ReleaseCandidate {
                    release_id: options.release_id.expect("validated candidate option"),
                    version: version.clone(),
                    prerelease: version.contains('-'),
                    asset_name: options
                        .archive
                        .file_name()
                        .and_then(|name| name.to_str())
                        .context("candidate archive name is not Unicode")?
                        .to_owned(),
                    asset_url: options.asset_url.expect("validated candidate option"),
                    asset_size: archive_size,
                    archive_sha256,
                },
                old_bundle_identity: committed.committed.current,
                target_bundle_identity: identity,
                staged_root: path_string(&options.bundle)?,
                final_version_root: options
                    .final_version_root
                    .expect("validated candidate option"),
                helper_protocol: verification.required_helper_protocol,
                timeline: Vec::new(),
            })?;
            write_json_atomic(
                options
                    .request
                    .as_ref()
                    .expect("validated candidate option"),
                &request,
            )?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn verify_installed_helper(
    path: &std::path::Path,
    publisher_sha256: &str,
    required_protocol: lsb_seawork_update::HelperProtocol,
) -> Result<()> {
    use std::process::Command;

    use lsb_seawork_update::{
        validate_helper_install_output, verify_windows_directory_protection,
        verify_windows_file_publisher,
    };
    use windows_service::service::{ServiceAccess, ServiceType};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    const HELPER_SERVICE_NAME: &str = "LocalSandboxSeaWorkUpdater";
    let updater = path.parent().context("installed helper has no parent")?;
    let product = updater
        .parent()
        .context("updater directory has no parent")?;
    verify_windows_directory_protection(product)
        .context("verify helper product root protection")?;
    verify_windows_directory_protection(updater).context("verify helper directory protection")?;
    verify_windows_file_publisher(path, &[publisher_sha256.to_owned()])
        .context("verify installed helper publisher")?;
    let output = Command::new(path)
        .args(["--verify-install", "--json"])
        .output()
        .context("run installed helper verification")?;
    if !output.status.success() {
        bail!(
            "installed helper verification failed with {}",
            output.status
        );
    }
    validate_helper_install_output(&output.stdout, HELPER_SERVICE_NAME, required_protocol)
        .context("validate installed helper protocol")?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(HELPER_SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    let config = service.query_config()?;
    let expected = format!("\"{}\" --service", path_string(path)?);
    if config.service_type != ServiceType::OWN_PROCESS
        || config.executable_path.as_os_str() != std::ffi::OsStr::new(&expected)
        || config
            .account_name
            .as_deref()
            .and_then(std::ffi::OsStr::to_str)
            .is_none_or(|account| !account.eq_ignore_ascii_case("LocalSystem"))
    {
        bail!(
            "installed helper SCM configuration differs: path={:?}, account={:?}, type={:?}",
            config.executable_path,
            config.account_name,
            config.service_type
        );
    }
    Ok(())
}

#[cfg(windows)]
fn read_bundle_version(bundle: &std::path::Path) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        service_version: String,
    }
    let bytes = std::fs::read(bundle.join("manifests").join("bundle.json"))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    Ok(manifest.service_version)
}

#[cfg(windows)]
fn path_string(path: &std::path::Path) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .context("Windows path is not Unicode")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common(mode: &str) -> Vec<String> {
        vec![
            mode.to_owned(),
            "--archive".to_owned(),
            "candidate.zip".to_owned(),
            "--bundle".to_owned(),
            r"C:\stage\LocalSandbox".to_owned(),
            "--committed".to_owned(),
            r"C:\state\committed.json".to_owned(),
            "--publisher-subject".to_owned(),
            "CN=SeaWork, O=Sea".to_owned(),
            "--publisher-sha256".to_owned(),
            "a".repeat(64),
            "--transaction-id".to_owned(),
            "b".repeat(32),
        ]
    }

    #[test]
    fn baseline_rejects_candidate_only_options() {
        let mut args = common("initialize-baseline");
        args.extend(["--request".to_owned(), "request.json".to_owned()]);
        assert!(parse(&args).is_err());
    }

    #[test]
    fn candidate_requires_complete_request_binding() {
        let mut args = common("seed-candidate");
        for pair in [
            ["--request", r"C:\state\request.json"],
            [
                "--helper",
                r"C:\Program Files\SeaWork\LocalSandbox\updater\localsandbox-seawork-updater.exe",
            ],
            [
                "--final-version-root",
                r"C:\Program Files\SeaWork\LocalSandbox\versions\0.5.6",
            ],
            ["--created-utc", "2026-08-04T00:00:00Z"],
            ["--release-id", "1"],
            [
                "--asset-url",
                "https://github.com/LocalSandBox/local-sandbox/releases/download/v0.5.6/lsb-seawork-service-v0.5.6-windows-x86_64.zip",
            ],
        ] {
            args.extend(pair.map(str::to_owned));
        }
        assert_eq!(parse(&args).unwrap().mode, Mode::SeedCandidate);
    }
}
