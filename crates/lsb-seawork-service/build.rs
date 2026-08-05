use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=resources/LocalSandboxSeaWork.mc");
    println!("cargo:rerun-if-env-changed=LSB_COMPILE_EVENT_MESSAGES");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_MC_PATH");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_RC_PATH");
    compile_publisher_policy();
    compile_sentry_configuration();

    if std::env::var_os("LSB_COMPILE_EVENT_MESSAGES").is_none() {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        panic!("event messages may be compiled only for a Windows target");
    }

    let mc = required_tool("LSB_WINDOWS_MC_PATH");
    let rc = required_tool("LSB_WINDOWS_RC_PATH");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is unavailable"))
        .join("event-messages");
    std::fs::create_dir_all(&output).expect("create event message output directory");
    let source = Path::new("resources/LocalSandboxSeaWork.mc");

    run(
        Command::new(&mc)
            .arg("-n")
            .arg("-h")
            .arg(&output)
            .arg("-r")
            .arg(&output)
            .arg("-z")
            .arg("LocalSandboxSeaWork")
            .arg(source),
        "mc.exe",
    );
    let resource_script = output.join("LocalSandboxSeaWork.rc");
    if !resource_script.is_file() {
        panic!("mc.exe did not produce {}", resource_script.display());
    }
    let compiled = output.join("LocalSandboxSeaWork.res");
    run(
        Command::new(&rc)
            .arg("/nologo")
            .arg(format!("/fo{}", compiled.display()))
            .arg(&resource_script),
        "rc.exe",
    );
    if !compiled.is_file() {
        panic!("rc.exe did not produce {}", compiled.display());
    }
    println!(
        "cargo:rustc-link-arg-bin=localsandbox-seawork-service={}",
        compiled.display()
    );
}

fn compile_sentry_configuration() {
    const DSN: &str = "LSB_SENTRY_DSN";
    const ENVIRONMENT: &str = "LSB_SENTRY_ENVIRONMENT";
    const SAMPLE_RATE: &str = "LSB_SENTRY_TRACES_SAMPLE_RATE";
    const INCLUDE: &str = "LSB_SENTRY_NATIVE_INCLUDE_DIR";
    const LIBRARY: &str = "LSB_SENTRY_NATIVE_LIBRARY";
    const HANDLER: &str = "LSB_SENTRY_CRASHPAD_HANDLER";
    const WER: &str = "LSB_SENTRY_CRASHPAD_WER";
    for name in [
        DSN,
        ENVIRONMENT,
        SAMPLE_RATE,
        INCLUDE,
        LIBRARY,
        HANDLER,
        WER,
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    if std::env::var_os("CARGO_FEATURE_SENTRY_TELEMETRY").is_none() {
        println!("cargo:rustc-env=LSB_SENTRY_TELEMETRY_ENABLED=0");
        return;
    }

    let dsn = required_non_secret_value(DSN);
    if !(dsn.starts_with("https://") || dsn.starts_with("http://"))
        || dsn.chars().any(char::is_whitespace)
        || dsn.len() > 2_048
    {
        panic!("{DSN} must be one bounded HTTP(S) public Sentry DSN");
    }
    let environment = required_non_secret_value(ENVIRONMENT);
    if environment.len() > 64
        || !environment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        panic!("{ENVIRONMENT} must contain only 1-64 ASCII letters, digits, '.', '_', or '-'");
    }
    let sample_rate = required_non_secret_value(SAMPLE_RATE);
    let parsed_rate = sample_rate
        .parse::<f64>()
        .unwrap_or_else(|_| panic!("{SAMPLE_RATE} must be a number in the inclusive range 0-1"));
    if !parsed_rate.is_finite() || !(0.0..=1.0).contains(&parsed_rate) {
        panic!("{SAMPLE_RATE} must be a number in the inclusive range 0-1");
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let include = required_directory(INCLUDE);
        if !include.join("sentry.h").is_file() {
            panic!("{INCLUDE} must contain sentry.h");
        }
        let library = required_file(LIBRARY);
        if library.extension().and_then(|value| value.to_str()) != Some("lib") {
            panic!("{LIBRARY} must name the prepared static sentry.lib");
        }
        let handler = required_file(HANDLER);
        if handler.file_name().and_then(|value| value.to_str()) != Some("crashpad_handler.exe") {
            panic!("{HANDLER} must name the prepared crashpad_handler.exe");
        }
        let wer = required_file(WER);
        if wer.file_name().and_then(|value| value.to_str()) != Some("crashpad_wer.dll") {
            panic!("{WER} must name the prepared crashpad_wer.dll");
        }
        let install_root = include
            .canonicalize()
            .expect("canonicalize prepared Sentry include directory")
            .parent()
            .expect("prepared Sentry include directory has no parent")
            .to_path_buf();
        for (name, artifact) in [(LIBRARY, &library), (HANDLER, &handler), (WER, &wer)] {
            let artifact_root = artifact
                .canonicalize()
                .unwrap_or_else(|_| panic!("canonicalize {name}"))
                .parent()
                .and_then(std::path::Path::parent)
                .unwrap_or_else(|| panic!("{name} is outside a prepared install tree"))
                .to_path_buf();
            if artifact_root != install_root {
                panic!(
                    "{INCLUDE}, {LIBRARY}, {HANDLER}, and {WER} must come from the same prepared Sentry Native build"
                );
            }
        }
        println!(
            "cargo:rustc-env=LSB_SENTRY_CRASHPAD_HANDLER={}",
            handler.display()
        );
        println!(
            "cargo:rustc-link-search=native={}",
            library
                .parent()
                .expect("native library has no parent")
                .display()
        );
        for library in [
            "sentry",
            "crashpad_client",
            "crashpad_mpack",
            "crashpad_util",
            "crashpad_compat",
            "crashpad_zlib",
            "mini_chromium",
            "dbghelp",
            "shlwapi",
            "version",
            "winhttp",
            "user32",
            "advapi32",
            "kernel32",
            "rpcrt4",
            "powrprof",
            "synchronization",
        ] {
            println!("cargo:rustc-link-lib={library}");
        }
    }

    println!("cargo:rustc-env=LSB_SENTRY_TELEMETRY_ENABLED=1");
    println!("cargo:rustc-env=LSB_SENTRY_DSN={dsn}");
    println!("cargo:rustc-env=LSB_SENTRY_ENVIRONMENT={environment}");
    println!("cargo:rustc-env=LSB_SENTRY_TRACES_SAMPLE_RATE={sample_rate}");
}

fn required_non_secret_value(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"));
    if value.is_empty() {
        panic!("{name} is required");
    }
    value
}

fn required_directory(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name).unwrap_or_else(|| panic!("{name} must name an absolute directory")),
    );
    if !path.is_absolute() || !path.is_dir() {
        panic!("{name} must name an absolute directory");
    }
    path
}

fn required_file(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name).unwrap_or_else(|| panic!("{name} must name an absolute file")),
    );
    if !path.is_absolute() || !path.is_file() {
        panic!("{name} must name an absolute file");
    }
    path
}

fn compile_publisher_policy() {
    const CURRENT: &str = "SEAWORK_PUBLISHER_SHA256";
    const PREVIOUS: &str = "SEAWORK_PUBLISHER_SHA256_PREVIOUS";
    println!("cargo:rerun-if-env-changed={CURRENT}");
    println!("cargo:rerun-if-env-changed={PREVIOUS}");
    let current = std::env::var(CURRENT).unwrap_or_default();
    let previous = std::env::var(PREVIOUS).unwrap_or_default();
    for (name, value) in [(CURRENT, &current), (PREVIOUS, &previous)] {
        if !value.is_empty()
            && (value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            panic!("{name} must be one SHA-256 certificate thumbprint");
        }
    }
    let target = std::env::var("TARGET").unwrap_or_default();
    let profile = std::env::var("PROFILE").unwrap_or_default();
    if target.contains("windows") && profile == "release" && current.is_empty() {
        panic!("Windows release service requires {CURRENT}");
    }
    if !previous.is_empty() && current.is_empty() {
        panic!("{PREVIOUS} requires {CURRENT}");
    }
    if !previous.is_empty() && previous.eq_ignore_ascii_case(&current) {
        panic!("current and previous SeaWork publisher thumbprints must differ");
    }
    let policy = if previous.is_empty() {
        current.to_ascii_lowercase()
    } else {
        format!(
            "{},{}",
            current.to_ascii_lowercase(),
            previous.to_ascii_lowercase()
        )
    };
    println!("cargo:rustc-env=LSB_COMPILED_SEAWORK_PUBLISHERS_SHA256={policy}");
}

fn required_tool(variable: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(variable)
            .unwrap_or_else(|| panic!("{variable} must name an explicit Windows SDK tool")),
    );
    if !path.is_absolute() || !path.is_file() {
        panic!("{variable} must name an absolute regular file");
    }
    path
}

fn run(command: &mut Command, label: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to execute {label}: {error}"));
    if !status.success() {
        panic!("{label} failed with {status}");
    }
}
