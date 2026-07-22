use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=resources/LocalSandboxSeaWork.mc");
    println!("cargo:rerun-if-env-changed=LSB_COMPILE_EVENT_MESSAGES");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_MC_PATH");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_RC_PATH");
    compile_publisher_policy();

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
