use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=resources/LocalSandboxSeaWork.mc");
    println!("cargo:rerun-if-env-changed=LSB_COMPILE_EVENT_MESSAGES");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_MC_PATH");
    println!("cargo:rerun-if-env-changed=LSB_WINDOWS_RC_PATH");

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
