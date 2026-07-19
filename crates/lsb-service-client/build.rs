use std::env;

const PUBLISHER_ENV: &str = "SEAWORK_PUBLISHER_SHA256";

fn main() {
    println!("cargo:rerun-if-env-changed={PUBLISHER_ENV}");

    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    let publisher = env::var(PUBLISHER_ENV).unwrap_or_default();
    if !publisher.is_empty()
        && (publisher.len() != 64 || !publisher.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        panic!("{PUBLISHER_ENV} must be one SHA-256 certificate thumbprint");
    }
    if target.contains("windows") && profile == "release" && publisher.is_empty() {
        panic!("Windows release clients require {PUBLISHER_ENV}");
    }
    println!(
        "cargo:rustc-env=LSB_COMPILED_SEAWORK_PUBLISHER_SHA256={}",
        publisher.to_ascii_lowercase()
    );
}
