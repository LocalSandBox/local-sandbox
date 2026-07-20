use std::env;

const PUBLISHER_ENV: &str = "SEAWORK_PUBLISHER_SHA256";
const PREVIOUS_PUBLISHER_ENV: &str = "SEAWORK_PUBLISHER_SHA256_PREVIOUS";

fn main() {
    println!("cargo:rerun-if-env-changed={PUBLISHER_ENV}");
    println!("cargo:rerun-if-env-changed={PREVIOUS_PUBLISHER_ENV}");

    let target = env::var("TARGET").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    let publisher = env::var(PUBLISHER_ENV).unwrap_or_default();
    let previous = env::var(PREVIOUS_PUBLISHER_ENV).unwrap_or_default();
    validate_optional_thumbprint(PUBLISHER_ENV, &publisher);
    validate_optional_thumbprint(PREVIOUS_PUBLISHER_ENV, &previous);
    if target.contains("windows") && profile == "release" && publisher.is_empty() {
        panic!("Windows release clients require {PUBLISHER_ENV}");
    }
    if !previous.is_empty() && publisher.is_empty() {
        panic!("{PREVIOUS_PUBLISHER_ENV} requires {PUBLISHER_ENV}");
    }
    if !previous.is_empty() && previous.eq_ignore_ascii_case(&publisher) {
        panic!("current and previous SeaWork publisher thumbprints must differ");
    }
    let policy = if previous.is_empty() {
        publisher.to_ascii_lowercase()
    } else {
        format!(
            "{},{}",
            publisher.to_ascii_lowercase(),
            previous.to_ascii_lowercase()
        )
    };
    println!("cargo:rustc-env=LSB_COMPILED_SEAWORK_PUBLISHERS_SHA256={policy}");
}

fn validate_optional_thumbprint(name: &str, value: &str) {
    if !value.is_empty()
        && (value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        panic!("{name} must be one SHA-256 certificate thumbprint");
    }
}
