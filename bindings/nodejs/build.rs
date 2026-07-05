fn main() {
  println!("cargo:rustc-check-cfg=cfg(lsb_nodejs_supported)");

  let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
  let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

  let supported_macos =
    target_os == "macos" && matches!(target_arch.as_str(), "aarch64" | "x86_64");
  let supported_windows = target_os == "windows" && target_arch == "x86_64";

  if supported_macos || supported_windows {
    println!("cargo:rustc-cfg=lsb_nodejs_supported");
  }

  napi_build::setup();
}
