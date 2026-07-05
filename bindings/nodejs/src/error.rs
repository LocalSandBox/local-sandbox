use napi::{Error, Status};

// Non-macOS builds compile enough of the package to install and report a clear
// runtime error, but they do not link lsb_sdk or boot VMs.
#[cfg(not(lsb_nodejs_supported))]
pub(crate) fn unsupported_platform_error() -> Error {
  Error::new(
    Status::GenericFailure,
    "lsb native bindings support macOS on arm64/x64 and Windows 11 x64 through the win32-x64-msvc package. Unsupported hosts should install only the root package metadata or fail with a missing native package such as @local-sandbox/lsb-nodejs-win32-x64-msvc / lsb-nodejs.win32-x64-msvc.node.".to_string(),
  )
}

#[cfg(lsb_nodejs_supported)]
pub(crate) fn to_napi_error(error: anyhow::Error) -> Error {
  let message = error
    .chain()
    .map(ToString::to_string)
    .collect::<Vec<_>>()
    .join(": ");
  Error::new(Status::GenericFailure, message)
}
