$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB e2e test =="

cargo test --workspace --locked

# Future full suite:
# - boot VM
# - exec command
# - stream stdout/stderr
# - read/write files
# - mount source tree
# - port forwarding
# - no-network egress test
# - allow-net/proxy test
# - checkpoint save/restore
