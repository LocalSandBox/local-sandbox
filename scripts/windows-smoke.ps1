$ErrorActionPreference = "Stop"

Write-Host "== Windows LSB smoke test =="

cargo run -p lsb-cli -- --help

# Add this once the Windows VM backend can boot:
# cargo run -p lsb-cli -- run -- echo hello-from-windows

# Later:
# cargo run -p lsb-cli -- run --cpus 2 --memory 2048 -- echo resource-test
# cargo run -p lsb-cli -- run --port 8080:8080 -- your-port-forward-test
