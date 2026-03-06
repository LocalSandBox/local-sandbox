# Networking

Networking is **off by default**. Pass `--allow-net` to enable it.

## Enabling Network Access

```bash
shuru run --allow-net -- sh -c 'apt-get install -y curl && curl https://example.com'
```

Or set it in `shuru.json`:

```json
{
  "allow_net": true
}
```

## Port Forwarding

Forward host ports to guest ports with `-p HOST:GUEST`:

```bash
# Forward host 8080 to guest 80
shuru run --allow-net -p 8080:80 -- nginx -g 'daemon off;'

# Multiple ports
shuru run --allow-net -p 3000:3000 -p 5432:5432 -- sh -c 'start-services.sh'
```

Access forwarded services at `localhost:HOST_PORT` on the host machine.

Port forwards can also be set in `shuru.json`:

```json
{
  "ports": ["8080:80", "3000:3000"]
}
```

CLI `-p` flags are merged with config ports (not replaced).

## Without Networking

When `--allow-net` is not set, the VM has no network interface. DNS resolution, HTTP requests, and package installs will fail. This is the intended default for maximum isolation.

To install packages, either:
1. Use `--allow-net` during the run
2. Create a checkpoint with packages pre-installed, then run without networking:

```bash
shuru checkpoint create with-tools --allow-net -- apt-get install -y curl jq python3
shuru run --from with-tools -- python3 script.py   # no --allow-net needed
```
