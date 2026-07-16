# Project Config (lsb.json)

Place `lsb.json` in the project root (or pass `--config <path>`). All fields are optional.

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cpus` | number | 2 | Number of CPU cores |
| `memory` | number | 2048 | Memory in MB |
| `disk_size` | number | 4096 | Disk size in MB |
| `allow_net` | boolean | false | Enable networking |
| `ports` | string[] | [] | Port forwards, `"HOST:GUEST"` format |
| `mounts` | string[] | [] | Directory mounts, `"HOST:GUEST"` format |
| `command` | string[] | ["/bin/sh"] | Default command to run |
| `secrets` | object | {} | Secrets to inject via proxy (see below) |
| `network` | object | {} | Network access and HTTPS interception policy (see below) |

## Resolution Order

CLI flags take priority over config values. Config values take priority over hardcoded defaults.

```
CLI flag > lsb.json > default
```

For example, `lsb run --cpus 4` with `{"cpus": 2}` in lsb.json uses 4 CPUs.

## Secrets

Secrets let the guest use API keys without exposing the real values. The guest receives a random placeholder token; the proxy substitutes the real value only on HTTPS requests to allowed hosts.

```json
{
  "allow_net": true,
  "secrets": {
    "API_KEY": {
      "value": "sk-your-openai-key",
      "hosts": ["api.openai.com"]
    }
  }
}
```

- `value`: literal secret value held on the host
- `hosts`: domains where the proxy will substitute the placeholder with the real value

The guest sees `$API_KEY=lsb_tok_...`. The real secret never enters the VM.

## Network Policy

Restrict which domains the guest can reach:

```json
{
  "allow_net": true,
  "network": {
    "allow": ["api.openai.com", "registry.npmjs.org", "*.github.com"]
  }
}
```

- Empty or absent `allow` list means all domains are allowed.
- Supports wildcards: `*.example.com` matches `api.example.com` but not `example.com`.
- DNS queries for blocked domains return REFUSED.

## HTTPS Request Headers

Set a caller-supplied `User-Agent` or another safe end-to-end header on
interceptable HTTPS requests:

```json
{
  "allow_net": true,
  "network": {
    "https_interception": {
      "enabled": true,
      "request_headers": [
        {
          "name": "User-Agent",
          "value": "my-sandbox-agent/1.0",
          "hosts": {
            "allow": ["api.example.com", "*.internal.example.com"],
            "deny": ["billing.internal.example.com"]
          }
        }
      ]
    }
  }
}
```

- `enabled` defaults to `false`; enabling it with no rules is invalid.
- A rule without `hosts` is global. With `allow`, a match is required. With
  `deny`, a match excludes the destination. Deny wins when both match.
- Scopes use normalized TLS SNI, not the HTTP `Host` header. Exact and
  `*.example.com` matches are case-insensitive and ignore a trailing dot.
- Explicit empty allow or deny arrays are invalid.
- Existing header instances are removed case-insensitively and one configured
  value is inserted on every HTTP/1.1 request.
- Values may be sensitive. Prefer allow lists instead of global credential
  headers.
- Routing/framing/hop-by-hop fields cannot be configured. Limits are 64 rules,
  128 bytes per name, 8 KiB per value, and 64 KiB total.
- The feature is limited to HTTP/1.1 over TCP port 443 with visible TLS SNI.
  Pinned certificates, mutual TLS, private trust stores, HTTP/2, HTTP/3, and
  QUIC are unsupported.
- Secret replacement in a fixed-length body changes that request to chunked
  HTTP/1.1 framing. Origins that reject chunked request bodies may be
  incompatible with body substitution.

## Example

```json
{
  "cpus": 4,
  "memory": 4096,
  "disk_size": 8192,
  "allow_net": true,
  "ports": ["3000:3000", "8080:80"],
  "mounts": [".:/workspace"],
  "command": ["/bin/sh", "-c", "cd /workspace && sh"],
  "secrets": {
    "API_KEY": {
      "value": "sk-your-openai-key",
      "hosts": ["api.openai.com"]
    }
  },
  "network": {
    "allow": ["api.openai.com", "registry.npmjs.org"]
  }
}
```

With this config, `lsb run` boots a VM that can only reach `api.openai.com` and `registry.npmjs.org`, with the OpenAI API key injected securely via the proxy.
