# m_connectionhash_verify

Verifies connection hashes from WEBIRC flags or GECOS JSON to authenticate WebIRC gateway connections. Provides early rejection for anti-abuse protection.

## Description

This module validates that WebIRC gateway connections provide a correct cryptographic hash proving they came through an authorized gateway. Connections with invalid or missing hashes (when required) are rejected early in the connection lifecycle, before full registration completes.

The hash is computed as: `sha256(salt + ":" + client_ip)[:11]` (first 11 hex characters)

## Configuration

```xml
<module name="connectionhash_verify">

<connectionhash
    salt="your-secret-salt-here"
    mode="both"
    key="connection/hash"
    gecoskey="ih"
    reason="Connection verification failed">
```

### Attributes

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| salt | string | *required* | Shared secret used to compute hashes. Must match the gateway's salt. |
| mode | string | "webirc" | Verification mode: `webirc`, `gecos`, or `both` |
| key | string | "connection/hash" | WEBIRC flag key containing the hash |
| gecoskey | string | "ih" | JSON key in GECOS/realname containing the hash |
| reason | string | "Connection verification failed" | Quit message for rejected connections |

### Modes

- **`webirc`** - Check hash from WEBIRC flags only (fastest)
- **`gecos`** - Check hash from GECOS JSON only (for gateways that don't support WEBIRC flags)
- **`both`** - Try WEBIRC flags first, fall back to GECOS (recommended for dual-mode)

## Environment Variables

When using the Docker image with the configuration scripts:

| Variable | Default | Description |
|----------|---------|-------------|
| `INSP_CONNECTIONHASH_SALT` | (empty) | Hash salt - module disabled if empty |
| `INSP_CONNECTIONHASH_MODE` | "webirc" | Verification mode |
| `INSP_CONNECTIONHASH_KEY` | "connection/hash" | WEBIRC flag key |
| `INSP_CONNECTIONHASH_GECOSKEY` | "ih" | GECOS JSON key |
| `INSP_CONNECTIONHASH_REASON` | "Connection verification failed" | Rejection message |

## How It Works

1. **OnWebIRCAuth**: When a WEBIRC command is processed, the module stores the provided hash (if present in flags)
2. **OnUserRegister**: After the client IP has been updated by m_gateway, the module:
   - Computes the expected hash from the (now updated) client IP
   - Compares against the stored WEBIRC hash and/or GECOS JSON hash
   - Rejects the connection if a hash was provided but doesn't match
   - Allows connections without any hash (non-WebIRC clients)

## Gateway Configuration

The WebIRC gateway must send the hash via one or both methods:

### WEBIRC Flags Method
```
WEBIRC <password> <gateway> <hostname> <ip> :connection/hash=<hash> geo/country=US
```

### GECOS JSON Method
The gateway sets the client's realname to JSON containing the hash:
```json
{"ih":"abc12345678","realname":"Original Name"}
```

## Dependencies

- Requires `m_gateway` (for WEBIRC processing)
- Requires `hash/sha256` provider (typically from `m_password_hash`)
- Requires RapidJSON library (for GECOS JSON parsing)

## Example: Dual-Mode Setup

### InspIRCd Configuration
```xml
<connectionhash
    salt="MySecretSalt123"
    mode="both"
    key="connection/hash"
    gecoskey="ih"
    reason="Invalid connection">
```

### Gateway Configuration (webircgateway-connectionhash plugin)
```bash
WEBIRC_CONNECTION_SALT=MySecretSalt123
WEBIRC_CONNECTIONHASH_MODE=both
```

Both must use the **same salt** value.

## Security Considerations

- Keep the salt secret - it should only be known to InspIRCd and authorized gateways
- Use a cryptographically random salt of at least 32 characters
- The hash provides authentication but not encryption - use TLS for the gateway connection
- Connections without any hash are allowed by default (to support direct IRC clients)

## Logging

Debug logging shows verification results:
```
m_connectionhash_verify: WEBIRC hash verified for nick (1.2.3.4)
m_connectionhash_verify: GECOS hash mismatch for nick (1.2.3.4): got=abc expected=xyz
m_connectionhash_verify: Hash verification failed for nick (1.2.3.4) mode=both
```
