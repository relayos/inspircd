# WEBIRC Metadata Module

The `m_webirc_metadata` module reads WEBIRC flags from web gateways and converts them to IRCv3 metadata keys. This allows web clients to pass arbitrary metadata (e.g., location, connection hash) through the gateway to the IRC server.

## Loading

```xml
<module name="webirc_metadata">
```

This module depends on `ircv3_metadata` for the metadata API and `gateway` for WEBIRC flag handling.

## Configuration

Define which WEBIRC flags should be converted to metadata keys using `<webircmeta>` blocks:

```xml
<webircmeta key="connection/hash">
<webircmeta key="geo/country-code">
<webircmeta key="geo/country">
```

Each `<webircmeta>` block requires a `key` attribute specifying the flag/metadata key name. The same key name is used for both the WEBIRC flag and the resulting IRCv3 metadata.

### Gateway Configuration

The gateway must be configured to trust these flags. Add them to the `trustedflags` attribute:

```xml
<gateway type="webirc"
         mask="127.0.0.1"
         password="secret"
         trustedflags="connection/hash geo/country-code geo/country">
```

Set `trustedflags="*"` to trust all flags (not recommended for production).

## How It Works

1. Web client connects to webircgateway with query params or plugin-set tags
2. webircgateway sends: `WEBIRC pass gw host ip :connection/hash=abc123 location/country-code=US`
3. InspIRCd's `m_gateway` parses flags and fires `OnWebIRCAuth` event
4. This module reads matching flags and sets IRCv3 metadata via `m_ircv3_metadata`
5. Clients with `draft/metadata-2` capability can read the values

## Example Flow

**webircgateway sends:**
```
WEBIRC secretpass kiwiirc gateway.example.com 203.0.113.42 :connection/hash=a1b2c3d4e5f location/country-code=US location/country-name=United\ States
```

**Resulting metadata (visible to clients):**
```
METADATA user connection/hash * :a1b2c3d4e5f
METADATA user location/country-code * :US
METADATA user location/country-name * :United States
```

## Security Considerations

- Only flags listed in `<webircmeta>` blocks are processed
- Gateway must have the flags in `trustedflags` to pass them through
- Metadata keys are registered as `servicesonly`, preventing clients from overwriting them
- Values are cleared on user disconnect

## Common Keys

| Key | Source | Description |
|-----|--------|-------------|
| `connection/hash` | webircgateway-connectionhash plugin | Salted hash of client IP |
| `geo/country-code` | webircgateway-geoip plugin | ISO 3166-1 alpha-2 country code (falls back to `AQ`) |
| `geo/country` | webircgateway-geoip plugin | English country name (falls back to `Antarctica`) |
| `user/gender` | Client query param | User's gender |
| `user/interested-in` | Client query param | User's preference |
