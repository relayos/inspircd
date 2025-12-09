# Metadata Trigger Module

The `m_metadata_trigger` module triggers actions based on user metadata values. This allows automatic channel joins, mode changes, or notices when users connect with specific metadata (e.g., auto-join country lobbies based on geo/country-code).

## Loading

```xml
<module name="metadata_trigger">
```

This module depends on `ircv3_metadata` for the metadata event API.

## Configuration

Define triggers using `<metadata_trigger>` blocks:

```xml
<metadata_trigger key="geo/country-code" action="join" target="#lobby-$value" trigger="once" delay="2">
<metadata_trigger key="geo/country-code" value="US" action="join" target="#us-users" trigger="once" delay="2">
<metadata_trigger key="verified" value="true" action="mode" target="+V" trigger="always">
<metadata_trigger key="gender" action="notice" target="Welcome! Your profile is set up." trigger="once" delay="3">
```

### Attributes

| Attribute | Required | Default | Description |
|-----------|----------|---------|-------------|
| `key` | Yes | - | Metadata key to match (e.g., `geo/country-code`) |
| `value` | No | (any) | Specific value to match. If omitted, matches any non-empty value |
| `action` | Yes | - | Action to perform: `join`, `mode`, or `notice` |
| `target` | Yes | - | Target for the action. Use `$value` as placeholder for metadata value |
| `trigger` | No | `once` | When to trigger: `once` (only on connect) or `always` (any metadata change) |
| `delay` | No | `0` | Seconds to wait before executing the action |

### Actions

- **join**: Joins the user to a channel. Target is the channel name.
- **mode**: Sets user modes. Target is the mode string (e.g., `+V` or `-i`).
- **notice**: Sends a notice to the user. Target is the notice text.

### Variable Substitution

Use `$value` in the target to substitute the actual metadata value:

```xml
<!-- User with geo/country-code=US joins #lobby-US -->
<metadata_trigger key="geo/country-code" action="join" target="#lobby-$value">

<!-- User with geo/country-code=GB joins #lobby-GB -->
<!-- Same config works for any country code -->
```

## How It Works

1. User connects via WEBIRC gateway with metadata flags
2. `m_webirc_metadata` converts flags to IRCv3 metadata
3. `m_metadata_trigger` receives `OnMetadataChanged` event
4. If user isn't fully connected yet, trigger is queued
5. On `OnPostConnect`, queued triggers are executed
6. If delay > 0, a timer is started

## Example Use Cases

### Country-specific lobbies

```xml
<!-- Auto-join users to #lobby-{country-code} -->
<metadata_trigger key="geo/country-code" action="join" target="#lobby-$value" trigger="once" delay="2">
```

### Regional channels

```xml
<!-- US users join #north-america -->
<metadata_trigger key="geo/country-code" value="US" action="join" target="#north-america" trigger="once">
<metadata_trigger key="geo/country-code" value="CA" action="join" target="#north-america" trigger="once">
<metadata_trigger key="geo/country-code" value="MX" action="join" target="#north-america" trigger="once">
```

### Welcome notice

```xml
<metadata_trigger key="geo/country" action="notice" target="Welcome from $value!" trigger="once" delay="1">
```

### Verified user mode

```xml
<!-- Set +V mode on verified users -->
<metadata_trigger key="account/verified" value="true" action="mode" target="+V" trigger="always">
```

## Security Considerations

- Triggers only fire for metadata keys configured in `<metadata_trigger>` blocks
- The `trigger="once"` option prevents repeated execution on reconnect within the same session
- Use `delay` to ensure the user is fully settled before joining channels
- Metadata keys should be protected by `m_webirc_metadata` (servicesonly) to prevent client spoofing

## Integration with WEBIRC

This module works best with `m_webirc_metadata`. Configure your gateway to pass location data:

```xml
<!-- Gateway config -->
<gateway type="webirc" mask="10.0.0.0/8" password="secret" trustedflags="*">

<!-- Metadata keys to accept -->
<webircmeta key="geo/country-code">
<webircmeta key="geo/country">

<!-- Trigger config -->
<metadata_trigger key="geo/country-code" action="join" target="#lobby-$value" trigger="once" delay="2">
```
