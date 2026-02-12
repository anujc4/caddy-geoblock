# Caddy GeoBlock Module

A Caddy v2 HTTP handler module that blocks or allows requests based on geographic location and network information from MaxMind databases.

## Features

- **Geographic blocking**: Block or allow requests by country, continent, city, or subdivision
- **ASN blocking**: Block or allow requests by Autonomous System Number or organization name
- **IP range filtering**: Allow or deny specific IP ranges (CIDR notation), checked before geo lookup
- **Multiple database support**: Use multiple MaxMind databases together (e.g., GeoLite2-City + GeoLite2-ASN)
- **Placeholders**: Exposes geo data as placeholders for use in responses and logging
- **Private IP handling**: Automatically allows localhost and private IPs
- **Configurable responses**: Custom HTTP status codes and messages for blocked requests

## Installation

Build Caddy with this module using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/anujc4/caddy-geoblock
```

For local development:

```bash
make build
```

## Configuration

### Caddyfile Syntax

```caddyfile
geoblock {
    # Database paths (at least one required)
    db_path <path>
    db_path <path>  # Multiple databases can be specified

    # Allow lists (only listed values allowed)
    allow_countries <codes...>
    allow_continents <codes...>
    allow_subdivisions <codes...>
    allow_cities <names...>
    allow_asn <numbers...>
    allow_asn_org <names...>

    # Deny lists (listed values blocked, takes precedence over allow)
    deny_countries <codes...>
    deny_continents <codes...>
    deny_subdivisions <codes...>
    deny_cities <names...>
    deny_asn <numbers...>
    deny_asn_org <names...>

    # IP range allow/deny (CIDR notation, checked before geo lookup)
    allow_ip_ranges <cidrs...>
    deny_ip_ranges <cidrs...>

    # Response customization
    blocked_status <code>
    blocked_message <message>
}
```

### JSON Configuration

```json
{
    "handler": "geoblock",
    "db_paths": ["/path/to/GeoLite2-City.mmdb", "/path/to/GeoLite2-ASN.mmdb"],
    "deny_countries": ["CN", "RU", "KP"],
    "allow_continents": ["NA", "EU"],
    "deny_asn": ["12345"],
    "allow_ip_ranges": ["10.0.0.0/8"],
    "deny_ip_ranges": ["1.2.3.0/24"],
    "blocked_status_code": 403,
    "blocked_message": "Access denied from {geoblock.country_code}"
}
```

## Examples

### Block specific countries

```caddyfile
:80 {
    geoblock {
        db_path /usr/share/GeoIP/GeoLite2-Country.mmdb
        deny_countries CN RU KP IR
        blocked_message "Access denied"
    }

    respond "Welcome!" 200
}
```

### Allow only specific countries

```caddyfile
:80 {
    geoblock {
        db_path /usr/share/GeoIP/GeoLite2-Country.mmdb
        allow_countries US CA GB DE FR
        blocked_status 451
        blocked_message "Not available in your region"
    }

    file_server
}
```

### Block by ASN with multiple databases

```caddyfile
:80 {
    geoblock {
        db_path /usr/share/GeoIP/GeoLite2-City.mmdb
        db_path /usr/share/GeoIP/GeoLite2-ASN.mmdb

        deny_countries CN RU
        deny_asn 4134 4837  # China Telecom
        deny_asn_org "Bad Hosting"

        blocked_message "Blocked: {geoblock.country_code} / ASN {geoblock.asn}"
    }

    respond "Hello from {geoblock.city_name}, {geoblock.country_code}!" 200
}
```

### IP range based access control

```caddyfile
:80 {
    geoblock {
        db_path /usr/share/GeoIP/GeoLite2-Country.mmdb

        # Allow internal networks
        allow_ip_ranges 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12

        # Block specific external range
        deny_ip_ranges 1.2.3.0/24

        # Then apply geo rules for other IPs
        allow_countries US CA
    }

    respond "OK" 200
}
```

## Placeholders

The module sets the following placeholders that can be used in responses and logging:

| Placeholder | Description |
|-------------|-------------|
| `{geoblock.country_code}` | ISO country code (e.g., "US") |
| `{geoblock.country_name}` | Country name (e.g., "United States") |
| `{geoblock.city_name}` | City name |
| `{geoblock.continent_code}` | Continent code (e.g., "NA") |
| `{geoblock.continent_name}` | Continent name |
| `{geoblock.subdivision_code}` | Subdivision/state code(s) |
| `{geoblock.subdivision_name}` | Subdivision/state name(s) |
| `{geoblock.asn}` | Autonomous System Number |
| `{geoblock.asn_org}` | ASN organization name |
| `{geoblock.latitude}` | Latitude |
| `{geoblock.longitude}` | Longitude |
| `{geoblock.time_zone}` | Time zone |
| `{geoblock.postal_code}` | Postal code |
| `{geoblock.blocked}` | "true" or "false" |
| `{geoblock.blocked_reason}` | Reason for blocking |

## Special Values

- Use `UNK` in allow/deny lists to match unknown or unrecognized values
- Private and loopback IPs (localhost, 10.x.x.x, 192.168.x.x, etc.) are always allowed

## MaxMind Databases

This module requires MaxMind GeoIP2 or GeoLite2 databases:

- **GeoLite2-Country**: Basic country-level data (free)
- **GeoLite2-City**: City-level data including subdivisions and coordinates (free)
- **GeoLite2-ASN**: Autonomous System Number data (free)

Sign up for a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>

## Development

### Prerequisites

- Go 1.21+
- [xcaddy](https://github.com/caddyserver/xcaddy) for building
- [golangci-lint](https://golangci-lint.run/) for linting

### Make Commands

```bash
# Run all tests with race detection
make test

# Build Caddy with the geoblock module
make build

# Run linter
make lint

# Clean build artifacts
make clean
```

### Testing

Tests use MaxMind's freely available test databases included in `testdata/`.

```bash
make test
```

## License

Apache License 2.0
