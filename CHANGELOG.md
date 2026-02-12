# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-02-12

### Fixed

- Implement `RequestMatcherWithError` interface to fix deprecation warning with Caddy v2.10+

## [0.1.0] - 2026-02-12

### Added

- Geo-blocking HTTP handler for Caddy v2 (`http.handlers.geoblock`)
- Request matcher for custom routing (`http.matchers.geoblock`)
- Support for MaxMind GeoLite2 and GeoIP2 databases
- Multiple database support (e.g., City + ASN databases together)
- Country-based filtering (allow/deny lists)
- Continent-based filtering (allow/deny lists)
- Subdivision/state filtering (allow/deny lists)
- City-based filtering (allow/deny lists)
- ASN number filtering (allow/deny lists)
- ASN organization filtering with substring matching (allow/deny lists)
- IP range filtering with CIDR notation (allow/deny lists)
- Automatic allow for private and loopback IP addresses
- Configurable blocked response status code and message
- Placeholder support for geo data in responses:
  - `{geoblock.country_code}`, `{geoblock.country_name}`
  - `{geoblock.city_name}`, `{geoblock.continent_code}`
  - `{geoblock.subdivision_code}`, `{geoblock.subdivision_name}`
  - `{geoblock.asn}`, `{geoblock.asn_org}`
  - `{geoblock.latitude}`, `{geoblock.longitude}`
  - `{geoblock.time_zone}`, `{geoblock.postal_code}`
  - `{geoblock.blocked}`, `{geoblock.blocked_reason}`
- Caddyfile directive support
- Database connection pooling across config reloads

### Security

- Updated quic-go to v0.57.0 to address CVE

[Unreleased]: https://github.com/anujc4/caddy-geoblock/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/anujc4/caddy-geoblock/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/anujc4/caddy-geoblock/releases/tag/v0.1.0
