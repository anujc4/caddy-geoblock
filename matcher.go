// Copyright 2024 Anuj Chandra
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddygeoblock

import (
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Matcher{})
}

// Matcher implements a request matcher that matches requests based on
// geographic location and network information from MaxMind databases.
//
// When a request matches (would be blocked by the geo rules), it returns true,
// allowing you to handle matched requests with custom logic such as serving
// a static site or redirecting.
//
// The matcher sets various placeholders with geo information that can be used
// by downstream handlers:
//   - {geoblock.country_code}
//   - {geoblock.country_name}
//   - {geoblock.city_name}
//   - {geoblock.continent_code}
//   - {geoblock.subdivision_code}
//   - {geoblock.asn}
//   - {geoblock.asn_org}
//   - {geoblock.latitude}
//   - {geoblock.longitude}
//   - {geoblock.time_zone}
//   - {geoblock.postal_code}
//   - {geoblock.blocked}
//   - {geoblock.blocked_reason}
type Matcher struct {
	GeoFilterConfig

	filter *GeoFilter
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoblock",
		New: func() caddy.Module { return new(Matcher) },
	}
}

// Provision sets up the matcher.
func (m *Matcher) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Initialize the geo filter
	m.filter = NewGeoFilter(&m.GeoFilterConfig, m.logger)
	if err := m.filter.Provision(ctx); err != nil {
		return err
	}

	return nil
}

// Validate ensures the matcher is properly configured.
func (m *Matcher) Validate() error {
	return m.filter.Validate()
}

// Cleanup releases resources held by the matcher.
func (m *Matcher) Cleanup() error {
	if m.filter != nil {
		return m.filter.Cleanup()
	}
	return nil
}

// MatchWithError returns true if the request matches the geo-blocking criteria
// (i.e., the request would be blocked). It implements caddyhttp.RequestMatcherWithError.
func (m Matcher) MatchWithError(r *http.Request) (bool, error) {
	// Get client IP from Caddy's context
	clientIPStr, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if !ok || clientIPStr == "" {
		m.logger.Warn("failed to get client IP from context")
		return false, nil
	}

	clientIP := ParseIP(clientIPStr)
	if clientIP == nil {
		m.logger.Warn("failed to parse client IP", zap.String("ip", clientIPStr))
		return false, nil
	}

	// Perform the geo filtering check
	result := m.filter.CheckIP(clientIP)

	// Set placeholders with geo data
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	m.setPlaceholders(r, repl, result)

	return result.Blocked, nil
}

// Match returns true if the request matches the geo-blocking criteria.
// Deprecated: Use MatchWithError instead. This method is kept for backward compatibility.
func (m Matcher) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// setPlaceholders sets all geoblock placeholders in the request context.
func (m *Matcher) setPlaceholders(r *http.Request, repl *caddy.Replacer, result FilterResult) {
	// Set vars in request context for use by other handlers
	caddyhttp.SetVar(r.Context(), "geoblock.blocked", strconv.FormatBool(result.Blocked))
	caddyhttp.SetVar(r.Context(), "geoblock.blocked_reason", result.Reason)

	// Also set in replacer for use in templates and messages
	repl.Set("geoblock.blocked", strconv.FormatBool(result.Blocked))
	repl.Set("geoblock.blocked_reason", result.Reason)

	if result.Record == nil {
		m.setEmptyVars(r, repl)
		return
	}

	// Set all geo data in both context vars and replacer
	m.setVar(r, repl, "geoblock.country_code", result.Record.Country.ISOCode)
	m.setVar(r, repl, "geoblock.country_name", result.Record.Country.Name())
	m.setVar(r, repl, "geoblock.city_name", result.Record.City.Name())
	m.setVar(r, repl, "geoblock.continent_code", result.Record.Continent.Code)
	m.setVar(r, repl, "geoblock.continent_name", result.Record.Continent.Name())
	m.setVar(r, repl, "geoblock.subdivision_code", result.Record.SubdivisionCodesString())
	m.setVar(r, repl, "geoblock.subdivision_name", result.Record.SubdivisionNamesString())
	m.setVar(r, repl, "geoblock.asn", strconv.Itoa(result.Record.AutonomousSystemNumber))
	m.setVar(r, repl, "geoblock.asn_org", result.Record.AutonomousSystemOrganization)
	m.setVar(r, repl, "geoblock.latitude", strconv.FormatFloat(result.Record.Location.Latitude, 'f', 6, 64))
	m.setVar(r, repl, "geoblock.longitude", strconv.FormatFloat(result.Record.Location.Longitude, 'f', 6, 64))
	m.setVar(r, repl, "geoblock.time_zone", result.Record.Location.TimeZone)
	m.setVar(r, repl, "geoblock.postal_code", result.Record.Postal.Code)
}

// setVar sets a value in both the request context and replacer.
func (m *Matcher) setVar(r *http.Request, repl *caddy.Replacer, key, value string) {
	caddyhttp.SetVar(r.Context(), key, value)
	repl.Set(key, value)
}

// setEmptyVars sets empty values for all geo placeholders.
func (m *Matcher) setEmptyVars(r *http.Request, repl *caddy.Replacer) {
	keys := []string{
		"geoblock.country_code", "geoblock.country_name", "geoblock.city_name",
		"geoblock.continent_code", "geoblock.continent_name",
		"geoblock.subdivision_code", "geoblock.subdivision_name",
		"geoblock.asn", "geoblock.asn_org",
		"geoblock.latitude", "geoblock.longitude",
		"geoblock.time_zone", "geoblock.postal_code",
	}
	for _, key := range keys {
		caddyhttp.SetVar(r.Context(), key, "")
		repl.Set(key, "")
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	@blocked {
//	    geoblock {
//	        # Database paths (at least one required)
//	        db_path <path>
//	        db_path <path>  # Multiple databases can be specified
//
//	        # Allow lists (only listed values allowed)
//	        allow_countries <codes...>
//	        allow_continents <codes...>
//	        allow_subdivisions <codes...>
//	        allow_cities <names...>
//	        allow_asn <numbers...>
//	        allow_asn_org <names...>
//
//	        # Deny lists (listed values blocked, takes precedence over allow)
//	        deny_countries <codes...>
//	        deny_continents <codes...>
//	        deny_subdivisions <codes...>
//	        deny_cities <names...>
//	        deny_asn <numbers...>
//	        deny_asn_org <names...>
//
//	        # IP range allow/deny (CIDR notation, checked before geo lookup)
//	        allow_ip_ranges <cidrs...>
//	        deny_ip_ranges <cidrs...>
//	    }
//	}
func (m *Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// consume the matcher name
	d.Next()

	// Check if this is block syntax or inline
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "db_path":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DatabasePaths = append(m.DatabasePaths, args...)

		case "allow_countries":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowCountries = append(m.AllowCountries, args...)

		case "deny_countries":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyCountries = append(m.DenyCountries, args...)

		case "allow_continents":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowContinents = append(m.AllowContinents, args...)

		case "deny_continents":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyContinents = append(m.DenyContinents, args...)

		case "allow_subdivisions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowSubdivisions = append(m.AllowSubdivisions, args...)

		case "deny_subdivisions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenySubdivisions = append(m.DenySubdivisions, args...)

		case "allow_cities":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowCities = append(m.AllowCities, args...)

		case "deny_cities":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyCities = append(m.DenyCities, args...)

		case "allow_asn":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowASN = append(m.AllowASN, args...)

		case "deny_asn":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyASN = append(m.DenyASN, args...)

		case "allow_asn_org":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowASNOrg = append(m.AllowASNOrg, args...)

		case "deny_asn_org":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyASNOrg = append(m.DenyASNOrg, args...)

		case "allow_ip_ranges":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.AllowIPRanges = append(m.AllowIPRanges, args...)

		case "deny_ip_ranges":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			m.DenyIPRanges = append(m.DenyIPRanges, args...)

		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*Matcher)(nil)
	_ caddy.Validator                   = (*Matcher)(nil)
	_ caddy.CleanerUpper                = (*Matcher)(nil)
	_ caddyhttp.RequestMatcherWithError = (*Matcher)(nil)
	_ caddyfile.Unmarshaler             = (*Matcher)(nil)
)
