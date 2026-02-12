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
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("geoblock", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("geoblock", httpcaddyfile.Before, "basicauth")
}

// parseCaddyfile unmarshals tokens from h into a new Handler.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	geoblock {
//	    # Database paths (at least one required)
//	    db_path <path>
//	    db_path <path>  # Multiple databases can be specified
//
//	    # Allow lists (only listed values allowed)
//	    allow_countries <codes...>
//	    allow_continents <codes...>
//	    allow_subdivisions <codes...>
//	    allow_cities <names...>
//	    allow_asn <numbers...>
//	    allow_asn_org <names...>
//
//	    # Deny lists (listed values blocked, takes precedence over allow)
//	    deny_countries <codes...>
//	    deny_continents <codes...>
//	    deny_subdivisions <codes...>
//	    deny_cities <names...>
//	    deny_asn <numbers...>
//	    deny_asn_org <names...>
//
//	    # IP range allow/deny (CIDR notation, checked before geo lookup)
//	    allow_ip_ranges <cidrs...>
//	    deny_ip_ranges <cidrs...>
//
//	    # Response customization
//	    blocked_status <code>
//	    blocked_message <message>
//	}
//
// Example:
//
//	geoblock {
//	    db_path /usr/share/GeoIP/GeoLite2-City.mmdb
//	    db_path /usr/share/GeoIP/GeoLite2-ASN.mmdb
//
//	    deny_countries CN RU KP
//	    allow_continents NA EU
//
//	    allow_ip_ranges 10.0.0.0/8 192.168.0.0/16
//	    deny_ip_ranges 1.2.3.0/24
//
//	    blocked_status 403
//	    blocked_message "Access denied from {geoblock.country_code}"
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for d.NextBlock(0) {
		switch d.Val() {
		case "db_path":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DatabasePaths = append(h.DatabasePaths, args...)

		case "allow_countries":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowCountries = append(h.AllowCountries, args...)

		case "deny_countries":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyCountries = append(h.DenyCountries, args...)

		case "allow_continents":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowContinents = append(h.AllowContinents, args...)

		case "deny_continents":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyContinents = append(h.DenyContinents, args...)

		case "allow_subdivisions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowSubdivisions = append(h.AllowSubdivisions, args...)

		case "deny_subdivisions":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenySubdivisions = append(h.DenySubdivisions, args...)

		case "allow_cities":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowCities = append(h.AllowCities, args...)

		case "deny_cities":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyCities = append(h.DenyCities, args...)

		case "allow_asn":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowASN = append(h.AllowASN, args...)

		case "deny_asn":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyASN = append(h.DenyASN, args...)

		case "allow_asn_org":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowASNOrg = append(h.AllowASNOrg, args...)

		case "deny_asn_org":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyASNOrg = append(h.DenyASNOrg, args...)

		case "allow_ip_ranges":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.AllowIPRanges = append(h.AllowIPRanges, args...)

		case "deny_ip_ranges":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			h.DenyIPRanges = append(h.DenyIPRanges, args...)

		case "blocked_status":
			if !d.NextArg() {
				return d.ArgErr()
			}
			status, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid status code %q: %v", d.Val(), err)
			}
			h.BlockedStatusCode = status

		case "blocked_message":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.BlockedMessage = d.Val()
			// Allow multi-word messages by consuming remaining args
			for d.NextArg() {
				h.BlockedMessage += " " + d.Val()
			}

		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}

	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Handler)(nil)
