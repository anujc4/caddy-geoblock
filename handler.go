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
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements geolocation-based request blocking for Caddy.
//
// It looks up the client's IP address in MaxMind databases and blocks
// or allows requests based on geographic and network criteria.
//
// When a request is blocked, an HTTP error with status 403 (or configured status)
// is returned. This error can be handled using Caddy's error handling routes.
//
// The handler sets various placeholders with geo information that can be used
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
type Handler struct {
	// DatabasePaths specifies paths to MaxMind database files.
	// Multiple databases can be specified to combine data (e.g., GeoLite2-City + GeoLite2-ASN).
	// At least one database path is required.
	DatabasePaths []string `json:"db_paths,omitempty"`

	// Allow lists - if specified, only these values are allowed.
	// Use "UNK" to match unknown/unrecognized values.
	AllowCountries    []string `json:"allow_countries,omitempty"`
	AllowContinents   []string `json:"allow_continents,omitempty"`
	AllowSubdivisions []string `json:"allow_subdivisions,omitempty"`
	AllowCities       []string `json:"allow_cities,omitempty"`
	AllowASN          []string `json:"allow_asn,omitempty"`
	AllowASNOrg       []string `json:"allow_asn_org,omitempty"`

	// Deny lists - if specified, these values are blocked.
	// Deny takes precedence over allow when both are specified.
	// Use "UNK" to match unknown/unrecognized values.
	DenyCountries    []string `json:"deny_countries,omitempty"`
	DenyContinents   []string `json:"deny_continents,omitempty"`
	DenySubdivisions []string `json:"deny_subdivisions,omitempty"`
	DenyCities       []string `json:"deny_cities,omitempty"`
	DenyASN          []string `json:"deny_asn,omitempty"`
	DenyASNOrg       []string `json:"deny_asn_org,omitempty"`

	// IP range allow/deny lists (CIDR notation).
	// These are checked before geo lookup and can bypass it entirely.
	AllowIPRanges []string `json:"allow_ip_ranges,omitempty"`
	DenyIPRanges  []string `json:"deny_ip_ranges,omitempty"`

	// BlockedStatusCode is the HTTP status code to return when a request is blocked.
	// Default: 403 (Forbidden)
	BlockedStatusCode int `json:"blocked_status_code,omitempty"`

	// BlockedMessage is the message to include in the error response.
	// Supports placeholders like {geoblock.country_code}.
	// Default: "Access denied"
	BlockedMessage string `json:"blocked_message,omitempty"`

	// Internal fields
	dbManager      *DatabaseManager
	ipRangeChecker *IPRangeChecker
	logger         *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.geoblock",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()

	// Set defaults
	if h.BlockedStatusCode == 0 {
		h.BlockedStatusCode = http.StatusForbidden
	}
	if h.BlockedMessage == "" {
		h.BlockedMessage = "Access denied"
	}

	// Initialize database manager
	h.dbManager = NewDatabaseManager()
	for _, dbPath := range h.DatabasePaths {
		if err := h.dbManager.LoadDatabase(dbPath); err != nil {
			return fmt.Errorf("failed to load database %s: %w", dbPath, err)
		}
	}

	// Initialize IP range checker
	var err error
	h.ipRangeChecker, err = NewIPRangeChecker(h.AllowIPRanges, h.DenyIPRanges)
	if err != nil {
		return fmt.Errorf("failed to initialize IP range checker: %w", err)
	}

	return nil
}

// Validate ensures the handler is properly configured.
func (h *Handler) Validate() error {
	if len(h.DatabasePaths) == 0 {
		return fmt.Errorf("at least one database path is required (db_paths)")
	}

	// Zero is allowed (will use default), but if set, must be valid
	if h.BlockedStatusCode != 0 && (h.BlockedStatusCode < 100 || h.BlockedStatusCode > 599) {
		return fmt.Errorf("blocked_status_code must be a valid HTTP status code (100-599)")
	}

	return nil
}

// Cleanup releases resources held by the handler.
func (h *Handler) Cleanup() error {
	if h.dbManager != nil {
		return h.dbManager.Cleanup()
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Get client IP from Caddy's context
	clientIPStr, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if !ok || clientIPStr == "" {
		h.logger.Warn("failed to get client IP from context")
		return next.ServeHTTP(w, r)
	}

	clientIP := ParseIP(clientIPStr)
	if clientIP == nil {
		h.logger.Warn("failed to parse client IP", zap.String("ip", clientIPStr))
		return next.ServeHTTP(w, r)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// Always allow private/loopback IPs
	if IsPrivateOrLoopback(clientIP) {
		h.logger.Debug("allowing private/loopback IP", zap.String("ip", clientIPStr))
		h.setPlaceholders(r, repl, nil, false, "")
		return next.ServeHTTP(w, r)
	}

	// Check IP ranges first (before geo lookup)
	if h.ipRangeChecker != nil {
		switch h.ipRangeChecker.Check(clientIP) {
		case CheckResultAllow:
			h.logger.Debug("IP allowed by IP range", zap.String("ip", clientIPStr))
			h.setPlaceholders(r, repl, nil, false, "")
			return next.ServeHTTP(w, r)
		case CheckResultDeny:
			h.logger.Info("IP denied by IP range", zap.String("ip", clientIPStr))
			h.setPlaceholders(r, repl, nil, true, "ip_range")
			return h.blockRequest(w, r, repl, "ip_range")
		}
	}

	// Perform geo lookup
	record, err := h.dbManager.Lookup(clientIP)
	if err != nil {
		h.logger.Warn("geo lookup failed", zap.String("ip", clientIPStr), zap.Error(err))
		// If we have allow ranges configured but no geo data, and this IP wasn't in allow ranges, block it
		if h.ipRangeChecker.HasAllowRanges() {
			h.setPlaceholders(r, repl, nil, true, "ip_range_required")
			return h.blockRequest(w, r, repl, "ip_range_required")
		}
		// Otherwise, allow the request to proceed (fail open)
		h.setPlaceholders(r, repl, nil, false, "")
		return next.ServeHTTP(w, r)
	}

	// Set placeholders with geo data
	h.setPlaceholders(r, repl, record, false, "")

	// Log geo data at debug level
	h.logger.Debug("geo lookup result",
		zap.String("ip", clientIPStr),
		zap.String("country", record.Country.ISOCode),
		zap.String("city", record.City.Name()),
		zap.String("continent", record.Continent.Code),
		zap.Int("asn", record.AutonomousSystemNumber),
		zap.String("asn_org", record.AutonomousSystemOrganization),
	)

	// Check if request should be blocked
	blocked, reason := h.isBlocked(record)
	if blocked {
		h.logger.Info("request blocked",
			zap.String("ip", clientIPStr),
			zap.String("reason", reason),
			zap.String("country", record.Country.ISOCode),
			zap.Int("asn", record.AutonomousSystemNumber),
		)
		h.setPlaceholders(r, repl, record, true, reason)
		return h.blockRequest(w, r, repl, reason)
	}

	return next.ServeHTTP(w, r)
}

// isBlocked determines if a request should be blocked based on the geo record.
// It returns true if blocked, along with the reason for blocking.
func (h *Handler) isBlocked(record *GeoRecord) (bool, string) {
	// Check countries
	if blocked, reason := h.checkList(
		record.GetCountryCode(),
		h.AllowCountries,
		h.DenyCountries,
		"country",
	); blocked {
		return true, reason
	}

	// Check continents
	if blocked, reason := h.checkList(
		record.GetContinentCode(),
		h.AllowContinents,
		h.DenyContinents,
		"continent",
	); blocked {
		return true, reason
	}

	// Check subdivisions
	subdivisionCodes := record.GetSubdivisionCodes()
	if len(subdivisionCodes) > 0 {
		// Check if any subdivision is denied
		for _, code := range subdivisionCodes {
			if blocked, reason := h.checkList(code, nil, h.DenySubdivisions, "subdivision"); blocked {
				return true, reason
			}
		}
		// Check if any subdivision is allowed (if allow list is configured)
		if len(h.AllowSubdivisions) > 0 {
			allowed := false
			for _, code := range subdivisionCodes {
				if slices.Contains(h.AllowSubdivisions, code) {
					allowed = true
					break
				}
			}
			if !allowed {
				return true, "subdivision_not_allowed"
			}
		}
	} else {
		// No subdivisions found, check UNK
		if blocked, reason := h.checkList(
			UnknownValue,
			h.AllowSubdivisions,
			h.DenySubdivisions,
			"subdivision",
		); blocked {
			return true, reason
		}
	}

	// Check cities
	cityName := record.City.Name()
	if cityName == "" {
		cityName = UnknownValue
	}
	if blocked, reason := h.checkList(cityName, h.AllowCities, h.DenyCities, "city"); blocked {
		return true, reason
	}

	// Check ASN
	asnStr := strconv.Itoa(record.AutonomousSystemNumber)
	if record.AutonomousSystemNumber == 0 {
		asnStr = UnknownValue
	}
	if blocked, reason := h.checkList(asnStr, h.AllowASN, h.DenyASN, "asn"); blocked {
		return true, reason
	}

	// Check ASN Organization
	asnOrg := record.AutonomousSystemOrganization
	if asnOrg == "" {
		asnOrg = UnknownValue
	}
	if blocked, reason := h.checkListContains(asnOrg, h.AllowASNOrg, h.DenyASNOrg, "asn_org"); blocked {
		return true, reason
	}

	return false, ""
}

// checkList checks if a value should be blocked based on allow/deny lists.
// Deny list takes precedence over allow list.
func (h *Handler) checkList(value string, allowList, denyList []string, fieldName string) (bool, string) {
	// Normalize value for comparison
	value = strings.ToUpper(strings.TrimSpace(value))

	// Check deny list first (deny takes precedence)
	if len(denyList) > 0 {
		for _, denied := range denyList {
			if strings.EqualFold(value, denied) {
				return true, fieldName + "_denied"
			}
		}
	}

	// Check allow list
	if len(allowList) > 0 {
		for _, allowed := range allowList {
			if strings.EqualFold(value, allowed) {
				return false, "" // Explicitly allowed
			}
		}
		// Value not in allow list
		return true, fieldName + "_not_allowed"
	}

	// No lists configured for this field, allow by default
	return false, ""
}

// checkListContains is like checkList but uses substring matching for deny list.
// This is useful for ASN organization names which may vary.
func (h *Handler) checkListContains(value string, allowList, denyList []string, fieldName string) (bool, string) {
	valueLower := strings.ToLower(strings.TrimSpace(value))

	// Check deny list first (deny takes precedence) - substring match
	if len(denyList) > 0 {
		for _, denied := range denyList {
			if strings.Contains(valueLower, strings.ToLower(denied)) {
				return true, fieldName + "_denied"
			}
		}
	}

	// Check allow list - substring match
	if len(allowList) > 0 {
		for _, allowed := range allowList {
			if strings.Contains(valueLower, strings.ToLower(allowed)) {
				return false, "" // Explicitly allowed
			}
		}
		// Value not in allow list
		return true, fieldName + "_not_allowed"
	}

	return false, ""
}

// setPlaceholders sets all geoblock placeholders in the request context.
// These are accessible via {http.request.var.geoblock.*} placeholders.
func (h *Handler) setPlaceholders(r *http.Request, repl *caddy.Replacer, record *GeoRecord, blocked bool, reason string) {
	// Set vars in request context for use by other handlers
	caddyhttp.SetVar(r.Context(), "geoblock.blocked", strconv.FormatBool(blocked))
	caddyhttp.SetVar(r.Context(), "geoblock.blocked_reason", reason)

	// Also set in replacer for use in templates and messages
	repl.Set("geoblock.blocked", strconv.FormatBool(blocked))
	repl.Set("geoblock.blocked_reason", reason)

	if record == nil {
		setEmptyVars(r, repl)
		return
	}

	// Set all geo data in both context vars and replacer
	setVar(r, repl, "geoblock.country_code", record.Country.ISOCode)
	setVar(r, repl, "geoblock.country_name", record.Country.Name())
	setVar(r, repl, "geoblock.city_name", record.City.Name())
	setVar(r, repl, "geoblock.continent_code", record.Continent.Code)
	setVar(r, repl, "geoblock.continent_name", record.Continent.Name())
	setVar(r, repl, "geoblock.subdivision_code", record.SubdivisionCodesString())
	setVar(r, repl, "geoblock.subdivision_name", record.SubdivisionNamesString())
	setVar(r, repl, "geoblock.asn", strconv.Itoa(record.AutonomousSystemNumber))
	setVar(r, repl, "geoblock.asn_org", record.AutonomousSystemOrganization)
	setVar(r, repl, "geoblock.latitude", strconv.FormatFloat(record.Location.Latitude, 'f', 6, 64))
	setVar(r, repl, "geoblock.longitude", strconv.FormatFloat(record.Location.Longitude, 'f', 6, 64))
	setVar(r, repl, "geoblock.time_zone", record.Location.TimeZone)
	setVar(r, repl, "geoblock.postal_code", record.Postal.Code)
}

// setVar sets a value in both the request context and replacer.
func setVar(r *http.Request, repl *caddy.Replacer, key, value string) {
	caddyhttp.SetVar(r.Context(), key, value)
	repl.Set(key, value)
}

// setEmptyVars sets empty values for all geo placeholders.
func setEmptyVars(r *http.Request, repl *caddy.Replacer) {
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

// blockRequest returns an HTTP error for blocked requests.
func (h *Handler) blockRequest(w http.ResponseWriter, r *http.Request, repl *caddy.Replacer, reason string) error {
	// Expand any placeholders in the blocked message
	message := repl.ReplaceAll(h.BlockedMessage, "")

	return caddyhttp.Error(h.BlockedStatusCode, fmt.Errorf("%s", message))
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
