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
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// GeoFilterConfig holds the configuration for geo-based filtering.
// This is embedded by both Handler and Matcher to share configuration fields.
type GeoFilterConfig struct {
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
}

// GeoFilter handles the actual geo-based filtering logic.
// It is provisioned from GeoFilterConfig and used by both Handler and Matcher.
type GeoFilter struct {
	config         *GeoFilterConfig
	dbManager      *DatabaseManager
	ipRangeChecker *IPRangeChecker
	logger         *zap.Logger
}

// NewGeoFilter creates a new GeoFilter from the given configuration.
func NewGeoFilter(config *GeoFilterConfig, logger *zap.Logger) *GeoFilter {
	return &GeoFilter{
		config: config,
		logger: logger,
	}
}

// Provision sets up the GeoFilter by loading databases and initializing the IP range checker.
func (f *GeoFilter) Provision(ctx caddy.Context) error {
	// Initialize database manager
	f.dbManager = NewDatabaseManager()
	for _, dbPath := range f.config.DatabasePaths {
		if err := f.dbManager.LoadDatabase(dbPath); err != nil {
			return fmt.Errorf("failed to load database %s: %w", dbPath, err)
		}
	}

	// Initialize IP range checker
	var err error
	f.ipRangeChecker, err = NewIPRangeChecker(f.config.AllowIPRanges, f.config.DenyIPRanges)
	if err != nil {
		return fmt.Errorf("failed to initialize IP range checker: %w", err)
	}

	return nil
}

// Cleanup releases resources held by the GeoFilter.
func (f *GeoFilter) Cleanup() error {
	if f.dbManager != nil {
		return f.dbManager.Cleanup()
	}
	return nil
}

// Validate ensures the GeoFilter configuration is valid.
func (f *GeoFilter) Validate() error {
	if len(f.config.DatabasePaths) == 0 {
		return fmt.Errorf("at least one database path is required (db_paths)")
	}
	return nil
}

// FilterResult contains the result of a geo-filtering check.
type FilterResult struct {
	// Blocked indicates whether the request should be blocked.
	Blocked bool
	// Reason provides the reason for blocking (empty if not blocked).
	Reason string
	// Record contains the geo information for the IP (may be nil).
	Record *GeoRecord
}

// CheckIP performs the geo-filtering check for the given IP address.
// It returns a FilterResult indicating whether the IP should be blocked.
func (f *GeoFilter) CheckIP(ip net.IP) FilterResult {
	// Always allow private/loopback IPs
	if IsPrivateOrLoopback(ip) {
		if f.logger != nil {
			f.logger.Debug("allowing private/loopback IP", zap.String("ip", ip.String()))
		}
		return FilterResult{Blocked: false, Reason: "", Record: nil}
	}

	// Check IP ranges first (before geo lookup)
	if f.ipRangeChecker != nil {
		switch f.ipRangeChecker.Check(ip) {
		case CheckResultAllow:
			if f.logger != nil {
				f.logger.Debug("IP allowed by IP range", zap.String("ip", ip.String()))
			}
			return FilterResult{Blocked: false, Reason: "", Record: nil}
		case CheckResultDeny:
			if f.logger != nil {
				f.logger.Info("IP denied by IP range", zap.String("ip", ip.String()))
			}
			return FilterResult{Blocked: true, Reason: "ip_range", Record: nil}
		}
	}

	// Perform geo lookup
	record, err := f.dbManager.Lookup(ip)
	if err != nil {
		if f.logger != nil {
			f.logger.Warn("geo lookup failed", zap.String("ip", ip.String()), zap.Error(err))
		}
		// If we have allow ranges configured but no geo data, and this IP wasn't in allow ranges, block it
		if f.ipRangeChecker.HasAllowRanges() {
			return FilterResult{Blocked: true, Reason: "ip_range_required", Record: nil}
		}
		// Otherwise, allow the request to proceed (fail open)
		return FilterResult{Blocked: false, Reason: "", Record: nil}
	}

	// Log geo data at debug level
	if f.logger != nil {
		f.logger.Debug("geo lookup result",
			zap.String("ip", ip.String()),
			zap.String("country", record.Country.ISOCode),
			zap.String("city", record.City.Name()),
			zap.String("continent", record.Continent.Code),
			zap.Int("asn", record.AutonomousSystemNumber),
			zap.String("asn_org", record.AutonomousSystemOrganization),
		)
	}

	// Check if request should be blocked
	blocked, reason := f.isBlocked(record)
	if blocked && f.logger != nil {
		f.logger.Info("request blocked",
			zap.String("ip", ip.String()),
			zap.String("reason", reason),
			zap.String("country", record.Country.ISOCode),
			zap.Int("asn", record.AutonomousSystemNumber),
		)
	}

	return FilterResult{Blocked: blocked, Reason: reason, Record: record}
}

// isBlocked determines if a request should be blocked based on the geo record.
// It returns true if blocked, along with the reason for blocking.
func (f *GeoFilter) isBlocked(record *GeoRecord) (bool, string) {
	// Check countries
	if blocked, reason := f.checkList(
		record.GetCountryCode(),
		f.config.AllowCountries,
		f.config.DenyCountries,
		"country",
	); blocked {
		return true, reason
	}

	// Check continents
	if blocked, reason := f.checkList(
		record.GetContinentCode(),
		f.config.AllowContinents,
		f.config.DenyContinents,
		"continent",
	); blocked {
		return true, reason
	}

	// Check subdivisions
	subdivisionCodes := record.GetSubdivisionCodes()
	if len(subdivisionCodes) > 0 {
		// Check if any subdivision is denied
		for _, code := range subdivisionCodes {
			if blocked, reason := f.checkList(code, nil, f.config.DenySubdivisions, "subdivision"); blocked {
				return true, reason
			}
		}
		// Check if any subdivision is allowed (if allow list is configured)
		if len(f.config.AllowSubdivisions) > 0 {
			allowed := false
			for _, code := range subdivisionCodes {
				if slices.Contains(f.config.AllowSubdivisions, code) {
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
		if blocked, reason := f.checkList(
			UnknownValue,
			f.config.AllowSubdivisions,
			f.config.DenySubdivisions,
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
	if blocked, reason := f.checkList(cityName, f.config.AllowCities, f.config.DenyCities, "city"); blocked {
		return true, reason
	}

	// Check ASN
	asnStr := strconv.Itoa(record.AutonomousSystemNumber)
	if record.AutonomousSystemNumber == 0 {
		asnStr = UnknownValue
	}
	if blocked, reason := f.checkList(asnStr, f.config.AllowASN, f.config.DenyASN, "asn"); blocked {
		return true, reason
	}

	// Check ASN Organization
	asnOrg := record.AutonomousSystemOrganization
	if asnOrg == "" {
		asnOrg = UnknownValue
	}
	if blocked, reason := f.checkListContains(asnOrg, f.config.AllowASNOrg, f.config.DenyASNOrg, "asn_org"); blocked {
		return true, reason
	}

	return false, ""
}

// checkList checks if a value should be blocked based on allow/deny lists.
// Deny list takes precedence over allow list.
func (f *GeoFilter) checkList(value string, allowList, denyList []string, fieldName string) (bool, string) {
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
func (f *GeoFilter) checkListContains(value string, allowList, denyList []string, fieldName string) (bool, string) {
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
