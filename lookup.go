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
	"net/netip"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/oschwald/maxminddb-golang"
)

// dbPool manages MaxMind database instances across config reloads.
// This ensures databases are shared and properly cleaned up.
var dbPool = caddy.NewUsagePool()

// dbHandle wraps a MaxMind database reader for use with UsagePool.
type dbHandle struct {
	reader *maxminddb.Reader
	path   string
}

// Destruct implements caddy.Destructor for cleanup when the pool releases the handle.
func (h *dbHandle) Destruct() error {
	if h.reader != nil {
		return h.reader.Close()
	}
	return nil
}

// DatabaseManager handles loading and querying multiple MaxMind databases.
type DatabaseManager struct {
	// databases holds all loaded database handles
	databases []*dbHandle
	mu        sync.RWMutex
}

// NewDatabaseManager creates a new DatabaseManager.
func NewDatabaseManager() *DatabaseManager {
	return &DatabaseManager{
		databases: make([]*dbHandle, 0),
	}
}

// LoadDatabase loads a MaxMind database from the given path.
// It uses the dbPool to share database instances across config reloads.
func (m *DatabaseManager) LoadDatabase(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we already have this database loaded
	for _, db := range m.databases {
		if db.path == path {
			return nil // Already loaded
		}
	}

	// Load or get from pool
	val, loaded, err := dbPool.LoadOrNew(path, func() (caddy.Destructor, error) {
		reader, err := maxminddb.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open MaxMind database %s: %w", path, err)
		}
		return &dbHandle{reader: reader, path: path}, nil
	})
	if err != nil {
		return err
	}

	handle := val.(*dbHandle)
	m.databases = append(m.databases, handle)

	if loaded {
		// Database was already in the pool, increment reference
		_ = loaded // Reference counting is handled by the pool
	}

	return nil
}

// Cleanup releases all database handles back to the pool.
func (m *DatabaseManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, db := range m.databases {
		if _, err := dbPool.Delete(db.path); err != nil {
			lastErr = err
		}
	}
	m.databases = nil
	return lastErr
}

// Lookup queries all loaded databases for information about the given IP address.
// Results from multiple databases are merged into a single GeoRecord.
func (m *DatabaseManager) Lookup(ip net.IP) (*GeoRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.databases) == 0 {
		return nil, fmt.Errorf("no databases loaded")
	}

	record := &GeoRecord{}
	var lastErr error

	for _, db := range m.databases {
		var tempRecord GeoRecord
		err := db.reader.Lookup(ip, &tempRecord)
		if err != nil {
			lastErr = err
			continue
		}
		// Merge results - non-empty values take precedence
		mergeRecords(record, &tempRecord)
	}

	// If all lookups failed, return the last error
	if record.IsEmpty() && lastErr != nil {
		return nil, lastErr
	}

	return record, nil
}

// mergeRecords merges src into dst, with src values taking precedence for non-empty fields.
func mergeRecords(dst, src *GeoRecord) {
	// Country
	if src.Country.ISOCode != "" {
		dst.Country = src.Country
	}

	// City
	if src.City.Name() != "" {
		dst.City = src.City
	}

	// Continent
	if src.Continent.Code != "" {
		dst.Continent = src.Continent
	}

	// Location (only if coordinates are set)
	if src.Location.Latitude != 0 || src.Location.Longitude != 0 {
		dst.Location = src.Location
	}

	// Postal
	if src.Postal.Code != "" {
		dst.Postal = src.Postal
	}

	// Subdivisions
	if len(src.Subdivisions) > 0 {
		dst.Subdivisions = src.Subdivisions
	}

	// ASN
	if src.AutonomousSystemNumber != 0 {
		dst.AutonomousSystemNumber = src.AutonomousSystemNumber
		dst.AutonomousSystemOrganization = src.AutonomousSystemOrganization
	}
}

// IPRangeChecker handles IP range allow/deny list checking.
type IPRangeChecker struct {
	allowRanges []netip.Prefix
	denyRanges  []netip.Prefix
}

// NewIPRangeChecker creates a new IPRangeChecker from string CIDR ranges.
func NewIPRangeChecker(allowCIDRs, denyCIDRs []string) (*IPRangeChecker, error) {
	checker := &IPRangeChecker{
		allowRanges: make([]netip.Prefix, 0, len(allowCIDRs)),
		denyRanges:  make([]netip.Prefix, 0, len(denyCIDRs)),
	}

	for _, cidr := range allowCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allow CIDR %q: %w", cidr, err)
		}
		checker.allowRanges = append(checker.allowRanges, prefix)
	}

	for _, cidr := range denyCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid deny CIDR %q: %w", cidr, err)
		}
		checker.denyRanges = append(checker.denyRanges, prefix)
	}

	return checker, nil
}

// CheckResult represents the result of an IP range check.
type CheckResult int

const (
	// CheckResultNoMatch means the IP didn't match any ranges.
	CheckResultNoMatch CheckResult = iota
	// CheckResultAllow means the IP matched an allow range.
	CheckResultAllow
	// CheckResultDeny means the IP matched a deny range.
	CheckResultDeny
)

// Check determines if an IP should be allowed, denied, or requires further geo checking.
// Deny ranges take precedence over allow ranges.
func (c *IPRangeChecker) Check(ip net.IP) CheckResult {
	if c == nil {
		return CheckResultNoMatch
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return CheckResultNoMatch
	}
	// Normalize IPv4-mapped IPv6 addresses
	addr = addr.Unmap()

	// Check deny ranges first (deny takes precedence)
	for _, prefix := range c.denyRanges {
		if prefix.Contains(addr) {
			return CheckResultDeny
		}
	}

	// Check allow ranges
	for _, prefix := range c.allowRanges {
		if prefix.Contains(addr) {
			return CheckResultAllow
		}
	}

	// If allow ranges are configured but IP didn't match any, it should be checked via geo
	// If no ranges are configured, no match means proceed to geo check
	return CheckResultNoMatch
}

// HasAllowRanges returns true if any allow ranges are configured.
func (c *IPRangeChecker) HasAllowRanges() bool {
	return c != nil && len(c.allowRanges) > 0
}

// HasDenyRanges returns true if any deny ranges are configured.
func (c *IPRangeChecker) HasDenyRanges() bool {
	return c != nil && len(c.denyRanges) > 0
}

// IsPrivateOrLoopback checks if an IP address is private or loopback.
// These addresses should always be allowed.
func IsPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for private ranges
	if ip.IsPrivate() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	return false
}

// ParseIP parses an IP address string and returns a net.IP.
// It handles both IPv4 and IPv6 addresses.
func ParseIP(ipStr string) net.IP {
	// First try parsing as-is
	ip := net.ParseIP(ipStr)
	if ip != nil {
		return ip
	}

	// Try parsing as host:port
	host, _, err := net.SplitHostPort(ipStr)
	if err != nil {
		return nil
	}

	return net.ParseIP(host)
}
