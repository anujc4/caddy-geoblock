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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsPrivateOrLoopback(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Loopback addresses
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 loopback other", "127.0.0.2", true},
		{"IPv6 loopback", "::1", true},

		// Private IPv4 ranges (RFC 1918)
		{"10.x.x.x", "10.0.0.1", true},
		{"10.x.x.x middle", "10.128.0.1", true},
		{"172.16.x.x", "172.16.0.1", true},
		{"172.31.x.x", "172.31.255.255", true},
		{"192.168.x.x", "192.168.1.1", true},

		// Link-local
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv6 link-local", "fe80::1", true},

		// Unspecified
		{"IPv4 unspecified", "0.0.0.0", true},
		{"IPv6 unspecified", "::", true},

		// Public addresses
		{"Google DNS", "8.8.8.8", false},
		{"Cloudflare DNS", "1.1.1.1", false},
		{"Public IPv6", "2001:4860:4860::8888", false},

		// Edge cases
		{"172.15.x.x (public)", "172.15.255.255", false},
		{"172.32.x.x (public)", "172.32.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse IP: %s", tt.ip)

			result := IsPrivateOrLoopback(ip)
			assert.Equal(t, tt.expected, result, "IsPrivateOrLoopback(%s)", tt.ip)
		})
	}
}

func TestIsPrivateOrLoopback_NilIP(t *testing.T) {
	assert.False(t, IsPrivateOrLoopback(nil), "nil IP should return false")
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string // expected IP string, or "" if nil
	}{
		{"Simple IPv4", "192.168.1.1", "192.168.1.1"},
		{"Simple IPv6", "2001:db8::1", "2001:db8::1"},
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1"},
		{"IPv6 with port", "[2001:db8::1]:8080", "2001:db8::1"},
		{"Invalid IP", "not-an-ip", ""},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIP(tt.input)
			if tt.expected == "" {
				assert.Nil(t, result, "ParseIP(%s) should return nil", tt.input)
			} else {
				require.NotNil(t, result, "ParseIP(%s) should not return nil", tt.input)
				assert.Equal(t, tt.expected, result.String(), "ParseIP(%s)", tt.input)
			}
		})
	}
}

func TestIPRangeChecker_Check(t *testing.T) {
	tests := []struct {
		name        string
		allowCIDRs  []string
		denyCIDRs   []string
		ip          string
		expected    CheckResult
		expectError bool
	}{
		{
			name:       "No ranges configured",
			allowCIDRs: nil,
			denyCIDRs:  nil,
			ip:         "8.8.8.8",
			expected:   CheckResultNoMatch,
		},
		{
			name:       "IP in allow range",
			allowCIDRs: []string{"10.0.0.0/8"},
			denyCIDRs:  nil,
			ip:         "10.1.2.3",
			expected:   CheckResultAllow,
		},
		{
			name:       "IP not in allow range",
			allowCIDRs: []string{"10.0.0.0/8"},
			denyCIDRs:  nil,
			ip:         "192.168.1.1",
			expected:   CheckResultNoMatch,
		},
		{
			name:       "IP in deny range",
			allowCIDRs: nil,
			denyCIDRs:  []string{"192.168.0.0/16"},
			ip:         "192.168.1.1",
			expected:   CheckResultDeny,
		},
		{
			name:       "IP not in deny range",
			allowCIDRs: nil,
			denyCIDRs:  []string{"192.168.0.0/16"},
			ip:         "10.0.0.1",
			expected:   CheckResultNoMatch,
		},
		{
			name:       "Deny takes precedence over allow",
			allowCIDRs: []string{"192.168.0.0/16"},
			denyCIDRs:  []string{"192.168.1.0/24"},
			ip:         "192.168.1.100",
			expected:   CheckResultDeny,
		},
		{
			name:       "Allow when not in more specific deny",
			allowCIDRs: []string{"192.168.0.0/16"},
			denyCIDRs:  []string{"192.168.1.0/24"},
			ip:         "192.168.2.100",
			expected:   CheckResultAllow,
		},
		{
			name:       "IPv6 allow range",
			allowCIDRs: []string{"2001:db8::/32"},
			denyCIDRs:  nil,
			ip:         "2001:db8::1",
			expected:   CheckResultAllow,
		},
		{
			name:       "IPv6 deny range",
			allowCIDRs: nil,
			denyCIDRs:  []string{"2001:db8::/32"},
			ip:         "2001:db8::1",
			expected:   CheckResultDeny,
		},
		{
			name:        "Invalid allow CIDR",
			allowCIDRs:  []string{"invalid"},
			denyCIDRs:   nil,
			ip:          "8.8.8.8",
			expectError: true,
		},
		{
			name:        "Invalid deny CIDR",
			allowCIDRs:  nil,
			denyCIDRs:   []string{"not-a-cidr"},
			ip:          "8.8.8.8",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewIPRangeChecker(tt.allowCIDRs, tt.denyCIDRs)

			if tt.expectError {
				assert.Error(t, err, "expected error for invalid CIDR")
				return
			}

			require.NoError(t, err, "unexpected error creating checker")

			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse IP: %s", tt.ip)

			result := checker.Check(ip)
			assert.Equal(t, tt.expected, result, "Check(%s)", tt.ip)
		})
	}
}

func TestIPRangeChecker_HasRanges(t *testing.T) {
	tests := []struct {
		name             string
		allowCIDRs       []string
		denyCIDRs        []string
		hasAllowExpected bool
		hasDenyExpected  bool
	}{
		{
			name:             "No ranges",
			allowCIDRs:       nil,
			denyCIDRs:        nil,
			hasAllowExpected: false,
			hasDenyExpected:  false,
		},
		{
			name:             "Only allow ranges",
			allowCIDRs:       []string{"10.0.0.0/8"},
			denyCIDRs:        nil,
			hasAllowExpected: true,
			hasDenyExpected:  false,
		},
		{
			name:             "Only deny ranges",
			allowCIDRs:       nil,
			denyCIDRs:        []string{"192.168.0.0/16"},
			hasAllowExpected: false,
			hasDenyExpected:  true,
		},
		{
			name:             "Both ranges",
			allowCIDRs:       []string{"10.0.0.0/8"},
			denyCIDRs:        []string{"192.168.0.0/16"},
			hasAllowExpected: true,
			hasDenyExpected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker, err := NewIPRangeChecker(tt.allowCIDRs, tt.denyCIDRs)
			require.NoError(t, err)

			assert.Equal(t, tt.hasAllowExpected, checker.HasAllowRanges(), "HasAllowRanges()")
			assert.Equal(t, tt.hasDenyExpected, checker.HasDenyRanges(), "HasDenyRanges()")
		})
	}
}

func TestIPRangeChecker_NilChecker(t *testing.T) {
	var checker *IPRangeChecker

	ip := net.ParseIP("8.8.8.8")
	require.NotNil(t, ip)

	// Nil checker should return NoMatch
	assert.Equal(t, CheckResultNoMatch, checker.Check(ip), "nil checker should return NoMatch")
	assert.False(t, checker.HasAllowRanges(), "nil checker should not have allow ranges")
	assert.False(t, checker.HasDenyRanges(), "nil checker should not have deny ranges")
}

func TestIPRangeChecker_MultipleRanges(t *testing.T) {
	allowCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	denyCIDRs := []string{"10.10.0.0/16", "172.16.10.0/24"}

	checker, err := NewIPRangeChecker(allowCIDRs, denyCIDRs)
	require.NoError(t, err)

	tests := []struct {
		ip       string
		expected CheckResult
	}{
		{"10.0.0.1", CheckResultAllow},
		{"10.10.0.1", CheckResultDeny},    // In deny range
		{"10.20.0.1", CheckResultAllow},   // In allow, not in deny
		{"172.16.0.1", CheckResultAllow},  // In allow, not in specific deny
		{"172.16.10.1", CheckResultDeny},  // In deny range
		{"192.168.1.1", CheckResultAllow}, // In allow
		{"8.8.8.8", CheckResultNoMatch},   // Not in any range
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)

			result := checker.Check(ip)
			assert.Equal(t, tt.expected, result, "Check(%s)", tt.ip)
		})
	}
}

const (
	testCountryDB = "testdata/GeoIP2-Country-Test.mmdb"
	testCityDB    = "testdata/GeoIP2-City-Test.mmdb"
	testASNDB     = "testdata/GeoLite2-ASN-Test.mmdb"
)

func TestDatabaseManager_LoadDatabase(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })

	require.NoError(t, m.LoadDatabase(testCountryDB))
	assert.Len(t, m.databases, 1)
}

func TestDatabaseManager_LoadDatabase_NonExistent(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })

	err := m.LoadDatabase("testdata/does-not-exist.mmdb")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open MaxMind database")
}

func TestDatabaseManager_LoadDatabase_Duplicate(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })

	require.NoError(t, m.LoadDatabase(testCountryDB))
	require.NoError(t, m.LoadDatabase(testCountryDB))
	assert.Len(t, m.databases, 1, "duplicate path should be a no-op")
}

func TestDatabaseManager_Lookup_NoDatabases(t *testing.T) {
	m := NewDatabaseManager()

	_, err := m.Lookup(net.ParseIP("8.8.8.8"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no databases loaded")
}

func TestDatabaseManager_Lookup_KnownIP(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })
	require.NoError(t, m.LoadDatabase(testCountryDB))

	record, err := m.Lookup(net.ParseIP("81.2.69.142"))
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, "GB", record.Country.ISOCode)
}

func TestDatabaseManager_Lookup_UnknownIP(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })
	require.NoError(t, m.LoadDatabase(testCountryDB))

	// 192.168.1.1 is not present in any MaxMind test fixture.
	record, err := m.Lookup(net.ParseIP("192.168.1.1"))
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.True(t, record.IsEmpty(), "private IP should produce empty record")
}

func TestDatabaseManager_Lookup_InvalidIP(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })
	require.NoError(t, m.LoadDatabase(testCountryDB))

	// A net.IP with an invalid length cannot be converted to netip.Addr.
	_, err := m.Lookup(net.IP{1, 2, 3})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address")
}

func TestDatabaseManager_Lookup_IPv4MappedIPv6(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })
	require.NoError(t, m.LoadDatabase(testCountryDB))

	// 16-byte IPv4-mapped IPv6 form of 81.2.69.142. Without Unmap() this
	// would look up an IPv6 address that is not in the test database.
	ip := net.ParseIP("81.2.69.142").To16()
	require.NotNil(t, ip)

	record, err := m.Lookup(ip)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, "GB", record.Country.ISOCode, "IPv4-mapped IPv6 should resolve via Unmap()")
}

func TestDatabaseManager_Lookup_MultipleDatabases(t *testing.T) {
	m := NewDatabaseManager()
	t.Cleanup(func() { _ = m.Cleanup() })

	require.NoError(t, m.LoadDatabase(testCityDB))
	require.NoError(t, m.LoadDatabase(testASNDB))

	record, err := m.Lookup(net.ParseIP("81.2.69.142"))
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, "GB", record.Country.ISOCode, "city DB should populate country")
}

func TestDatabaseManager_Cleanup(t *testing.T) {
	m := NewDatabaseManager()
	require.NoError(t, m.LoadDatabase(testCountryDB))
	require.Len(t, m.databases, 1)

	require.NoError(t, m.Cleanup())
	assert.Nil(t, m.databases, "Cleanup should clear loaded databases")

	_, err := m.Lookup(net.ParseIP("8.8.8.8"))
	require.Error(t, err)
}
