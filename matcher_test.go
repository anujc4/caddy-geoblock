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
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatcher_CaddyModule(t *testing.T) {
	m := Matcher{}
	info := m.CaddyModule()

	assert.Equal(t, "http.matchers.geoblock", string(info.ID))
	assert.NotNil(t, info.New)

	// Test that New() returns a new Matcher
	newModule := info.New()
	_, ok := newModule.(*Matcher)
	assert.True(t, ok, "New() should return *Matcher")
}

func TestMatcher_Validate(t *testing.T) {
	tests := []struct {
		name        string
		matcher     Matcher
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid configuration",
			matcher: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
				},
			},
			expectError: false,
		},
		{
			name:        "Missing database paths",
			matcher:     Matcher{},
			expectError: true,
			errorMsg:    "at least one database path is required",
		},
		{
			name: "Empty database paths slice",
			matcher: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{},
				},
			},
			expectError: true,
			errorMsg:    "at least one database path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a filter for the matcher to use during validation
			tt.matcher.filter = NewGeoFilter(&tt.matcher.GeoFilterConfig, nil)
			err := tt.matcher.Validate()
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMatcher_UnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Matcher
		expectError bool
		errorMsg    string
	}{
		{
			name: "Minimal config with single db_path",
			input: `geoblock {
				db_path /path/to/GeoLite2-City.mmdb
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/GeoLite2-City.mmdb"},
				},
			},
		},
		{
			name: "Multiple db_paths",
			input: `geoblock {
				db_path /path/to/GeoLite2-City.mmdb
				db_path /path/to/GeoLite2-ASN.mmdb
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{
						"/path/to/GeoLite2-City.mmdb",
						"/path/to/GeoLite2-ASN.mmdb",
					},
				},
			},
		},
		{
			name: "Deny countries",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_countries CN RU KP
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyCountries: []string{"CN", "RU", "KP"},
				},
			},
		},
		{
			name: "Allow countries",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_countries US CA GB
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:  []string{"/path/to/db.mmdb"},
					AllowCountries: []string{"US", "CA", "GB"},
				},
			},
		},
		{
			name: "IP ranges",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_ip_ranges 10.0.0.0/8
				deny_ip_ranges 1.2.3.0/24
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					AllowIPRanges: []string{"10.0.0.0/8"},
					DenyIPRanges:  []string{"1.2.3.0/24"},
				},
			},
		},
		{
			name: "Full configuration",
			input: `geoblock {
				db_path /path/to/GeoLite2-City.mmdb
				db_path /path/to/GeoLite2-ASN.mmdb
				allow_countries US CA
				deny_countries CN RU
				allow_continents NA EU
				deny_continents AS
				allow_subdivisions CA NY
				deny_subdivisions TX
				allow_cities "New York"
				deny_cities Beijing
				allow_asn 15169
				deny_asn 12345
				allow_asn_org Google
				deny_asn_org "Bad Hosting"
				allow_ip_ranges 10.0.0.0/8
				deny_ip_ranges 1.2.3.0/24
			}`,
			expected: Matcher{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:     []string{"/path/to/GeoLite2-City.mmdb", "/path/to/GeoLite2-ASN.mmdb"},
					AllowCountries:    []string{"US", "CA"},
					DenyCountries:     []string{"CN", "RU"},
					AllowContinents:   []string{"NA", "EU"},
					DenyContinents:    []string{"AS"},
					AllowSubdivisions: []string{"CA", "NY"},
					DenySubdivisions:  []string{"TX"},
					AllowCities:       []string{"New York"},
					DenyCities:        []string{"Beijing"},
					AllowASN:          []string{"15169"},
					DenyASN:           []string{"12345"},
					AllowASNOrg:       []string{"Google"},
					DenyASNOrg:        []string{"Bad Hosting"},
					AllowIPRanges:     []string{"10.0.0.0/8"},
					DenyIPRanges:      []string{"1.2.3.0/24"},
				},
			},
		},
		{
			name: "Error - unrecognized subdirective",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_status 403
			}`,
			expectError: true,
			errorMsg:    "unrecognized subdirective",
		},
		{
			name: "Error - db_path without value",
			input: `geoblock {
				db_path
			}`,
			expectError: true,
		},
		{
			name: "Error - deny_countries without value",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_countries
			}`,
			expectError: true,
		},
		{
			name: "Error - matcher with arguments",
			input: `geoblock somearg {
				db_path /path/to/db.mmdb
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var m Matcher
			err := m.UnmarshalCaddyfile(d)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)

			// Compare relevant fields
			assert.Equal(t, tt.expected.DatabasePaths, m.DatabasePaths, "DatabasePaths")
			assert.Equal(t, tt.expected.AllowCountries, m.AllowCountries, "AllowCountries")
			assert.Equal(t, tt.expected.DenyCountries, m.DenyCountries, "DenyCountries")
			assert.Equal(t, tt.expected.AllowContinents, m.AllowContinents, "AllowContinents")
			assert.Equal(t, tt.expected.DenyContinents, m.DenyContinents, "DenyContinents")
			assert.Equal(t, tt.expected.AllowSubdivisions, m.AllowSubdivisions, "AllowSubdivisions")
			assert.Equal(t, tt.expected.DenySubdivisions, m.DenySubdivisions, "DenySubdivisions")
			assert.Equal(t, tt.expected.AllowCities, m.AllowCities, "AllowCities")
			assert.Equal(t, tt.expected.DenyCities, m.DenyCities, "DenyCities")
			assert.Equal(t, tt.expected.AllowASN, m.AllowASN, "AllowASN")
			assert.Equal(t, tt.expected.DenyASN, m.DenyASN, "DenyASN")
			assert.Equal(t, tt.expected.AllowASNOrg, m.AllowASNOrg, "AllowASNOrg")
			assert.Equal(t, tt.expected.DenyASNOrg, m.DenyASNOrg, "DenyASNOrg")
			assert.Equal(t, tt.expected.AllowIPRanges, m.AllowIPRanges, "AllowIPRanges")
			assert.Equal(t, tt.expected.DenyIPRanges, m.DenyIPRanges, "DenyIPRanges")
		})
	}
}

func TestMatcher_UnmarshalCaddyfile_Accumulation(t *testing.T) {
	// Test that multiple directives accumulate values
	input := `geoblock {
		db_path /path/to/db1.mmdb
		db_path /path/to/db2.mmdb
		deny_countries CN
		deny_countries RU
		deny_countries KP
		allow_asn 111
		allow_asn 222
	}`

	d := caddyfile.NewTestDispenser(input)

	var m Matcher
	err := m.UnmarshalCaddyfile(d)
	require.NoError(t, err)

	assert.Equal(t, []string{"/path/to/db1.mmdb", "/path/to/db2.mmdb"}, m.DatabasePaths)
	assert.Equal(t, []string{"CN", "RU", "KP"}, m.DenyCountries)
	assert.Equal(t, []string{"111", "222"}, m.AllowASN)
}
