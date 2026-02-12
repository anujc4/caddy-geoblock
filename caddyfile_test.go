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

func TestUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Handler
		expectError bool
		errorMsg    string
	}{
		{
			name: "Minimal config with single db_path",
			input: `geoblock {
				db_path /path/to/GeoLite2-City.mmdb
			}`,
			expected: Handler{
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
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{
						"/path/to/GeoLite2-City.mmdb",
						"/path/to/GeoLite2-ASN.mmdb",
					},
				},
			},
		},
		{
			name: "Multiple db_paths on same line",
			input: `geoblock {
				db_path /path/to/City.mmdb /path/to/ASN.mmdb
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{
						"/path/to/City.mmdb",
						"/path/to/ASN.mmdb",
					},
				},
			},
		},
		{
			name: "Allow countries",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_countries US CA GB
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:  []string{"/path/to/db.mmdb"},
					AllowCountries: []string{"US", "CA", "GB"},
				},
			},
		},
		{
			name: "Deny countries",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_countries CN RU KP
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyCountries: []string{"CN", "RU", "KP"},
				},
			},
		},
		{
			name: "Allow continents",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_continents NA EU
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:   []string{"/path/to/db.mmdb"},
					AllowContinents: []string{"NA", "EU"},
				},
			},
		},
		{
			name: "Deny continents",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_continents AS AF
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:  []string{"/path/to/db.mmdb"},
					DenyContinents: []string{"AS", "AF"},
				},
			},
		},
		{
			name: "Allow subdivisions",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_subdivisions CA NY TX
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:     []string{"/path/to/db.mmdb"},
					AllowSubdivisions: []string{"CA", "NY", "TX"},
				},
			},
		},
		{
			name: "Deny subdivisions",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_subdivisions FL OH
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:    []string{"/path/to/db.mmdb"},
					DenySubdivisions: []string{"FL", "OH"},
				},
			},
		},
		{
			name: "Allow cities",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_cities "New York" "Los Angeles"
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					AllowCities:   []string{"New York", "Los Angeles"},
				},
			},
		},
		{
			name: "Deny cities",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_cities Beijing Moscow
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyCities:    []string{"Beijing", "Moscow"},
				},
			},
		},
		{
			name: "Allow ASN",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_asn 15169 13335
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					AllowASN:      []string{"15169", "13335"},
				},
			},
		},
		{
			name: "Deny ASN",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_asn 12345 67890
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyASN:       []string{"12345", "67890"},
				},
			},
		},
		{
			name: "Allow ASN org",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_asn_org Google Cloudflare
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					AllowASNOrg:   []string{"Google", "Cloudflare"},
				},
			},
		},
		{
			name: "Deny ASN org",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_asn_org "Bad Hosting"
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyASNOrg:    []string{"Bad Hosting"},
				},
			},
		},
		{
			name: "Allow IP ranges",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_ip_ranges 10.0.0.0/8 192.168.0.0/16
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					AllowIPRanges: []string{"10.0.0.0/8", "192.168.0.0/16"},
				},
			},
		},
		{
			name: "Deny IP ranges",
			input: `geoblock {
				db_path /path/to/db.mmdb
				deny_ip_ranges 1.2.3.0/24 5.6.7.0/24
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
					DenyIPRanges:  []string{"1.2.3.0/24", "5.6.7.0/24"},
				},
			},
		},
		{
			name: "Blocked status code",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_status 451
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
				},
				BlockedStatusCode: 451,
			},
		},
		{
			name: "Blocked message single word",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_message Forbidden
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
				},
				BlockedMessage: "Forbidden",
			},
		},
		{
			name: "Blocked message multiple words",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_message Access denied from your location
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
				},
				BlockedMessage: "Access denied from your location",
			},
		},
		{
			name: "Blocked message with placeholder",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_message "Blocked: {geoblock.country_code}"
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths: []string{"/path/to/db.mmdb"},
				},
				BlockedMessage: "Blocked: {geoblock.country_code}",
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
				deny_asn 12345
				allow_ip_ranges 10.0.0.0/8
				deny_ip_ranges 1.2.3.0/24
				blocked_status 403
				blocked_message Access denied
			}`,
			expected: Handler{
				GeoFilterConfig: GeoFilterConfig{
					DatabasePaths:   []string{"/path/to/GeoLite2-City.mmdb", "/path/to/GeoLite2-ASN.mmdb"},
					AllowCountries:  []string{"US", "CA"},
					DenyCountries:   []string{"CN", "RU"},
					AllowContinents: []string{"NA", "EU"},
					DenyASN:         []string{"12345"},
					AllowIPRanges:   []string{"10.0.0.0/8"},
					DenyIPRanges:    []string{"1.2.3.0/24"},
				},
				BlockedStatusCode: 403,
				BlockedMessage:    "Access denied",
			},
		},
		{
			name: "Error - unrecognized subdirective",
			input: `geoblock {
				db_path /path/to/db.mmdb
				invalid_directive value
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
			name: "Error - allow_countries without value",
			input: `geoblock {
				db_path /path/to/db.mmdb
				allow_countries
			}`,
			expectError: true,
		},
		{
			name: "Error - blocked_status without value",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_status
			}`,
			expectError: true,
		},
		{
			name: "Error - blocked_status invalid value",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_status not_a_number
			}`,
			expectError: true,
			errorMsg:    "invalid status code",
		},
		{
			name: "Error - blocked_message without value",
			input: `geoblock {
				db_path /path/to/db.mmdb
				blocked_message
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)

			var h Handler
			err := h.UnmarshalCaddyfile(d)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)

			// Compare relevant fields
			assert.Equal(t, tt.expected.DatabasePaths, h.DatabasePaths, "DatabasePaths")
			assert.Equal(t, tt.expected.AllowCountries, h.AllowCountries, "AllowCountries")
			assert.Equal(t, tt.expected.DenyCountries, h.DenyCountries, "DenyCountries")
			assert.Equal(t, tt.expected.AllowContinents, h.AllowContinents, "AllowContinents")
			assert.Equal(t, tt.expected.DenyContinents, h.DenyContinents, "DenyContinents")
			assert.Equal(t, tt.expected.AllowSubdivisions, h.AllowSubdivisions, "AllowSubdivisions")
			assert.Equal(t, tt.expected.DenySubdivisions, h.DenySubdivisions, "DenySubdivisions")
			assert.Equal(t, tt.expected.AllowCities, h.AllowCities, "AllowCities")
			assert.Equal(t, tt.expected.DenyCities, h.DenyCities, "DenyCities")
			assert.Equal(t, tt.expected.AllowASN, h.AllowASN, "AllowASN")
			assert.Equal(t, tt.expected.DenyASN, h.DenyASN, "DenyASN")
			assert.Equal(t, tt.expected.AllowASNOrg, h.AllowASNOrg, "AllowASNOrg")
			assert.Equal(t, tt.expected.DenyASNOrg, h.DenyASNOrg, "DenyASNOrg")
			assert.Equal(t, tt.expected.AllowIPRanges, h.AllowIPRanges, "AllowIPRanges")
			assert.Equal(t, tt.expected.DenyIPRanges, h.DenyIPRanges, "DenyIPRanges")
			assert.Equal(t, tt.expected.BlockedStatusCode, h.BlockedStatusCode, "BlockedStatusCode")
			assert.Equal(t, tt.expected.BlockedMessage, h.BlockedMessage, "BlockedMessage")
		})
	}
}

func TestUnmarshalCaddyfile_Accumulation(t *testing.T) {
	// Test that multiple directives accumulate values
	input := `geoblock {
		db_path /path/to/db1.mmdb
		db_path /path/to/db2.mmdb
		allow_countries US
		allow_countries CA
		allow_countries GB
		deny_asn 111
		deny_asn 222
	}`

	d := caddyfile.NewTestDispenser(input)

	var h Handler
	err := h.UnmarshalCaddyfile(d)
	require.NoError(t, err)

	assert.Equal(t, []string{"/path/to/db1.mmdb", "/path/to/db2.mmdb"}, h.DatabasePaths)
	assert.Equal(t, []string{"US", "CA", "GB"}, h.AllowCountries)
	assert.Equal(t, []string{"111", "222"}, h.DenyASN)
}
