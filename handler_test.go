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

	"github.com/stretchr/testify/assert"
)

func TestHandler_checkList(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name          string
		value         string
		allowList     []string
		denyList      []string
		expectBlocked bool
		expectReason  string
	}{
		{
			name:          "No lists configured - allow by default",
			value:         "US",
			allowList:     nil,
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Value in allow list",
			value:         "US",
			allowList:     []string{"US", "CA", "GB"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Value not in allow list",
			value:         "CN",
			allowList:     []string{"US", "CA", "GB"},
			denyList:      nil,
			expectBlocked: true,
			expectReason:  "country_not_allowed",
		},
		{
			name:          "Value in deny list",
			value:         "CN",
			allowList:     nil,
			denyList:      []string{"CN", "RU", "KP"},
			expectBlocked: true,
			expectReason:  "country_denied",
		},
		{
			name:          "Value not in deny list",
			value:         "US",
			allowList:     nil,
			denyList:      []string{"CN", "RU", "KP"},
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Deny takes precedence over allow",
			value:         "CN",
			allowList:     []string{"CN", "US"}, // CN is in allow list
			denyList:      []string{"CN"},       // But also in deny list
			expectBlocked: true,
			expectReason:  "country_denied",
		},
		{
			name:          "Case insensitive matching",
			value:         "us",
			allowList:     []string{"US", "CA"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Unknown value with UNK in allow list",
			value:         "UNK",
			allowList:     []string{"US", "UNK"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Unknown value with UNK in deny list",
			value:         "UNK",
			allowList:     nil,
			denyList:      []string{"UNK"},
			expectBlocked: true,
			expectReason:  "country_denied",
		},
		{
			name:          "Whitespace handling",
			value:         "  US  ",
			allowList:     []string{"US"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := h.checkList(tt.value, tt.allowList, tt.denyList, "country")
			assert.Equal(t, tt.expectBlocked, blocked, "blocked")
			assert.Equal(t, tt.expectReason, reason, "reason")
		})
	}
}

func TestHandler_checkListContains(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name          string
		value         string
		allowList     []string
		denyList      []string
		expectBlocked bool
		expectReason  string
	}{
		{
			name:          "No lists configured",
			value:         "Google LLC",
			allowList:     nil,
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "Substring match in allow list",
			value:         "Google LLC",
			allowList:     []string{"Google"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name:          "No substring match in allow list",
			value:         "Amazon.com Inc.",
			allowList:     []string{"Google", "Microsoft"},
			denyList:      nil,
			expectBlocked: true,
			expectReason:  "asn_org_not_allowed",
		},
		{
			name:          "Substring match in deny list",
			value:         "Some Hosting Provider Inc.",
			allowList:     nil,
			denyList:      []string{"Hosting Provider"},
			expectBlocked: true,
			expectReason:  "asn_org_denied",
		},
		{
			name:          "Case insensitive substring match",
			value:         "GOOGLE LLC",
			allowList:     []string{"google"},
			denyList:      nil,
			expectBlocked: false,
			expectReason:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := h.checkListContains(tt.value, tt.allowList, tt.denyList, "asn_org")
			assert.Equal(t, tt.expectBlocked, blocked, "blocked")
			assert.Equal(t, tt.expectReason, reason, "reason")
		})
	}
}

func TestHandler_isBlocked(t *testing.T) {
	tests := []struct {
		name          string
		handler       Handler
		record        *GeoRecord
		expectBlocked bool
		expectReason  string
	}{
		{
			name:    "No rules - allow all",
			handler: Handler{},
			record: &GeoRecord{
				Country:                CountryRecord{ISOCode: "US"},
				AutonomousSystemNumber: 12345,
			},
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name: "Deny country",
			handler: Handler{
				DenyCountries: []string{"CN", "RU"},
			},
			record: &GeoRecord{
				Country: CountryRecord{ISOCode: "CN"},
			},
			expectBlocked: true,
			expectReason:  "country_denied",
		},
		{
			name: "Allow country",
			handler: Handler{
				AllowCountries: []string{"US", "CA"},
			},
			record: &GeoRecord{
				Country: CountryRecord{ISOCode: "US"},
			},
			expectBlocked: false,
			expectReason:  "",
		},
		{
			name: "Country not in allow list",
			handler: Handler{
				AllowCountries: []string{"US", "CA"},
			},
			record: &GeoRecord{
				Country: CountryRecord{ISOCode: "GB"},
			},
			expectBlocked: true,
			expectReason:  "country_not_allowed",
		},
		{
			name: "Deny continent",
			handler: Handler{
				DenyContinents: []string{"AS"},
			},
			record: &GeoRecord{
				Country:   CountryRecord{ISOCode: "CN"},
				Continent: ContinentRecord{Code: "AS"},
			},
			expectBlocked: true,
			expectReason:  "continent_denied",
		},
		{
			name: "Deny ASN",
			handler: Handler{
				DenyASN: []string{"12345", "67890"},
			},
			record: &GeoRecord{
				Country:                CountryRecord{ISOCode: "US"},
				AutonomousSystemNumber: 12345,
			},
			expectBlocked: true,
			expectReason:  "asn_denied",
		},
		{
			name: "Deny ASN org by substring",
			handler: Handler{
				DenyASNOrg: []string{"Malicious Hosting"},
			},
			record: &GeoRecord{
				Country:                      CountryRecord{ISOCode: "US"},
				AutonomousSystemNumber:       99999,
				AutonomousSystemOrganization: "Malicious Hosting Provider LLC",
			},
			expectBlocked: true,
			expectReason:  "asn_org_denied",
		},
		{
			name: "Deny subdivision",
			handler: Handler{
				DenySubdivisions: []string{"CA"},
			},
			record: &GeoRecord{
				Country: CountryRecord{ISOCode: "US"},
				Subdivisions: []SubdivisionRecord{
					{ISOCode: "CA"},
				},
			},
			expectBlocked: true,
			expectReason:  "subdivision_denied",
		},
		{
			name: "Deny city",
			handler: Handler{
				DenyCities: []string{"Beijing"},
			},
			record: &GeoRecord{
				Country: CountryRecord{ISOCode: "CN"},
				City:    CityRecord{Names: map[string]string{"en": "Beijing"}},
			},
			expectBlocked: true,
			expectReason:  "city_denied",
		},
		{
			name: "Multiple rules - first match wins",
			handler: Handler{
				DenyCountries:  []string{"CN"},
				DenyContinents: []string{"AS"},
			},
			record: &GeoRecord{
				Country:   CountryRecord{ISOCode: "CN"},
				Continent: ContinentRecord{Code: "AS"},
			},
			expectBlocked: true,
			expectReason:  "country_denied", // Country is checked first
		},
		{
			name: "Unknown country with UNK denied",
			handler: Handler{
				DenyCountries: []string{"UNK"},
			},
			record:        &GeoRecord{},
			expectBlocked: true,
			expectReason:  "country_denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := tt.handler.isBlocked(tt.record)
			assert.Equal(t, tt.expectBlocked, blocked, "blocked")
			assert.Equal(t, tt.expectReason, reason, "reason")
		})
	}
}

func TestHandler_Validate(t *testing.T) {
	tests := []struct {
		name        string
		handler     Handler
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid configuration",
			handler: Handler{
				DatabasePaths:     []string{"/path/to/db.mmdb"},
				BlockedStatusCode: 403,
			},
			expectError: false,
		},
		{
			name: "Missing database paths",
			handler: Handler{
				BlockedStatusCode: 403,
			},
			expectError: true,
			errorMsg:    "at least one database path is required",
		},
		{
			name: "Empty database paths slice",
			handler: Handler{
				DatabasePaths:     []string{},
				BlockedStatusCode: 403,
			},
			expectError: true,
			errorMsg:    "at least one database path is required",
		},
		{
			name: "Invalid status code - too low",
			handler: Handler{
				DatabasePaths:     []string{"/path/to/db.mmdb"},
				BlockedStatusCode: 50,
			},
			expectError: true,
			errorMsg:    "blocked_status_code must be a valid HTTP status code",
		},
		{
			name: "Invalid status code - too high",
			handler: Handler{
				DatabasePaths:     []string{"/path/to/db.mmdb"},
				BlockedStatusCode: 600,
			},
			expectError: true,
			errorMsg:    "blocked_status_code must be a valid HTTP status code",
		},
		{
			name: "Zero status code is valid (will use default)",
			handler: Handler{
				DatabasePaths:     []string{"/path/to/db.mmdb"},
				BlockedStatusCode: 0,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.handler.Validate()
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

func TestHandler_CaddyModule(t *testing.T) {
	h := Handler{}
	info := h.CaddyModule()

	assert.Equal(t, "http.handlers.geoblock", string(info.ID))
	assert.NotNil(t, info.New)

	// Test that New() returns a new Handler
	newModule := info.New()
	_, ok := newModule.(*Handler)
	assert.True(t, ok, "New() should return *Handler")
}
