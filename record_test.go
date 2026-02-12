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

func TestCountryRecord_Name(t *testing.T) {
	tests := []struct {
		name     string
		record   CountryRecord
		expected string
	}{
		{
			name: "With English name",
			record: CountryRecord{
				ISOCode: "US",
				Names:   map[string]string{"en": "United States", "de": "Vereinigte Staaten"},
			},
			expected: "United States",
		},
		{
			name: "Without English name",
			record: CountryRecord{
				ISOCode: "DE",
				Names:   map[string]string{"de": "Deutschland"},
			},
			expected: "",
		},
		{
			name:     "Nil names map",
			record:   CountryRecord{ISOCode: "US"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.Name())
		})
	}
}

func TestCityRecord_Name(t *testing.T) {
	tests := []struct {
		name     string
		record   CityRecord
		expected string
	}{
		{
			name: "With English name",
			record: CityRecord{
				Names: map[string]string{"en": "New York", "es": "Nueva York"},
			},
			expected: "New York",
		},
		{
			name:     "Nil names map",
			record:   CityRecord{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.Name())
		})
	}
}

func TestContinentRecord_Name(t *testing.T) {
	tests := []struct {
		name     string
		record   ContinentRecord
		expected string
	}{
		{
			name: "With English name",
			record: ContinentRecord{
				Code:  "NA",
				Names: map[string]string{"en": "North America"},
			},
			expected: "North America",
		},
		{
			name:     "Nil names map",
			record:   ContinentRecord{Code: "NA"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.Name())
		})
	}
}

func TestSubdivisionRecord_Name(t *testing.T) {
	tests := []struct {
		name     string
		record   SubdivisionRecord
		expected string
	}{
		{
			name: "With English name",
			record: SubdivisionRecord{
				ISOCode: "CA",
				Names:   map[string]string{"en": "California"},
			},
			expected: "California",
		},
		{
			name:     "Nil names map",
			record:   SubdivisionRecord{ISOCode: "CA"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.Name())
		})
	}
}

func TestGeoRecord_GetSubdivisionCodes(t *testing.T) {
	tests := []struct {
		name     string
		record   GeoRecord
		expected []string
	}{
		{
			name: "Multiple subdivisions",
			record: GeoRecord{
				Subdivisions: []SubdivisionRecord{
					{ISOCode: "CA"},
					{ISOCode: "LA"},
				},
			},
			expected: []string{"CA", "LA"},
		},
		{
			name: "Single subdivision",
			record: GeoRecord{
				Subdivisions: []SubdivisionRecord{
					{ISOCode: "NY"},
				},
			},
			expected: []string{"NY"},
		},
		{
			name:     "No subdivisions",
			record:   GeoRecord{},
			expected: []string{},
		},
		{
			name: "Empty ISO code filtered out",
			record: GeoRecord{
				Subdivisions: []SubdivisionRecord{
					{ISOCode: "CA"},
					{ISOCode: ""},
					{ISOCode: "NY"},
				},
			},
			expected: []string{"CA", "NY"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.record.GetSubdivisionCodes()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGeoRecord_GetSubdivisionNames(t *testing.T) {
	record := GeoRecord{
		Subdivisions: []SubdivisionRecord{
			{ISOCode: "CA", Names: map[string]string{"en": "California"}},
			{ISOCode: "LA", Names: map[string]string{"en": "Los Angeles County"}},
			{ISOCode: "XX", Names: nil}, // No name, should be filtered
		},
	}

	expected := []string{"California", "Los Angeles County"}
	assert.Equal(t, expected, record.GetSubdivisionNames())
}

func TestGeoRecord_SubdivisionStrings(t *testing.T) {
	record := GeoRecord{
		Subdivisions: []SubdivisionRecord{
			{ISOCode: "CA", Names: map[string]string{"en": "California"}},
			{ISOCode: "LA", Names: map[string]string{"en": "Los Angeles County"}},
		},
	}

	assert.Equal(t, "CA,LA", record.SubdivisionCodesString())
	assert.Equal(t, "California,Los Angeles County", record.SubdivisionNamesString())
}

func TestGeoRecord_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		record   GeoRecord
		expected bool
	}{
		{
			name:     "Empty record",
			record:   GeoRecord{},
			expected: true,
		},
		{
			name: "Has country",
			record: GeoRecord{
				Country: CountryRecord{ISOCode: "US"},
			},
			expected: false,
		},
		{
			name: "Has city",
			record: GeoRecord{
				City: CityRecord{Names: map[string]string{"en": "New York"}},
			},
			expected: false,
		},
		{
			name: "Has continent",
			record: GeoRecord{
				Continent: ContinentRecord{Code: "NA"},
			},
			expected: false,
		},
		{
			name: "Has ASN",
			record: GeoRecord{
				AutonomousSystemNumber: 12345,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.IsEmpty())
		})
	}
}

func TestGeoRecord_GetCountryCode(t *testing.T) {
	tests := []struct {
		name     string
		record   GeoRecord
		expected string
	}{
		{
			name: "Has country code",
			record: GeoRecord{
				Country: CountryRecord{ISOCode: "US"},
			},
			expected: "US",
		},
		{
			name:     "Empty country code",
			record:   GeoRecord{},
			expected: UnknownValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.GetCountryCode())
		})
	}
}

func TestGeoRecord_GetContinentCode(t *testing.T) {
	tests := []struct {
		name     string
		record   GeoRecord
		expected string
	}{
		{
			name: "Has continent code",
			record: GeoRecord{
				Continent: ContinentRecord{Code: "NA"},
			},
			expected: "NA",
		},
		{
			name:     "Empty continent code",
			record:   GeoRecord{},
			expected: UnknownValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.GetContinentCode())
		})
	}
}

func TestGeoRecord_GetASNString(t *testing.T) {
	tests := []struct {
		name     string
		record   GeoRecord
		expected string
	}{
		{
			name: "Has ASN",
			record: GeoRecord{
				AutonomousSystemNumber: 12345,
			},
			expected: "12345",
		},
		{
			name:     "Zero ASN",
			record:   GeoRecord{},
			expected: UnknownValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.record.GetASNString()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUnknownValue(t *testing.T) {
	assert.Equal(t, "UNK", UnknownValue)
}
