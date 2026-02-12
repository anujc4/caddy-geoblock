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
	"strings"
)

// GeoRecord holds all geographic and network information retrieved from MaxMind databases.
// This is a unified struct that can be populated from any combination of MaxMind databases
// (GeoLite2-Country, GeoLite2-City, GeoLite2-ASN, or their commercial equivalents).
type GeoRecord struct {
	Country      CountryRecord       `maxminddb:"country"`
	City         CityRecord          `maxminddb:"city"`
	Continent    ContinentRecord     `maxminddb:"continent"`
	Location     LocationRecord      `maxminddb:"location"`
	Postal       PostalRecord        `maxminddb:"postal"`
	Subdivisions []SubdivisionRecord `maxminddb:"subdivisions"`

	// ASN fields (from GeoLite2-ASN database)
	AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// CountryRecord contains country-level information.
type CountryRecord struct {
	GeoNameID         uint              `maxminddb:"geoname_id"`
	IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
	ISOCode           string            `maxminddb:"iso_code"`
	Names             map[string]string `maxminddb:"names"`
}

// Name returns the country name in English, or empty string if not available.
func (c CountryRecord) Name() string {
	if c.Names == nil {
		return ""
	}
	return c.Names["en"]
}

// CityRecord contains city-level information.
type CityRecord struct {
	GeoNameID uint              `maxminddb:"geoname_id"`
	Names     map[string]string `maxminddb:"names"`
}

// Name returns the city name in English, or empty string if not available.
func (c CityRecord) Name() string {
	if c.Names == nil {
		return ""
	}
	return c.Names["en"]
}

// ContinentRecord contains continent-level information.
type ContinentRecord struct {
	GeoNameID uint              `maxminddb:"geoname_id"`
	Code      string            `maxminddb:"code"`
	Names     map[string]string `maxminddb:"names"`
}

// Name returns the continent name in English, or empty string if not available.
func (c ContinentRecord) Name() string {
	if c.Names == nil {
		return ""
	}
	return c.Names["en"]
}

// LocationRecord contains geographic coordinates and related information.
type LocationRecord struct {
	AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
	Latitude       float64 `maxminddb:"latitude"`
	Longitude      float64 `maxminddb:"longitude"`
	MetroCode      uint    `maxminddb:"metro_code"`
	TimeZone       string  `maxminddb:"time_zone"`
}

// PostalRecord contains postal code information.
type PostalRecord struct {
	Code string `maxminddb:"code"`
}

// SubdivisionRecord contains subdivision (state/province/region) information.
type SubdivisionRecord struct {
	GeoNameID uint              `maxminddb:"geoname_id"`
	ISOCode   string            `maxminddb:"iso_code"`
	Names     map[string]string `maxminddb:"names"`
}

// Name returns the subdivision name in English, or empty string if not available.
func (s SubdivisionRecord) Name() string {
	if s.Names == nil {
		return ""
	}
	return s.Names["en"]
}

// GetSubdivisionCodes returns a slice of all subdivision ISO codes.
func (r *GeoRecord) GetSubdivisionCodes() []string {
	codes := make([]string, 0, len(r.Subdivisions))
	for _, sub := range r.Subdivisions {
		if sub.ISOCode != "" {
			codes = append(codes, sub.ISOCode)
		}
	}
	return codes
}

// GetSubdivisionNames returns a slice of all subdivision names in English.
func (r *GeoRecord) GetSubdivisionNames() []string {
	names := make([]string, 0, len(r.Subdivisions))
	for _, sub := range r.Subdivisions {
		if name := sub.Name(); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// SubdivisionCodesString returns comma-separated subdivision ISO codes.
func (r *GeoRecord) SubdivisionCodesString() string {
	return strings.Join(r.GetSubdivisionCodes(), ",")
}

// SubdivisionNamesString returns comma-separated subdivision names.
func (r *GeoRecord) SubdivisionNamesString() string {
	return strings.Join(r.GetSubdivisionNames(), ",")
}

// IsEmpty returns true if the record contains no meaningful data.
func (r *GeoRecord) IsEmpty() bool {
	return r.Country.ISOCode == "" &&
		r.City.Name() == "" &&
		r.Continent.Code == "" &&
		r.AutonomousSystemNumber == 0
}

// UnknownValue is used as a placeholder when a field cannot be determined.
const UnknownValue = "UNK"

// GetCountryCode returns the country ISO code or UnknownValue if not available.
func (r *GeoRecord) GetCountryCode() string {
	if r.Country.ISOCode == "" {
		return UnknownValue
	}
	return r.Country.ISOCode
}

// GetContinentCode returns the continent code or UnknownValue if not available.
func (r *GeoRecord) GetContinentCode() string {
	if r.Continent.Code == "" {
		return UnknownValue
	}
	return r.Continent.Code
}

// GetASNString returns the ASN as a string or UnknownValue if not available.
func (r *GeoRecord) GetASNString() string {
	if r.AutonomousSystemNumber == 0 {
		return UnknownValue
	}
	return strconv.Itoa(r.AutonomousSystemNumber)
}
