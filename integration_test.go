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
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests use MaxMind's test databases which have known IP -> location mappings.
// Test database IPs (from MaxMind test data):
//   - 81.2.69.142    -> GB (United Kingdom), London
//   - 216.160.83.56  -> US (United States), Milton
//   - 89.160.20.112  -> SE (Sweden)
//   - 2.125.160.216  -> GB (United Kingdom)
//   - 175.16.199.0   -> CN (China)
//   - 81.2.69.160    -> GB (United Kingdom) - London
//
// The tests configure Caddy to trust X-Forwarded-For from localhost,
// allowing us to simulate requests from different IPs.

const (
	// Test IPs from MaxMind test databases
	testIPUnitedKingdom = "81.2.69.142"
	testIPUnitedStates  = "216.160.83.56"
	testIPSweden        = "89.160.20.112"
	testIPChina         = "175.16.199.0"
	testIPPrivate       = "192.168.1.100"
	testIPLoopback      = "127.0.0.1"
)

func TestIntegration_DenyCountries(t *testing.T) {
	// Config that denies CN (China) and allows everything else
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-Country-Test.mmdb"],
									"deny_countries": ["CN"],
									"blocked_status_code": 403,
									"blocked_message": "Country blocked"
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	tests := []struct {
		name           string
		clientIP       string
		expectedStatus int
	}{
		{"UK IP should be allowed", testIPUnitedKingdom, 200},
		{"US IP should be allowed", testIPUnitedStates, 200},
		{"Sweden IP should be allowed", testIPSweden, 200},
		{"China IP should be blocked", testIPChina, 403},
		{"Private IP should be allowed", testIPPrivate, 200},
		{"Loopback should be allowed", testIPLoopback, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://localhost:8080", nil)
			require.NoError(t, err)
			req.Header.Set("X-Forwarded-For", tt.clientIP)

			resp := tester.AssertResponseCode(req, tt.expectedStatus)
			resp.Body.Close()
		})
	}
}

func TestIntegration_AllowCountries(t *testing.T) {
	// Config that only allows US and GB
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-Country-Test.mmdb"],
									"allow_countries": ["US", "GB"],
									"blocked_status_code": 451,
									"blocked_message": "Region not allowed"
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	tests := []struct {
		name           string
		clientIP       string
		expectedStatus int
	}{
		{"UK IP should be allowed", testIPUnitedKingdom, 200},
		{"US IP should be allowed", testIPUnitedStates, 200},
		{"Sweden IP should be blocked", testIPSweden, 451},
		{"China IP should be blocked", testIPChina, 451},
		{"Private IP should always be allowed", testIPPrivate, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://localhost:8080", nil)
			require.NoError(t, err)
			req.Header.Set("X-Forwarded-For", tt.clientIP)

			resp := tester.AssertResponseCode(req, tt.expectedStatus)
			resp.Body.Close()
		})
	}
}

func TestIntegration_DenyTakesPrecedence(t *testing.T) {
	// Config where GB is in both allow and deny - deny should take precedence
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-Country-Test.mmdb"],
									"allow_countries": ["US", "GB"],
									"deny_countries": ["GB"],
									"blocked_status_code": 403
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	// UK should be blocked even though it's in allow list (deny takes precedence)
	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", testIPUnitedKingdom)

	resp := tester.AssertResponseCode(req, 403)
	resp.Body.Close()

	// US should still be allowed
	req2, err := http.NewRequest("GET", "http://localhost:8080", nil)
	require.NoError(t, err)
	req2.Header.Set("X-Forwarded-For", testIPUnitedStates)

	resp2 := tester.AssertResponseCode(req2, 200)
	resp2.Body.Close()
}

func TestIntegration_IPRanges(t *testing.T) {
	// Config with IP range rules
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-Country-Test.mmdb"],
									"allow_ip_ranges": ["81.2.69.0/24"],
									"deny_ip_ranges": ["81.2.69.142/32"],
									"blocked_status_code": 403
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	tests := []struct {
		name           string
		clientIP       string
		expectedStatus int
	}{
		{"IP in allow range but also in deny range should be blocked", "81.2.69.142", 403},
		{"IP in allow range should be allowed", "81.2.69.143", 200},
		{"IP outside all ranges goes to geo check (US)", testIPUnitedStates, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://localhost:8080", nil)
			require.NoError(t, err)
			req.Header.Set("X-Forwarded-For", tt.clientIP)

			resp := tester.AssertResponseCode(req, tt.expectedStatus)
			resp.Body.Close()
		})
	}
}

func TestIntegration_MultipleDatabases(t *testing.T) {
	// Config using both City and ASN databases
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": [
										"testdata/GeoIP2-City-Test.mmdb",
										"testdata/GeoLite2-ASN-Test.mmdb"
									],
									"deny_countries": ["CN"]
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	// Test that it works with multiple databases
	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", testIPUnitedKingdom)

	resp := tester.AssertResponseCode(req, 200)
	resp.Body.Close()
}

func TestIntegration_Placeholders(t *testing.T) {
	// Config that returns geo info in response body using placeholders
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-City-Test.mmdb"]
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "country={geoblock.country_code},blocked={geoblock.blocked}"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", testIPUnitedKingdom)

	resp := tester.AssertResponseCode(req, 200)
	defer resp.Body.Close()

	// Read response body
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	// Check that placeholders were expanded
	assert.Contains(t, bodyStr, "country=GB", "Country code should be GB for UK IP")
	assert.Contains(t, bodyStr, "blocked=false", "Should not be blocked")
}

func TestIntegration_UnknownIPHandling(t *testing.T) {
	// Config that denies unknown countries
	config := `{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"http": {
				"servers": {
					"test": {
						"listen": [":8080"],
						"trusted_proxies": {
							"source": "static",
							"ranges": ["127.0.0.1/8", "::1/128"]
						},
						"routes": [{
							"handle": [
								{
									"handler": "geoblock",
									"db_paths": ["testdata/GeoIP2-Country-Test.mmdb"],
									"deny_countries": ["UNK"],
									"blocked_status_code": 403
								},
								{
									"handler": "static_response",
									"status_code": 200,
									"body": "OK"
								}
							]
						}]
					}
				}
			}
		}
	}`

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	// IP that's not in the test database should be treated as UNK
	// Using an IP that's unlikely to be in the test database
	req, err := http.NewRequest("GET", "http://localhost:8080", nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-For", "203.0.113.1") // TEST-NET-3, not in MaxMind test DB

	resp := tester.AssertResponseCode(req, 403)
	resp.Body.Close()
}

func TestIntegration_CaddyfileConfig(t *testing.T) {
	// Test using Caddyfile format
	caddyfile := `
	{
		admin localhost:2999
		http_port 8080
	}
	
	:8080 {
		@geo {
			client_ip forwarded
		}
		
		geoblock {
			db_path testdata/GeoIP2-Country-Test.mmdb
			deny_countries CN
			blocked_status 403
			blocked_message "Blocked"
		}
		
		respond "OK" 200
	}
	`

	tester := caddytest.NewTester(t)
	tester.InitServer(caddyfile, "caddyfile")

	// Test that the server starts and responds
	// Note: Without trusted_proxies in Caddyfile, X-Forwarded-For won't be trusted
	// So this just tests that the config parses and server starts
	tester.AssertGetResponse("http://localhost:8080", 200, "OK")
}
