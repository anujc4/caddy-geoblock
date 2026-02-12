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
	"strconv"

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
	GeoFilterConfig

	// BlockedStatusCode is the HTTP status code to return when a request is blocked.
	// Default: 403 (Forbidden)
	BlockedStatusCode int `json:"blocked_status_code,omitempty"`

	// BlockedMessage is the message to include in the error response.
	// Supports placeholders like {geoblock.country_code}.
	// Default: "Access denied"
	BlockedMessage string `json:"blocked_message,omitempty"`

	// Internal fields
	filter *GeoFilter
	logger *zap.Logger
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

	// Initialize the geo filter
	h.filter = NewGeoFilter(&h.GeoFilterConfig, h.logger)
	if err := h.filter.Provision(ctx); err != nil {
		return err
	}

	return nil
}

// Validate ensures the handler is properly configured.
func (h *Handler) Validate() error {
	if err := h.filter.Validate(); err != nil {
		return err
	}

	// Zero is allowed (will use default), but if set, must be valid
	if h.BlockedStatusCode != 0 && (h.BlockedStatusCode < 100 || h.BlockedStatusCode > 599) {
		return fmt.Errorf("blocked_status_code must be a valid HTTP status code (100-599)")
	}

	return nil
}

// Cleanup releases resources held by the handler.
func (h *Handler) Cleanup() error {
	if h.filter != nil {
		return h.filter.Cleanup()
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

	// Perform the geo filtering check
	result := h.filter.CheckIP(clientIP)

	// Set placeholders with geo data
	h.setPlaceholders(r, repl, result)

	// Block if necessary
	if result.Blocked {
		return h.blockRequest(w, r, repl, result.Reason)
	}

	return next.ServeHTTP(w, r)
}

// setPlaceholders sets all geoblock placeholders in the request context.
// These are accessible via {http.request.var.geoblock.*} placeholders.
func (h *Handler) setPlaceholders(r *http.Request, repl *caddy.Replacer, result FilterResult) {
	// Set vars in request context for use by other handlers
	caddyhttp.SetVar(r.Context(), "geoblock.blocked", strconv.FormatBool(result.Blocked))
	caddyhttp.SetVar(r.Context(), "geoblock.blocked_reason", result.Reason)

	// Also set in replacer for use in templates and messages
	repl.Set("geoblock.blocked", strconv.FormatBool(result.Blocked))
	repl.Set("geoblock.blocked_reason", result.Reason)

	if result.Record == nil {
		setEmptyVars(r, repl)
		return
	}

	// Set all geo data in both context vars and replacer
	setVar(r, repl, "geoblock.country_code", result.Record.Country.ISOCode)
	setVar(r, repl, "geoblock.country_name", result.Record.Country.Name())
	setVar(r, repl, "geoblock.city_name", result.Record.City.Name())
	setVar(r, repl, "geoblock.continent_code", result.Record.Continent.Code)
	setVar(r, repl, "geoblock.continent_name", result.Record.Continent.Name())
	setVar(r, repl, "geoblock.subdivision_code", result.Record.SubdivisionCodesString())
	setVar(r, repl, "geoblock.subdivision_name", result.Record.SubdivisionNamesString())
	setVar(r, repl, "geoblock.asn", strconv.Itoa(result.Record.AutonomousSystemNumber))
	setVar(r, repl, "geoblock.asn_org", result.Record.AutonomousSystemOrganization)
	setVar(r, repl, "geoblock.latitude", strconv.FormatFloat(result.Record.Location.Latitude, 'f', 6, 64))
	setVar(r, repl, "geoblock.longitude", strconv.FormatFloat(result.Record.Location.Longitude, 'f', 6, 64))
	setVar(r, repl, "geoblock.time_zone", result.Record.Location.TimeZone)
	setVar(r, repl, "geoblock.postal_code", result.Record.Postal.Code)
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

// isBlocked is used by tests to check if a request would be blocked.
// It delegates to the GeoFilter's isBlocked method.
func (h *Handler) isBlocked(record *GeoRecord) (bool, string) {
	// Create a temporary filter with the handler's config for testing
	tempFilter := &GeoFilter{config: &h.GeoFilterConfig}
	return tempFilter.isBlocked(record)
}

// checkList is used by tests to check value against allow/deny lists.
// It delegates to the GeoFilter's checkList method.
func (h *Handler) checkList(value string, allowList, denyList []string, fieldName string) (bool, string) {
	tempFilter := &GeoFilter{config: &h.GeoFilterConfig}
	return tempFilter.checkList(value, allowList, denyList, fieldName)
}

// checkListContains is used by tests to check value against allow/deny lists with substring matching.
// It delegates to the GeoFilter's checkListContains method.
func (h *Handler) checkListContains(value string, allowList, denyList []string, fieldName string) (bool, string) {
	tempFilter := &GeoFilter{config: &h.GeoFilterConfig}
	return tempFilter.checkListContains(value, allowList, denyList, fieldName)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
