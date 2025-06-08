package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"
)

// checkSessionGeoLocation checks if a session's endpoint location is allowed
// Returns true if the session should be torn down
func checkSessionGeoLocation(session *BgpSession) bool {
	// Skip checking if:
	// - Auto teardown is not enabled
	// - GeoIP database is not initialized
	// - Session endpoint is empty
	if !cfg.Metric.AutoTeardown || geoDB == nil || session.Endpoint == "" {
		return false
	}

	// Get country code from the endpoint
	countryCode, err := geoIPCountryCode(geoDB, session.Endpoint)
	if err != nil {
		log.Printf("<%s> Failed to get country code for %s: %v", session.UUID, session.Endpoint, err)
		return false // On error, don't teardown
	}

	// If country code is empty, don't teardown
	if countryCode == "" {
		return false
	}

	// Check whitelist/blacklist based on configuration
	switch strings.ToLower(cfg.Metric.GeoIPCountryMode) {
	case "whitelist":
		return checkWhitelistMode(session, countryCode)
	case "blacklist":
		return checkBlacklistMode(session, countryCode)
	default:
		// For any other mode, don't teardown
		return false
	}
}

// checkWhitelistMode checks if a country is in the whitelist
// Returns true if the session should be torn down
func checkWhitelistMode(session *BgpSession, countryCode string) bool {
	// In whitelist mode, tear down if country is NOT in the whitelist
	for _, allowedCountry := range cfg.Metric.WhitelistGeoCountries {
		if strings.EqualFold(countryCode, allowedCountry) {
			// Country is in whitelist, so don't teardown
			return false
		}
	}

	// Country not found in whitelist - should be torn down
	log.Printf("<%s> Endpoint %s, Country %s is not in the whitelist, session will be torn down",
		session.UUID, session.Endpoint, countryCode)
	return true
}

// checkBlacklistMode checks if a country is in the blacklist
// Returns true if the session should be torn down
func checkBlacklistMode(session *BgpSession, countryCode string) bool {
	// In blacklist mode, tear down if country IS in the blacklist
	for _, blockedCountry := range cfg.Metric.BlacklistGeoCountries {
		if strings.EqualFold(countryCode, blockedCountry) {
			// Country is in blacklist, so teardown
			log.Printf("<%s> Endpoint %s, Country %s is in the blacklist, session will be torn down",
				session.UUID, session.Endpoint, countryCode)
			return true
		}
	}

	// Country not found in blacklist - should not be torn down
	return false
}

// geoCheckTask runs periodically to check all active sessions against geo rules
func geoCheckTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Skip if geoDB is not initialized
	if geoDB == nil {
		log.Println("[GeoCheck] GeoIP database not initialized, geo checking disabled")
		return
	}

	// Run every 15 minutes by default
	interval := 15 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run an initial check on startup
	performGeoCheck()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[GeoCheck] Shutting down geo check task...")

			// Perform any geo-specific cleanup
			if geoDB != nil {
				log.Println("[GeoCheck] Ensuring GeoIP database is ready for cleanup")
			}

			log.Printf("[GeoCheck] Geo check task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			performGeoCheck()
		}
	}
}

// performGeoCheck checks all active sessions against geo rules
func performGeoCheck() {
	// Get all active sessions
	sessionMutex.RLock()
	sessionsToCheck := make([]BgpSession, 0, len(localSessions))
	for _, session := range localSessions {
		// Only check active sessions
		if session.Status == PEERING_STATUS_ENABLED || session.Status == PEERING_STATUS_PROBLEM {
			sessionsToCheck = append(sessionsToCheck, session)
		}
	}
	sessionMutex.RUnlock()

	if len(sessionsToCheck) == 0 {
		log.Println("[GeoCheck] No active sessions to check")
		return
	}

	// Check each session against geo rules
	for _, session := range sessionsToCheck {
		if checkSessionGeoLocation(&session) {
			teardownViolatingSession(&session)
		}
	}
}

// teardownViolatingSession tears down a session that violates geo rules
func teardownViolatingSession(session *BgpSession) {
	log.Printf("[GeoCheck] <%s> Session violates geo rules, tearing down", session.UUID)

	// Report teardown status to PeerAPI
	err := reportNewStatusToCenter(session.UUID, PEERING_STATUS_TEARDOWN)
	if err != nil {
		log.Printf("<%s> Failed to report teardown status: %v", session.UUID, err)
	}
}
