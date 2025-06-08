// Package main implements the peerapi agent functionality
// This file focuses on session management tasks
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/client"
)

const (
	PEERING_STATUS_DELETED = iota
	PEERING_STATUS_DISABLED
	PEERING_STATUS_ENABLED
	PEERING_STATUS_PENDING_APPROVAL
	PEERING_STATUS_QUEUED_FOR_SETUP
	PEERING_STATUS_QUEUED_FOR_DELETE
	PEERING_STATUS_PROBLEM
	PEERING_STATUS_TEARDOWN
)

// getBgpSessions fetches BGP session information from the PeerAPI server
func getBgpSessions() ([]BgpSession, error) {
	// Create HTTP client with timeout
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)

	// Build request URL
	url := fmt.Sprintf("%s/agent/%s/sessions", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)

	// Generate authentication token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to generate token: %v", err)
	}

	// Send request to PeerAPI
	agent.SetHeader("Authorization", "Bearer\x20"+token)
	resp, err := agent.Get(url)

	if err != nil {
		if resp != nil {
			resp.Close()
		}
		return nil, fmt.Errorf("[GetBGPSessions] failed to get sessions: %v", err)
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("[GetBGPSessions] failed to get sessions, status code: %d", resp.StatusCode())
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to parse response: %v", err)
	}

	if response.Code != 0 {
		return nil, fmt.Errorf("[GetBGPSessions] peerAPI returned error: %s", response.Message)
	}

	// Parse BGP sessions data
	var data BgpSessionsResponse
	err = json.Unmarshal(response.Data, &data)
	if err != nil {
		return nil, fmt.Errorf("[GetBGPSessions] failed to parse BGP sessions data: %v", err)
	}

	return data.BgpSessions, nil
}

// reportNewStatusToCenter reports a session status change to the PeerAPI server
func reportNewStatusToCenter(sessionUUID string, status int) error {
	// Create HTTP client with timeout
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)

	// Build request URL
	url := fmt.Sprintf("%s/agent/%s/modify", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)

	// Generate authentication token
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("<%s> failed to generate token: %v", sessionUUID, err)
	}

	// Send request to PeerAPI
	agent.SetHeader("Authorization", "Bearer\x20"+token)
	resp, err := agent.Post(url, client.Config{
		Body: map[string]any{
			"status":  status,
			"session": sessionUUID,
		},
	})

	if err != nil {
		if resp != nil {
			resp.Close()
		}
		return fmt.Errorf("<%s> failed to notify: %v", sessionUUID, err)
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		return fmt.Errorf("<%s> failed to notify, status code: %d", sessionUUID, resp.StatusCode())
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		return fmt.Errorf("<%s> failed to parse response: %v", sessionUUID, err)
	}

	if response.Code != 0 {
		return fmt.Errorf("<%s> peerAPI returned error: %s", sessionUUID, response.Message)
	}

	return nil
}

// processNewSession handles a newly discovered session
func processNewSession(session *BgpSession, nextLocal map[string]BgpSession) {
	switch session.Status {
	case PEERING_STATUS_QUEUED_FOR_SETUP:
		configureSession(session)
		err := reportNewStatusToCenter(session.UUID, PEERING_STATUS_ENABLED)
		if err == nil {
			session.Status = PEERING_STATUS_ENABLED
			log.Printf("[SyncSessions] Session %s has been configured and enabled", session.UUID)
		} else {
			log.Printf("[SyncSessions] Session %s has been configured but status update failed: %v",
				session.UUID, err)
		}
	case PEERING_STATUS_ENABLED, PEERING_STATUS_PROBLEM:
		configureSession(session)
		log.Printf("[SyncSessions] Session %s has been configured", session.UUID)
	default:
		log.Printf("[SyncSessions] Skipping session %s with status %d", session.UUID, session.Status)
	}
	nextLocal[session.UUID] = *session
}

// processChangedSession handles a session that has changed configuration
func processChangedSession(newSession *BgpSession, oldSession *BgpSession, nextLocal map[string]BgpSession) {
	if reflect.DeepEqual(*newSession, *oldSession) {
		// No changes, just copy to the new map
		nextLocal[newSession.UUID] = *newSession
		return
	}

	// Handle session based on its new status
	switch newSession.Status {
	case PEERING_STATUS_DISABLED, PEERING_STATUS_DELETED, PEERING_STATUS_TEARDOWN:
		deleteSession(oldSession)
		log.Printf("[SyncSessions] Session %s has been deleted due to status change to %d",
			newSession.UUID, newSession.Status)

	case PEERING_STATUS_QUEUED_FOR_DELETE:
		deleteSession(oldSession)
		err := reportNewStatusToCenter(newSession.UUID, PEERING_STATUS_DELETED)
		if err == nil {
			newSession.Status = PEERING_STATUS_DELETED
			log.Printf("[SyncSessions] Session %s has been deleted and status updated", newSession.UUID)
		} else {
			log.Printf("[SyncSessions] Session %s has been deleted but status update failed: %v",
				newSession.UUID, err)
		}

	case PEERING_STATUS_QUEUED_FOR_SETUP:
		configureSession(newSession)
		err := reportNewStatusToCenter(newSession.UUID, PEERING_STATUS_ENABLED)
		if err == nil {
			newSession.Status = PEERING_STATUS_ENABLED
			log.Printf("[SyncSessions] Session %s has been reconfigured and enabled", newSession.UUID)
		} else {
			log.Printf("[SyncSessions] Session %s has been reconfigured but status update failed: %v",
				newSession.UUID, err)
		}

	case PEERING_STATUS_ENABLED, PEERING_STATUS_PROBLEM:
		configureSession(newSession)
		log.Printf("[SyncSessions] Session %s has been reconfigured", newSession.UUID)
	}

	// Update the session in the new map
	nextLocal[newSession.UUID] = *newSession
}

// processDeletedSession handles a session that has been removed from the PeerAPI
func processDeletedSession(session *BgpSession) {
	deleteSession(session)
	log.Printf("[SyncSessions] Session %s has been removed from PeerAPI", session.UUID)
}

// mainSessionTask is the main function for session management
func mainSessionTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.SyncInterval) * time.Second)
	defer ticker.Stop()

	log.Println("[SessionSync] Starting session synchronization task")

	// Sync sessions immediately on startup
	syncSessions()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[SessionSync] Shutting down session synchronization task...")

			// Perform any session-specific cleanup
			sessionMutex.RLock()
			sessionCount := len(localSessions)
			sessionMutex.RUnlock()
			log.Printf("[SessionSync] Cleaning up %d managed BGP sessions", sessionCount)

			log.Printf("[SessionSync] Session synchronization task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			syncSessions()
		}
	}
}

// syncSessions synchronizes local sessions with the PeerAPI server
func syncSessions() {
	remoteSessions, err := getBgpSessions()
	if err != nil {
		log.Printf("[SyncSessions] Failed to get remote sessions: %v", err)
		return
	}

	nextLocal := make(map[string]BgpSession)
	remoteSessionUUIDs := make(map[string]struct{})

	// Process remote sessions
	for i := range remoteSessions {
		session := &remoteSessions[i]
		remoteSessionUUIDs[session.UUID] = struct{}{}
		sessionMutex.RLock()
		oldSession, exists := localSessions[session.UUID]
		sessionMutex.RUnlock()

		if !exists {
			// New session
			processNewSession(session, nextLocal)
		} else {
			// Existing session that may have changed
			processChangedSession(session, &oldSession, nextLocal)
		}
	}
	// Handle sessions that were deleted from the remote side
	sessionMutex.RLock()
	for uuid, session := range localSessions {
		if _, exists := remoteSessionUUIDs[uuid]; !exists {
			processDeletedSession(&session)
		}
	}
	sessionMutex.RUnlock()
	// Update local sessions map
	sessionMutex.Lock()
	localSessions = nextLocal
	sessionMutex.Unlock()
}
