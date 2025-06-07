package main

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	bearerScheme = "Bearer "
)

// verifyBearerToken verifies if the request has a valid bearer token
// The token should be a bcrypt hash of agentSecret+routerUuid
func verifyBearerToken(c fiber.Ctx, token, routerUUID string) bool {
	authHeader := c.Get("Authorization")
	if !strings.HasPrefix(authHeader, bearerScheme) {
		return false
	}

	tokenStr := authHeader[len(bearerScheme):]

	// Check if it's our own token going outbound
	if subtle.ConstantTimeCompare([]byte(tokenStr), []byte(token)) == 1 {
		return true
	}

	// Otherwise verify the inbound bcrypt hash
	err := bcrypt.CompareHashAndPassword([]byte(tokenStr), []byte(cfg.PeerAPI.AgentSecret+cfg.PeerAPI.RouterUUID))
	return err == nil
}

// generateToken generates a bcrypt token for outbound requests
func generateToken() (string, error) {
	if cfg.PeerAPI.Secret == "" || cfg.PeerAPI.RouterUUID == "" {
		return "", errors.New("missing PeerAPI secret or router UUID in config")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.PeerAPI.Secret+cfg.PeerAPI.RouterUUID), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Protected middleware protects routes with bearer token authentication
func Protected() fiber.Handler {
	return func(c fiber.Ctx) error {
		if !verifyBearerToken(c, "", c.Params("router")) {
			return c.Status(fiber.StatusUnauthorized).JSON(AgentApiResponse{
				Code: 401,
			})
		}
		return c.Next()
	}
}
