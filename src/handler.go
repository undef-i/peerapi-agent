package main

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

func initRouter(app *fiber.App) {
	app.Use(Protected())
	app.Get("/status", status)
	app.Get("/sync", manualSync)
	app.Post("/info", nodePassthroughInfo)
}

func status(c fiber.Ctx) error {
	// Acquire read locks for both session and metric data
	sessionMutex.RLock()
	metricMutex.RLock()

	// Create a response with the current sessions and metrics
	response := AgentApiResponse{
		Code:    0,
		Message: "OK",
		Data: any(map[string]any{
			"sessions": localSessions,
			"metrics":  localMetrics,
		}),
	}

	// Release locks in reverse order of acquisition
	metricMutex.RUnlock()
	sessionMutex.RUnlock()

	return c.JSON(response)
}

func manualSync(c fiber.Ctx) error {
	go syncSessions()
	return c.JSON(AgentApiResponse{
		Code:    0,
		Message: "Sync Triggered",
		Data:    nil,
	})
}

func nodePassthroughInfo(c fiber.Ctx) error {
	// Parse the request body
	var req NodePassthroughRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(AgentApiResponse{
			Code:    fiber.StatusBadRequest,
			Message: "Invalid request format",
			Data:    err,
		})
	}

	switch req.Data.LinkType {
	case "wireguard":
		return getWireGuardPassthroughInfo(c, &req)
	case "gre":
		return getGREPassthroughInfo(c, &req, false)
	case "ip6gre":
		return getGREPassthroughInfo(c, &req, true)
	default:
		return c.JSON(AgentApiResponse{
			Code:    fiber.StatusBadRequest,
			Message: "Link(Interface) type not supported",
			Data:    nil,
		})
	}
}

func getWireGuardPassthroughInfo(c fiber.Ctx, req *NodePassthroughRequest) error {
	port, err := getRandomUnusedPort("udp")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(AgentApiResponse{
			Code:    fiber.StatusInternalServerError,
			Message: "Failed to get random unused port",
			Data:    nil,
		})
	}

	// Create the passthrough data
	data := map[string]any{
		"asn":  req.ASN,
		"port": port,
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	tokenString, err := token.SignedString([]byte(cfg.PeerAPI.SessionPassthroughJwtSecert))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(AgentApiResponse{
			Code:    fiber.StatusInternalServerError,
			Message: "Failed to create token",
			Data:    nil,
		})
	}

	// Create response with endpoint and WireGuard public key
	endpoint := cfg.WireGuard.LocalEndpointHost
	if strings.Contains(endpoint, ":") {
		endpoint = fmt.Sprintf("[%s]", endpoint)
	}
	response := map[string]string{
		"passthrough": tokenString,
		"info": fmt.Sprintf(
			"**Endpoint**: ```%s:%d```\n\n**WireGuard** Public Key: ```%s```",
			endpoint,
			port,
			strings.TrimSpace(cfg.WireGuard.PublicKey),
		),
	}

	return c.JSON(AgentApiResponse{
		Code:    0,
		Message: "OK",
		Data:    response,
	})
}

// getGREPassthroughInfo generates passthrough information for GRE tunnel sessions
// The isIPv6 parameter determines whether to use IPv6GRE (true) or IPv4GRE (false)
func getGREPassthroughInfo(c fiber.Ctx, req *NodePassthroughRequest, isIPv6 bool) error {
	// Create the passthrough data (no port required for GRE tunnels)
	data := map[string]any{
		"asn": req.ASN,
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(data))
	tokenString, err := token.SignedString([]byte(cfg.PeerAPI.SessionPassthroughJwtSecert))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(AgentApiResponse{
			Code:    fiber.StatusInternalServerError,
			Message: "Failed to create token",
			Data:    nil,
		})
	}

	// Select the appropriate endpoint based on GRE type (IPv4 or IPv6)
	var endpoint string
	var tunnelType string
	if isIPv6 {
		endpoint = cfg.GRE.LocalEndpointHost6
		tunnelType = "GRE over IPv6(ip6gre)"
	} else {
		endpoint = cfg.GRE.LocalEndpointHost4
		tunnelType = "GRE over IPv4(gre)"
	}

	endpoint = strings.TrimSpace(endpoint)

	// Create response with endpoint info
	response := map[string]string{
		"passthrough": tokenString,
		"info": fmt.Sprintf(
			"- Keep in mind that GRE Tunnels are not safe, as traffic is not going to be encrypted\n- You can create only 1 session with the same endpoint\n- You must use IP instead of hostname for endpoint\n\n**Endpoint**: ```%s```\n\n**Tunnel Type**: ```%s```",
			endpoint,
			tunnelType,
		),
	}

	return c.JSON(AgentApiResponse{
		Code:    0,
		Message: "OK",
		Data:    response,
	})
}
