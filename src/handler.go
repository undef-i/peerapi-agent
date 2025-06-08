package main

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/golang-jwt/jwt/v5"
)

func initRouter(app *fiber.App) {
	app.Use(Protected())
	app.Get("/", status)
	app.Get("/sync", manualSync)
	app.Post("/info", nodePassthroughInfo)
}

func status(c fiber.Ctx) error {
	mutex.RLock()
	defer mutex.RUnlock()
	return c.JSON(AgentApiResponse{
		Code:    0,
		Message: "OK",
		Data: any(map[string]any{
			"sessions": localSessions,
			"metrics":  localMetrics,
		}),
	})
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
			Data:    nil,
		})
	}

	if req.Data.LinkType == "wireguard" {
		return getWireGuardPassthroughInfo(c, &req)
	}

	return c.JSON(AgentApiResponse{
		Code:    fiber.StatusBadRequest,
		Message: "Link(Interface) type not supported",
		Data:    nil,
	})
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
			cfg.WireGuard.PublicKey,
		),
	}

	return c.JSON(AgentApiResponse{
		Code:    0,
		Message: "OK",
		Data:    response,
	})
}
