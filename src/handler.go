package main

import (
	"github.com/gofiber/fiber/v3"
)

func initRouter(app *fiber.App) {
	app.Get("/", index)
}

func index(c fiber.Ctx) error {
	return c.SendString("Hello World!")
}

// func initRouter(app *fiber.App) {
// 	api := app.Group("/agent/:router")
// 	api.Use(Protected())

// 	api.Post("/heartbeat", heartbeat)
// 	api.Get("/sessions", sessions)
// 	api.Post("/report", report)
// 	api.Post("/modify", modify)
// }

// func heartbeat(c fiber.Ctx) error {
// 	hostname, _ := os.Hostname()
// 	kernel := fmt.Sprintf("%s %s %s", runtime.GOOS, runtime.GOARCH, runtime.Version())

// 	return c.JSON(ApiResponse{
// 		Success: true,
// 		Code:    fiber.StatusOK,
// 		Data: map[string]interface{}{
// 			"version": SERVER_SIGNATURE,
// 			"kernel":  kernel,
// 			"uptime":  time.Now().Unix(), // TODO: Get real system uptime
// 			"rs":      hostname,
// 			"tcp":     0, // TODO: Get TCP connections count
// 			"udp":     0, // TODO: Get UDP connections count
// 		},
// 	})
// }

// func sessions(c fiber.Ctx) error {
// 	// Fetch sessions from manager API
// 	url := fmt.Sprintf("%s/agent/%s/sessions", cfg.Server.ManagerURL, c.Params("router"))
// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return err
// 	}

// 	req.Header.Set("Authorization", "Bearer "+token)

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	var result struct {
// 		Success bool `json:"success"`
// 		Code    int  `json:"code"`
// 		Data    struct {
// 			BgpSessions []BgpSession `json:"bgpSessions"`
// 		} `json:"data"`
// 	}

// 	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
// 		return err
// 	}

// 	// Process sessions
// 	for _, session := range result.Data.BgpSessions {
// 		switch session.Status {
// 		case STATUS_DELETED, STATUS_QUEUED_FOR_DELETE:
// 			// Delete configuration
// 			netMgr.deleteInterface(session.Interface)
// 			birdPool.configureSession(session)

// 		case STATUS_ENABLED, STATUS_QUEUED_FOR_SETUP:
// 			// Create/update configuration
// 			if err := netMgr.configureInterface(session); err != nil {
// 				// Report problem
// 				session.Status = STATUS_PROBLEM
// 				reportSessionStatus(session.UUID, STATUS_PROBLEM)
// 				continue
// 			}
// 			if err := birdPool.configureSession(session); err != nil {
// 				session.Status = STATUS_PROBLEM
// 				reportSessionStatus(session.UUID, STATUS_PROBLEM)
// 				continue
// 			}

// 		case STATUS_DISABLED:
// 			// Disable configuration
// 			netMgr.deleteInterface(session.Interface)
// 			birdPool.configureSession(session)
// 		}
// 	}

// 	return c.JSON(ApiResponse{
// 		Success: true,
// 		Code:    fiber.StatusOK,
// 	})
// }

// func report(c fiber.Ctx) error {
// 	reports, err := birdPool.collectMetrics()
// 	if err != nil {
// 		return err
// 	}

// 	// Add interface metrics
// 	for i := range reports {
// 		if state, err := netMgr.getInterfaceState(reports[i].UUID); err == nil {
// 			reports[i].Interface = state
// 		}
// 	}

// 	// Send report to manager
// 	url := fmt.Sprintf("%s/agent/%s/report", cfg.Server.ManagerURL, c.Params("router"))
// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	jsonData, _ := json.Marshal(map[string]interface{}{
// 		"sessions": reports,
// 	})

// 	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
// 	if err != nil {
// 		return err
// 	}

// 	req.Header.Set("Authorization", "Bearer "+token)
// 	req.Header.Set("Content-Type", "application/json")

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	return c.JSON(ApiResponse{
// 		Success: true,
// 		Code:    fiber.StatusOK,
// 	})
// }

// func modify(c fiber.Ctx) error {
// 	var req SessionModifyRequest
// 	if err := c.BodyParser(&req); err != nil {
// 		return err
// 	}

// 	url := fmt.Sprintf("%s/agent/%s/modify", cfg.Server.ManagerURL, c.Params("router"))
// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	jsonData, _ := json.Marshal(req)

// 	httpReq, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
// 	if err != nil {
// 		return err
// 	}

// 	httpReq.Header.Set("Authorization", "Bearer "+token)
// 	httpReq.Header.Set("Content-Type", "application/json")

// 	client := &http.Client{}
// 	resp, err := client.Do(httpReq)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	return c.JSON(ApiResponse{
// 		Success: true,
// 		Code:    fiber.StatusOK,
// 	})
// }

// func reportSessionStatus(sessionID string, status int) error {
// 	url := fmt.Sprintf("%s/agent/%s/modify", cfg.Server.ManagerURL, cfg.Server.RouterUUID)
// 	token, err := generateToken()
// 	if err != nil {
// 		return err
// 	}

// 	jsonData, _ := json.Marshal(SessionModifyRequest{
// 		Session: sessionID,
// 		Status:  status,
// 	})

// 	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonData)))
// 	if err != nil {
// 		return err
// 	}

// 	req.Header.Set("Authorization", "Bearer "+token)
// 	req.Header.Set("Content-Type", "application/json")

// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	return nil
// }
