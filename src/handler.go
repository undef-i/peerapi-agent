package main

import (
	"bufio"

	"github.com/gofiber/fiber/v3"
	"github.com/iedon/peerapi-agent/bird"
)

func initRouter(app *fiber.App) {
	app.Get("/", index)
	app.Get("/birdc", birdc)
}

func index(c fiber.Ctx) error {
	return c.SendString("Hello World!")
}

func birdc(c fiber.Ctx) error {
	conn, err := bird.Open(cfg.Bird.ControlSocket)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).SendString(err.Error())
	}

	entered, err := bird.Restrict(conn)
	if err != nil || !entered {
		if err != nil {
			bird.Close(conn)
		}
		errorMessage := "Failed to enter restrict mode"
		if err != nil {
			errorMessage = err.Error()
		}
		return c.Status(fiber.StatusBadGateway).SendString(errorMessage)
	}

	prompt := c.Query("prompt")
	if prompt == "" {
		bird.Close(conn)
		return c.Status(fiber.StatusBadRequest).SendString("Prompt parameter is required")
	}

	if err := bird.Write(conn, prompt); err != nil {
		bird.Close(conn)
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to write command")
	}

	return c.Type("txt").SendStreamWriter(func(w *bufio.Writer) {
		defer bird.Close(conn)
		bird.Read(conn, w)
	})
}
