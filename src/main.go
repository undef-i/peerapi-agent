package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
)

const (
	SERVER_NAME      = "iEdon-PeerAPI-Agent"
	SERVER_VERSION   = "1.0"
	SERVER_SIGNATURE = SERVER_NAME + "/" + SERVER_VERSION
)

var cfg *config

func main() {
	configFile := flag.String("c", "config.json", "Path to the JSON configuration file")
	help := flag.Bool("h", false, "Print this message")
	flag.Parse()

	if *help {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "[-c config_file]")
		flag.PrintDefaults()
		return
	}

	var err error
	cfg, err = loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v\n", err)
	}

	app := fiber.New(fiber.Config{
		AppName:            SERVER_NAME,
		ServerHeader:       SERVER_SIGNATURE,
		EnableIPValidation: true,
		TrustedProxies:     cfg.Server.TrustedProxies,
		ReadTimeout:        time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:       time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:        time.Duration(cfg.Server.IdleTimeout) * time.Second,
		ReadBufferSize:     cfg.Server.ReadBufferSize,
		WriteBufferSize:    cfg.Server.WriteBufferSize,
		BodyLimit:          cfg.Server.BodyLimit,
	})

	initRouter(app)

	log.Fatal(app.Listen(cfg.Server.Listen))
}
