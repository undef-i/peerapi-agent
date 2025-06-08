package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/iedon/peerapi-agent/bird"
	"github.com/oschwald/geoip2-golang"
)

const (
	SERVER_NAME    = "iEdon-PeerAPI-Agent"
	SERVER_VERSION = "1.0"
)

var SERVER_SIGNATURE = fmt.Sprintf("%s (%s; %s; %s)", SERVER_NAME+"/"+SERVER_VERSION, runtime.GOOS, runtime.GOARCH, runtime.Version())

var (
	cfg      *config
	birdPool *bird.BirdPool
	geoDB    *geoip2.Reader // Global GeoIP database reader
)

// Global state variables for session management task/metric task/monitoring task
var localSessions = make(map[string]BgpSession)
var localMetrics = make(map[string]SessionMetric)
var localTrafficRate = make(map[string]TrafficRate)
var mutex sync.RWMutex
var bwMonitorMutex sync.Mutex

func initBirdConnectionPool() error {
	var err error
	birdPool, err = bird.NewBirdPool(cfg.Bird.ControlSocket, cfg.Bird.PoolSize, cfg.Bird.PoolSizeMax)
	if err != nil {
		return fmt.Errorf("failed to initialize bird manager: %v", err)
	}

	return nil
}

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

	if cfg.Metric.MaxMindGeoLiteCountryMmdbPath != "" {
		db, err := geoip2.Open(cfg.Metric.MaxMindGeoLiteCountryMmdbPath)
		if err != nil {
			log.Fatalf("Failed to load MaxMind GeoLiteCountry MMDB: %v\n", err)
		}
		geoDB = db
	}

	// Initialize managers
	if err := initBirdConnectionPool(); err != nil {
		log.Fatalf("Failed to initialize bird connection pool: %v\n", err)
	}

	app := fiber.New(fiber.Config{
		AppName:            SERVER_NAME,
		ServerHeader:       SERVER_SIGNATURE,
		EnableIPValidation: true,
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: cfg.Server.TrustedProxies},
		ReadTimeout:        time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout:       time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:        time.Duration(cfg.Server.IdleTimeout) * time.Second,
		ReadBufferSize:     cfg.Server.ReadBufferSize,
		WriteBufferSize:    cfg.Server.WriteBufferSize,
		BodyLimit:          cfg.Server.BodyLimit,
	})

	initRouter(app)

	// Start background tasks
	go heartbeatTask()
	go mainSessionTask()
	go metricTask()
	go bandwidthMonitorTask()
	go geoCheckTask()

	log.Fatal(app.Listen(cfg.Server.Listen))
}
