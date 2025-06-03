package main

import (
	"encoding/json"
	"os"
)

type serverConfig struct {
	Debug           bool     `json:"debug"` // Will print detail access log for debug
	Listen          string   `json:"listen"`
	BodyLimit       int      `json:"bodyLimit"`
	ReadTimeout     int      `json:"readTimeout"`
	WriteTimeout    int      `json:"writeTimeout"`
	IdleTimeout     int      `json:"idleTimeout"`
	ReadBufferSize  int      `json:"readBufferSize"`
	WriteBufferSize int      `json:"writeBufferSize"`
	TrustedProxies  []string `json:"trustedProxies"` // String array of IP or CIDR.
	// X-Forwarded headers from these networks will be trusted.
}

type birdConfig struct {
	ControlSocket string `json:"controlSocket"`
}

type config struct {
	Server serverConfig `json:"server"`
	Bird   birdConfig   `json:"bird"`
}

func loadConfig(filename string) (*config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := &config{}

	err = json.NewDecoder(file).Decode(cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
