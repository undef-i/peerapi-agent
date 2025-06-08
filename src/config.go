package main

import (
	"encoding/json"
	"os"
	"text/template"
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
	TrustedProxies  []string `json:"trustedProxies"` // String array of IP or CIDR. X-Forwarded headers from these networks will be trusted.
}

type peerApiCenterConfig struct {
	URL                         string   `json:"url"`               // URL of the PeerAPI center server
	Secret                      string   `json:"secret"`            // Secret key for PeerAPI center authentication
	RequestTimeout              int      `json:"requestTimeout"`    // Timeout for requests to the PeerAPI center
	RouterUUID                  string   `json:"routerUuid"`        // UUID of this router from PeerAPI center server
	AgentSecret                 string   `json:"agentSecret"`       // Secret key for agent authentication
	HeartbeatInterval           int      `json:"heartbeatInterval"` // Heartbeat interval in seconds
	SyncInterval                int      `json:"syncInterval"`      // Session sync interval in seconds
	MetricInterval              int      `json:"metricInterval"`
	WanInterfaces               []string `json:"wanInterfaces"` // List of WAN interfaces to monitor their traffic
	SessionPassthroughJwtSecert string   `json:"sessionPassthroughJwtSecert"`
}

type birdConfig struct {
	ControlSocket           string             `json:"controlSocket"`
	PoolSize                int                `json:"poolSize"`                // Number of connections to the BIRD control socket
	PoolSizeMax             int                `json:"poolSizeMax"`             // Maximum size of the connection pool
	BGPPeerConfDir          string             `json:"bgpPeerConfDir"`          // Directory for BGP peer configuration files
	BGPPeerConfTemplateFile string             `json:"bgpPeerConfTemplateFile"` // Template for BGP peer configuration files
	BGPPeerConfTemplate     *template.Template `json:"-"`
	IPCommandPath           string             `json:"ipCommandPath"`
}

type wireGuardConfig struct {
	WGCommandPath                  string `json:"wgCommandPath"`     // Path to the WireGuard command
	IPv4                           string `json:"ipv4"`              // IPv4 address for WireGuard interface
	IPv6                           string `json:"ipv6"`              // IPv6 address for WireGuard interface
	IPv6LinkLocal                  string `json:"ipv6LinkLocal"`     // IPv6 link-local address for WireGuard interface
	LocalEndpointHost              string `json:"LocalEndpointHost"` // Local endpoint for WireGuard interface
	PrivateKeyPath                 string `json:"privateKeyPath"`    // Private key for WireGuard interface
	PublicKeyPath                  string `json:"publicKeyPath"`     // Public key for WireGuard interface
	PrivateKey                     string `json:"-"`
	PublicKey                      string `json:"-"`
	PersistentKeepaliveInterval    int    `json:"persistentKeepaliveInterval"` // Persistent keepalive interval in seconds
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

type greConfig struct {
	IPv4                           string `json:"ipv4"`               // IPv4 address for GRE interface
	IPv6                           string `json:"ipv6"`               // IPv6 address for GRE interface
	IPv6LinkLocal                  string `json:"ipv6LinkLocal"`      // IPv6 link-local address for GRE interface
	LocalEndpointHost4             string `json:"localEndpointHost4"` // Local IPv4 endpoint for GRE tunnel
	LocalEndpointHost6             string `json:"localEndpointHost6"` // Local IPv6 endpoint for GRE tunnel
	DN42BandwidthCommunity         int    `json:"dn42BandwidthCommunity"`
	DN42InterfaceSecurityCommunity int    `json:"dn42InterfaceSecurityCommunity"`
}

type metricConfig struct {
	AutoTeardown                  bool     `json:"autoTeardown"`                  // Automatically teardown sessions based on metrics
	MaxMindGeoLiteCountryMmdbPath string   `json:"maxMindGeoLiteCountryMmdbPath"` // Path to MaxMind GeoLite2 Country database
	GeoIPCountryMode              string   `json:"geoIPCountryMode"`              // Mode for GeoIP country filtering (blacklist/whitelist)
	BlacklistGeoCountries         []string `json:"blacklistGeoCountries"`         // List of countries to blacklist
	WhitelistGeoCountries         []string `json:"whitelistGeoCountries"`         // List of countries to whitelist
	PingTimeout                   int      `json:"pingTimeout"`                   // Timeout for ping requests in seconds
	PingCount                     int      `json:"pingCount"`                     // Number of ping attempts
}

type config struct {
	Server    serverConfig        `json:"server"`
	PeerAPI   peerApiCenterConfig `json:"peerApiCenter"`
	Bird      birdConfig          `json:"bird"`
	Metric    metricConfig        `json:"metric"`
	WireGuard wireGuardConfig     `json:"wireGuard"`
	GRE       greConfig           `json:"gre"`
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

	if cfg.WireGuard.PrivateKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PrivateKeyPath)
		if err != nil {
			return cfg, err
		}
		cfg.WireGuard.PrivateKey = string(key)
	}

	if cfg.WireGuard.PublicKeyPath != "" {
		key, err := os.ReadFile(cfg.WireGuard.PublicKeyPath)
		if err != nil {
			return cfg, err
		}
		cfg.WireGuard.PublicKey = string(key)
	}

	if cfg.Bird.BGPPeerConfTemplateFile != "" {
		tmpl, err := template.ParseFiles(cfg.Bird.BGPPeerConfTemplateFile)
		if err != nil {
			return cfg, err
		}
		cfg.Bird.BGPPeerConfTemplate = tmpl
	}

	return cfg, nil
}
