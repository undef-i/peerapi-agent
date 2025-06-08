package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionData holds the parsed JSON from the session.Data field
type SessionData struct {
	Passthrough string `json:"passthrough"`
	Info        string `json:"info"`
}

// PassthroughData holds the values decoded from the JWT passthrough
type PassthroughData struct {
	ASN  uint `json:"asn"`
	Port int  `json:"port"`
}

// BirdTemplateData holds the data needed to render a BIRD configuration template
type BirdTemplateData struct {
	SessionName       string // Name of the BGP session
	InterfaceAddr     string // Interface address for the BGP connection
	ASN               uint   // Autonomous System Number of the peer
	IPv4ShouldImport  bool   // Whether to import IPv4 routes
	IPv4ShouldExport  bool   // Whether to export IPv4 routes
	IPv6ShouldImport  bool   // Whether to import IPv6 routes
	IPv6ShouldExport  bool   // Whether to export IPv6 routes
	ExtendedNextHopOn bool   // Whether to enable extended next hop
	FilterParams      string // Parameters for BGP filtering
}

var birdConfMutex sync.Mutex

// configureInterface sets up network interfaces based on the BGP session parameters.
// Currently supports WireGuard and GRE interface types.
func configureInterface(session *BgpSession) error {
	// Set a timeout for commands to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Printf("Configuring interface for session %s (asn: %d, type: %s, interface: %s)",
		session.UUID, session.ASN, session.Type, session.Interface)

	switch session.Type {
	case "wireguard":
		return configureWireguardInterface(ctx, session)
	case "gre", "ip6gre":
		return configureGreInterface(ctx, session)
	default:
		return fmt.Errorf("unsupported session type: %s", session.Type)
	}
}

// configureWireguardInterface sets up a WireGuard interface for the BGP session
func configureWireguardInterface(ctx context.Context, session *BgpSession) error {
	if session.Credential == "" {
		return fmt.Errorf("empty credential (used as publickey) specified")
	}

	// Delete the interface if it exists to ensure clean state
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
		// Continue anyway as we'll try to recreate it
	}

	// Create the new interface
	cmd := exec.CommandContext(ctx, "ip", "link", "add", "dev", session.Interface, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create wireguard interface: %v", err)
	}

	// Parse session data to get the port from passthrough JWT
	var port int
	if session.Data != "" {
		var sessionData SessionData
		if err := json.Unmarshal([]byte(session.Data), &sessionData); err != nil {
			log.Printf("Warning: Failed to parse session data: %v", err)
		} else if sessionData.Passthrough != "" {
			// Parse the JWT token from passthrough
			token, err := jwt.Parse(sessionData.Passthrough, func(token *jwt.Token) (any, error) {
				// Validate the signing method
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(cfg.PeerAPI.SessionPassthroughJwtSecert), nil
			})

			if err != nil {
				return fmt.Errorf("failed to decode session passthrough data: %v", err)
			} else if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				if portValue, exists := claims["port"]; exists {
					// Try to convert the port value to int
					port, ok = portValue.(int)
					if !ok {
						return fmt.Errorf("failed to decode port for wireguard: %v", err)
					}
				}
			}
		}
	}

	// Configure the peer settings
	wgArgs := []string{
		"set", session.Interface,
		"private-key", cfg.WireGuard.PrivateKey,
		"listen-port", strconv.Itoa(port),
		"peer", session.Credential,
		"endpoint", session.Endpoint,
		"persistent-keepalive", strconv.Itoa(cfg.WireGuard.PersistentKeepaliveInterval),
		"allowed-ips", "172.16.0.0/12,10.0.0.0/8,fd00::/8,fe80::/10",
	}

	cmd = exec.CommandContext(ctx, "wg", wgArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure wireguard: %v", err)
	}

	// Configure IP addresses
	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	// Set MTU
	cmd = exec.CommandContext(ctx, "ip", "link", "set", "mtu", strconv.Itoa(session.MTU), "dev", session.Interface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Bring up interface
	cmd = exec.CommandContext(ctx, "ip", "link", "set", "up", "dev", session.Interface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	log.Printf("Successfully configured WireGuard interface %s for session %s",
		session.Interface, session.UUID)
	return nil
}

// configureGreInterface sets up a GRE tunnel for the BGP session
// Handles both IPv4 GRE (gre) and IPv6 GRE (ip6gre) tunnel types
func configureGreInterface(ctx context.Context, session *BgpSession) error {
	// Delete the interface if it exists to ensure clean state
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete existing interface %s: %v", session.Interface, err)
		// Continue anyway as we'll try to recreate it
	}

	var cmd *exec.Cmd
	isIPv6 := session.Type == "ip6gre"

	if isIPv6 {
		// IPv6 GRE tunnel (ip6gre)
		cmd = exec.CommandContext(ctx, "ip", "-6", "tunnel", "add", session.Interface,
			"mode", "ip6gre",
			"local", cfg.GRE.LocalEndpointHost6,
			"remote", session.Endpoint)

		log.Printf("Creating IPv6 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost6, session.Endpoint)
	} else {
		// IPv4 GRE tunnel (gre)
		cmd = exec.CommandContext(ctx, "ip", "tunnel", "add", session.Interface,
			"mode", "gre",
			"local", cfg.GRE.LocalEndpointHost4,
			"remote", session.Endpoint)

		log.Printf("Creating IPv4 GRE tunnel: %s with local: %s remote: %s",
			session.Interface, cfg.GRE.LocalEndpointHost4, session.Endpoint)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create %s tunnel: %v", session.Type, err)
	}

	// Configure IP addresses
	if err := configureIPAddresses(ctx, session); err != nil {
		return err
	}

	// Set MTU
	cmd = exec.CommandContext(ctx, "ip", "link", "set", "mtu", strconv.Itoa(session.MTU), "dev", session.Interface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Bring up interface
	cmd = exec.CommandContext(ctx, "ip", "link", "set", "up", "dev", session.Interface)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	log.Printf("Successfully configured %s interface %s for session %s",
		session.Type, session.Interface, session.UUID)
	return nil
}

// configureIPAddresses sets up IP addresses on the interface
func configureIPAddresses(ctx context.Context, session *BgpSession) error {
	// Get local IP configuration based on session type
	var localIPv4, localIPv6, localIPv6LinkLocal string

	switch session.Type {
	case "wireguard":
		localIPv4 = cfg.WireGuard.IPv4
		localIPv6 = cfg.WireGuard.IPv6
		localIPv6LinkLocal = cfg.WireGuard.IPv6LinkLocal
	case "gre", "ip6gre":
		localIPv4 = cfg.GRE.IPv4
		localIPv6 = cfg.GRE.IPv6
		localIPv6LinkLocal = cfg.GRE.IPv6LinkLocal
	default:
		// Use WireGuard as fallback for unknown types
		localIPv4 = cfg.WireGuard.IPv4
		localIPv6 = cfg.WireGuard.IPv6
		localIPv6LinkLocal = cfg.WireGuard.IPv6LinkLocal
	}

	// Configure IPv4 if provided
	if session.IPv4 != "" {
		cmd := exec.CommandContext(ctx, "ip", "addr", "add", "dev", session.Interface,
			localIPv4+"/32", "peer", session.IPv4+"/32")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add IPv4: %v", err)
		}
		log.Printf("Added IPv4 address %s to interface %s", session.IPv4, session.Interface)
	}

	// Configure IPv6 Link-Local if provided, otherwise use global IPv6
	if session.IPv6LinkLocal != "" {
		cmd := exec.CommandContext(ctx, "ip", "addr", "add", "dev", session.Interface,
			localIPv6LinkLocal+"/64", "peer", session.IPv6LinkLocal+"/64")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add IPv6 link-local: %v", err)
		}
		log.Printf("Added IPv6 link-local address %s to interface %s",
			session.IPv6LinkLocal, session.Interface)
	} else if session.IPv6 != "" {
		cmd := exec.CommandContext(ctx, "ip", "addr", "add", "dev", session.Interface,
			localIPv6+"/128", "peer", session.IPv6+"/128")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add IPv6: %v", err)
		}
		log.Printf("Added IPv6 address %s to interface %s", session.IPv6, session.Interface)
	}

	return nil
}

// deleteInterface removes a network interface
func deleteInterface(iface string) error {
	// Set a timeout for commands to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	exist, err := interfaceExists(iface)
	if err != nil {
		log.Printf("Warning: Failed to check if interface %s exists: %v", iface, err)
		// Continue anyway to try deletion
	}

	if !exist {
		log.Printf("Interface %s does not exist, no need to delete", iface)
		return nil
	}

	// Bring the interface down first
	downCmd := exec.CommandContext(ctx, "ip", "link", "set", "down", "dev", iface)
	if err := downCmd.Run(); err != nil {
		log.Printf("Warning: Failed to bring down interface %s: %v", iface, err)
		// Continue with deletion anyway
	}

	// Delete the interface
	delCmd := exec.CommandContext(ctx, "ip", "link", "del", "dev", iface)
	if err := delCmd.Run(); err != nil {
		return fmt.Errorf("failed to delete interface %s: %v", iface, err)
	}

	log.Printf("Successfully deleted interface %s", iface)
	return nil
}

// configureBird generates and writes the BIRD configuration for a BGP session
func configureBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	log.Printf("Configuring BIRD for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	// Remove existing config file if it exists
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: Failed to remove existing BIRD config at %s: %v", confPath, err)
		// Continue anyway
	}

	// Ensure the template is loaded
	if cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("BIRD peer configuration template is not initialized")
	}

	// Determine community values based on session type
	ifBwCommunity, ifSecCommunity := getCommunityValues(session.Type)

	// Check if MP-BGP or extended nexthop is enabled
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(session.Extensions, "extended-nexthop")

	// Create output file
	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create BIRD config file %s: %v", confPath, err)
	}
	defer outFile.Close()

	// Generate base session name
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	// Generate the configuration based on BGP type
	if mpBGP {
		// For MP-BGP, generate a single protocol that handles both IPv4 and IPv6
		if err := generateMPBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	} else {
		// For traditional BGP, generate separate protocols for IPv4 and IPv6
		if err := generateTraditionalBGPConfig(outFile, session, sessionName, extendedNexthop, ifBwCommunity, ifSecCommunity); err != nil {
			return err
		}
	}

	if ok, err := birdPool.Configure(); err != nil {
		log.Printf("failed to configure BIRD: %v", err)
	} else if !ok {
		log.Printf("BIRD configuration failed")
	}

	log.Printf("Configured BIRD for session %s", session.UUID)
	return nil
}

// getCommunityValues returns the bandwidth and security community values based on session type
func getCommunityValues(sessionType string) (int, int) {
	// Default values for unknown session types
	ifBwCommunity := 24
	ifSecCommunity := 31

	// Override defaults for known session types
	switch sessionType {
	case "wireguard":
		ifBwCommunity = cfg.WireGuard.DN42BandwidthCommunity
		ifSecCommunity = cfg.WireGuard.DN42InterfaceSecurityCommunity
	case "gre", "ip6gre":
		ifBwCommunity = cfg.GRE.DN42BandwidthCommunity
		ifSecCommunity = cfg.GRE.DN42InterfaceSecurityCommunity
	}

	return ifBwCommunity, ifSecCommunity
}

// generateMPBGPConfig creates a single MP-BGP protocol configuration
func generateMPBGPConfig(outFile *os.File, session *BgpSession, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	interfaceAddr, err := getNeighborAddress(session)
	if err != nil {
		return err
	}

	templateData := BirdTemplateData{
		SessionName:       sessionName,
		InterfaceAddr:     interfaceAddr,
		ASN:               session.ASN,
		IPv4ShouldImport:  true,
		IPv4ShouldExport:  true,
		IPv6ShouldImport:  true,
		IPv6ShouldExport:  true,
		ExtendedNextHopOn: extendedNexthop,
		FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
	}

	if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
		return fmt.Errorf("failed to generate MP-BGP config: %v", err)
	}

	return nil
}

// generateTraditionalBGPConfig creates separate configurations for IPv4 and IPv6 BGP
func generateTraditionalBGPConfig(outFile *os.File, session *BgpSession, sessionName string, extendedNexthop bool, ifBwCommunity, ifSecCommunity int) error {
	// Generate IPv6 config if IPv6 addresses are available
	if session.IPv6LinkLocal != "" || session.IPv6 != "" {
		var interfaceAddr string
		if session.IPv6LinkLocal != "" {
			interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
		} else if session.IPv6 != "" {
			interfaceAddr = session.IPv6
		}

		templateData := BirdTemplateData{
			SessionName:       sessionName + "_v6",
			InterfaceAddr:     interfaceAddr,
			ASN:               session.ASN,
			IPv4ShouldImport:  false,
			IPv4ShouldExport:  false,
			IPv6ShouldImport:  true,
			IPv6ShouldExport:  true,
			ExtendedNextHopOn: extendedNexthop,
			FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
		}

		if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv6 BGP config: %v", err)
		}
	}

	// Generate IPv4 config if an IPv4 address is available
	if session.IPv4 != "" {
		templateData := BirdTemplateData{
			SessionName:       sessionName + "_v4",
			InterfaceAddr:     session.IPv4,
			ASN:               session.ASN,
			IPv4ShouldImport:  true,
			IPv4ShouldExport:  true,
			IPv6ShouldImport:  false,
			IPv6ShouldExport:  false,
			ExtendedNextHopOn: extendedNexthop,
			FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
		}

		if err := cfg.Bird.BGPPeerConfTemplate.Execute(outFile, templateData); err != nil {
			return fmt.Errorf("failed to generate IPv4 BGP config: %v", err)
		}
	}

	return nil
}

// getNeighborAddress selects the best available interface address for the session
func getNeighborAddress(session *BgpSession) (string, error) {
	// Try to get a suitable interface address in preferred order:
	// 1. IPv6 Link-Local with interface specification
	// 2. Global IPv6
	// 3. IPv4
	if session.IPv6LinkLocal != "" {
		return fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface), nil
	} else if session.IPv6 != "" {
		return session.IPv6, nil
	} else if session.IPv4 != "" {
		return session.IPv4, nil
	}

	return "", fmt.Errorf("no valid interface addresses for peering session %s", session.UUID)
}

// deleteBird removes the BIRD configuration file for a BGP session
func deleteBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	log.Printf("Removing BIRD configuration for session %s (interface: %s)", session.UUID, session.Interface)

	birdConfMutex.Lock()
	defer birdConfMutex.Unlock()

	if err := os.Remove(confPath); err != nil {
		if os.IsNotExist(err) {
			// If file doesn't exist, no need to return an error
			log.Printf("BIRD configuration file %s does not exist, nothing to remove", confPath)
			return nil
		}
		return fmt.Errorf("failed to remove BIRD configuration file %s: %v", confPath, err)
	}

	if ok, err := birdPool.Configure(); err != nil {
		log.Printf("failed to configure BIRD: %v", err)
	} else if !ok {
		log.Printf("BIRD configuration failed")
	}

	log.Printf("Successfully removed BIRD configuration for session %s", session.UUID)
	return nil
}

// configureSession sets up both the network interface and BIRD configuration for a BGP session
func configureSession(session *BgpSession) error {
	log.Printf("Configuring BGP session %s (ASN: %d, Interface: %s)",
		session.UUID, session.ASN, session.Interface)

	// First, configure the network interface
	if err := configureInterface(session); err != nil {
		log.Printf("Failed to configure interface for session %s: %v", session.UUID, err)
		return fmt.Errorf("interface configuration failed: %w", err)
	}

	// Then, configure the BIRD routing daemon
	if err := configureBird(session); err != nil {
		log.Printf("Failed to configure BIRD for session %s: %v", session.UUID, err)
		return fmt.Errorf("BIRD configuration failed: %w", err)
	}

	log.Printf("Successfully configured session %s", session.UUID)
	return nil
}

// deleteSession tears down a BGP session by removing both the interface and BIRD configuration
func deleteSession(session *BgpSession) error {
	log.Printf("Deleting BGP session %s (interface: %s)", session.UUID, session.Interface)

	// First, delete the network interface
	var interfaceErr error
	if err := deleteInterface(session.Interface); err != nil {
		log.Printf("Warning: Failed to delete interface %s: %v", session.Interface, err)
		interfaceErr = err
		// Continue with BIRD config removal even if interface deletion fails
	}

	// Then, delete the BIRD configuration
	birdErr := deleteBird(session)

	// Return interface error if it occurred, otherwise return BIRD error (if any)
	if interfaceErr != nil {
		return interfaceErr
	}

	if birdErr != nil {
		return birdErr
	}

	log.Printf("Successfully deleted session %s", session.UUID)
	return nil
}
