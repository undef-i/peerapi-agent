package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
)

type BirdTemplateData struct {
	SessionName       string
	InterfaceAddr     string
	ASN               int
	IPv4ShouldImport  bool
	IPv4ShouldExport  bool
	IPv6ShouldImport  bool
	IPv6ShouldExport  bool
	ExtendedNextHopOn bool
	FilterParams      string
}

func configureInterface(session *BgpSession) error {
	// Add wireguard interface if needed
	if session.Type == "wireguard" {

		if session.Credential == "" {
			return fmt.Errorf("empty credential(used as publickey) specified")
		}

		// Ensure the interface is deleted first, then create it
		exec.Command("ip", "link", "del", "dev", session.Interface).Run()
		if err := exec.Command("ip", "link", "add", "dev", session.Interface, "type", "wireguard").Run(); err != nil {
			return fmt.Errorf("failed to create wireguard interface: %v", err)
		}

		// If the interface is already configured, delete it first
		if err := deleteInterface(session.Interface); err != nil {
			return fmt.Errorf("failed to delete existing interface: %v", err)
		}
		// Recreate the interface
		if err := exec.Command("ip", "link", "add", session.Interface, "type", "wireguard").Run(); err != nil {
			return fmt.Errorf("failed to recreate wireguard interface: %v", err)
		}

		// Create WireGuard interface
		if err := exec.Command("wg", "set", session.Interface,
			"private-key", cfg.WireGuard.PrivateKey,
			"peer", session.Credential,
			"endpoint", session.Endpoint,
			"allowed-ips", "172.16.0.0/12,10.0.0.0/8,fd00::/8,fe80::/10").Run(); err != nil {
			return fmt.Errorf("failed to configure wireguard: %v", err)
		}

		// Configure addresses
		if session.IPv4 != "" {
			if err := exec.Command("ip", "addr", "add", "dev", session.Interface, cfg.WireGuard.IPv4+"/32", "peer", session.IPv4+"/32").Run(); err != nil {
				return fmt.Errorf("failed to add IPv4: %v", err)
			}
		}
		if session.IPv6LinkLocal != "" {
			if err := exec.Command("ip", "addr", "add", "dev", session.Interface, cfg.WireGuard.IPv6LinkLocal+"/64", "peer", session.IPv6LinkLocal+"/64").Run(); err != nil {
				return fmt.Errorf("failed to add IPv6 link-local: %v", err)
			}
		} else if session.IPv6 != "" {
			if err := exec.Command("ip", "addr", "add", "dev", session.Interface, cfg.WireGuard.IPv6+"/128", "peer", session.IPv6+"/128").Run(); err != nil {
				return fmt.Errorf("failed to add IPv6: %v", err)
			}
		}

		// Set MTU
		if err := exec.Command("ip", "link", "set", "mtu", strconv.Itoa(session.MTU), "dev", session.Interface).Run(); err != nil {
			return fmt.Errorf("failed to set MTU: %v", err)
		}

		// Bring up interface
		if err := exec.Command("ip", "link", "set", "up", "dev", session.Interface).Run(); err != nil {
			return fmt.Errorf("failed to bring up interface: %v", err)
		}

	}

	return fmt.Errorf("unsupported session type: %s", session.Type)
}

func deleteInterface(iface string) error {
	if exist, _ := interfaceExists(iface); !exist {
		exec.Command("ip", "link", "del", "dev", iface).Run() // dismiss error
		return nil
	}
	exec.Command("ip", "link", "set", "down", "dev", iface).Run()
	if err := exec.Command("ip", "link", "del", "dev", iface).Run(); err != nil {
		return fmt.Errorf("failed to delete interface: %v", err)
	}
	return nil
}

func configureBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	os.Remove(confPath)

	if cfg.Bird.BGPPeerConfTemplate == nil {
		return fmt.Errorf("failed to read bird peer configuration template")
	}

	ifBwCommunity := 24
	ifSecCommunity := 31
	if session.Type == "wireguard" {
		ifBwCommunity = cfg.WireGuard.DN42BandwidthCommunity
		ifSecCommunity = cfg.WireGuard.DN42InterfaceSecurityCommunity
	}

	mpBGP := slices.Contains(session.Extensions, "mp-bgp")
	extendedNexthop := slices.Contains(session.Extensions, "extended-nexthop")

	// Create output file
	outFile, err := os.Create(confPath)
	if err != nil {
		return fmt.Errorf("failed to create bird template file: %v", err)
	}
	defer outFile.Close()

	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)

	if mpBGP {
		var interfaceAddr string
		if session.IPv6LinkLocal != "" {
			interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
		} else if session.IPv6 != "" {
			interfaceAddr = session.IPv6
		} else if session.IPv4 != "" {
			interfaceAddr = session.IPv4
		} else {
			return fmt.Errorf("no valid interface addresses for peering session: %v", session.UUID)
		}
		cfg.Bird.BGPPeerConfTemplate.Execute(outFile, BirdTemplateData{
			SessionName:       sessionName,
			InterfaceAddr:     interfaceAddr,
			ASN:               session.ASN,
			IPv4ShouldImport:  true,
			IPv4ShouldExport:  true,
			IPv6ShouldImport:  true,
			IPv6ShouldExport:  true,
			ExtendedNextHopOn: extendedNexthop,
			FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
		})
	} else {
		if session.IPv6LinkLocal != "" || session.IPv6 != "" {
			var interfaceAddr string
			if session.IPv6LinkLocal != "" {
				interfaceAddr = fmt.Sprintf("%s%%'%s'", session.IPv6LinkLocal, session.Interface)
			} else if session.IPv6 != "" {
				interfaceAddr = session.IPv6
			}
			// Protocol for IPv6
			cfg.Bird.BGPPeerConfTemplate.Execute(outFile, BirdTemplateData{
				SessionName:       sessionName + "_v6",
				InterfaceAddr:     interfaceAddr,
				ASN:               session.ASN,
				IPv4ShouldImport:  false,
				IPv4ShouldExport:  false,
				IPv6ShouldImport:  true,
				IPv6ShouldExport:  true,
				ExtendedNextHopOn: extendedNexthop,
				FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
			})
		}
		if session.IPv4 != "" {
			// Protocol for IPv4
			cfg.Bird.BGPPeerConfTemplate.Execute(outFile, BirdTemplateData{
				SessionName:       sessionName + "_v4",
				InterfaceAddr:     session.IPv4,
				ASN:               session.ASN,
				IPv4ShouldImport:  true,
				IPv4ShouldExport:  true,
				IPv6ShouldImport:  false,
				IPv6ShouldExport:  false,
				ExtendedNextHopOn: extendedNexthop,
				FilterParams:      fmt.Sprintf("%d,%d,%d,%d", 0, ifBwCommunity, ifSecCommunity, session.Policy),
			})
		}

	}

	return nil
}

func deleteBird(session *BgpSession) error {
	confPath := path.Join(cfg.Bird.BGPPeerConfDir, session.Interface+".conf")
	return os.Remove(confPath)
}

func configureSession(session *BgpSession) error {
	err := configureInterface(session)
	if err != nil {
		return err
	}
	return configureBird(session)
}

func deleteSession(session *BgpSession) error {
	err := deleteInterface(session.Interface)
	if err != nil {
		return err
	}
	return deleteBird(session)
}
