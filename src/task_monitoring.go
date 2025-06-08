package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3/client"
)

// NetStat stores network interface statistics
type NetStat struct {
	Name    string
	RxBytes uint64
	TxBytes uint64
}

// TrafficRate stores network interface traffic rates
type TrafficRate struct {
	Name   string
	RxRate uint64 // in bytes per second
	TxRate uint64 // in bytes per second
}

// bandwidthMonitorTask runs every second to monitor bandwidth usage
func bandwidthMonitorTask() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		monitorTrafficRates()
	}
}

// monitorTrafficRates calculates traffic rates for all network interfaces
func monitorTrafficRates() {
	// Get initial statistics
	stats1, err1 := readNetStats()
	if err1 != nil {
		log.Printf("[BandwidthMonitor] Error reading network stats: %v\n", err1)
		return
	}

	// Wait 1 second to calculate delta
	time.Sleep(1 * time.Second)

	// Get updated statistics
	stats2, err2 := readNetStats()
	if err2 != nil {
		log.Printf("[BandwidthMonitor] Error reading network stats: %v\n", err2)
		return
	}

	bwMonitorMutex.Lock()
	defer bwMonitorMutex.Unlock()

	// Calculate traffic rates for each interface
	for iface, s1 := range stats1 {
		s2, ok := stats2[iface]
		if !ok {
			continue
		}

		// Calculate traffic rates (bytes per second)
		rxRate := s2.RxBytes - s1.RxBytes
		txRate := s2.TxBytes - s1.TxBytes

		// Create or update the traffic rate for this interface
		rate, exist := localTrafficRate[iface]
		if !exist {
			rate = TrafficRate{
				Name:   iface,
				RxRate: rxRate,
				TxRate: txRate,
			}
		} else {
			rate.RxRate = rxRate
			rate.TxRate = txRate
		}
		localTrafficRate[iface] = rate
	}

	// Also check for new interfaces in stats2 that weren't in stats1
	for iface := range stats2 {
		if _, ok := stats1[iface]; !ok {
			// New interface appeared, initialize with zeros
			localTrafficRate[iface] = TrafficRate{
				Name:   iface,
				RxRate: 0,
				TxRate: 0,
			}
		}
	}
}

// readNetStats reads network interface statistics from /proc/net/dev
func readNetStats() (map[string]NetStat, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/dev: %v", err)
	}
	defer file.Close()

	stats := make(map[string]NetStat)
	scanner := bufio.NewScanner(file)

	// Skip headers (first two lines)
	for i := 0; i < 2 && scanner.Scan(); i++ {
	}

	// Process each line (one per interface)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)

		if len(fields) < 17 {
			continue
		}

		// Extract interface name and stats
		iface := strings.TrimSuffix(fields[0], ":")
		rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[9], 10, 64)

		stats[iface] = NetStat{
			Name:    iface,
			RxBytes: rxBytes,
			TxBytes: txBytes,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning /proc/net/dev: %v", err)
	}

	return stats, nil
}

// heartbeatTask sends periodic heartbeats to the PeerAPI server
func heartbeatTask() {
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	uname := getOsUname()
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)

	for range ticker.C {
		sendHeartbeat(agent, uname)
	}
}

// sendHeartbeat sends a heartbeat message to the PeerAPI server
func sendHeartbeat(agent *client.Client, uname string) {
	url := fmt.Sprintf("%s/agent/%s/heartbeat", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		log.Printf("[HeartBeat] Failed to generate token: %v\n", err)
		return
	}

	routerSoftware, _ := birdPool.ShowStatus()
	rx, tx, _ := getInterfaceTraffic(cfg.PeerAPI.WanInterfaces)

	agent.SetHeader("Authorization", "Bearer\x20"+token)
	resp, err := agent.Post(url, client.Config{
		Body: map[string]any{
			"version":   SERVER_SIGNATURE,
			"kernel":    uname,
			"loadAvg":   getLoadAverageStr(),
			"uptime":    getUptimeSeconds(),
			"rs":        routerSoftware,
			"tx":        tx,
			"rx":        rx,
			"tcp":       getTcpConnections(),
			"udp":       getUdpConnections(),
			"timestamp": time.Now().UnixMilli(),
		},
	})
	if err != nil {
		log.Printf("[HeartBeat] Failed to send heartbeat: %v\n", err)
		return
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		log.Printf("[HeartBeat] Server returned status code: %d\n", resp.StatusCode())
	}
}
