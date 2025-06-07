package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/client"
)

const (
	PEERING_STATUS_DELETED = iota
	PEERING_STATUS_DISABLED
	PEERING_STATUS_ENABLED
	PEERING_STATUS_PENDING_APPROVAL
	PEERING_STATUS_QUEUED_FOR_SETUP
	PEERING_STATUS_QUEUED_FOR_DELETE
	PEERING_STATUS_PROBLEM
	PEERING_STATUS_TEARDOWN
)

var localSessions = make(map[string]BgpSession)
var localMetrics = make(map[string]SessionMetric)
var mutex sync.RWMutex

func heartbeatTask() {
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	uname := GetOsUname()

	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)
	for range ticker.C {
		url := fmt.Sprintf("%s/agent/%s/heartbeat", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
		token, err := generateToken()
		if err != nil {
			log.Printf("Failed to generate token: %v\n", err)
			continue
		}

		routerSoftware, _ := birdPool.ShowStatus()
		rx, tx, _ := GetInterfaceTraffic(cfg.PeerAPI.WanInterfaces)

		agent.SetHeader("Authorization", "Bearer\x20"+token)
		resp, err := agent.Post(url, client.Config{
			Body: map[string]any{
				"version":   SERVER_SIGNATURE,
				"kernel":    uname,
				"loadAvg":   GetLoadAverageStr(),
				"uptime":    GetUptimeSeconds(),
				"rs":        routerSoftware,
				"tx":        tx,
				"rx":        rx,
				"tcp":       GetTcpConnections(),
				"udp":       GetUdpConnections(),
				"timestamp": time.Now().UnixMilli(),
			},
		})
		if err != nil {
			resp.Close()
			log.Printf("Failed to send heartbeat: %v\n", err)
			continue
		}
		resp.Close()
	}
}

func getBgpSessions() ([]BgpSession, error) {
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)

	url := fmt.Sprintf("%s/agent/%s/sessions", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("Failed to generate token: %v\n", err)
	}
	agent.SetHeader("Authorization", "Bearer\x20"+token)
	resp, err := agent.Get(url)

	if err != nil {
		resp.Close()
		return nil, fmt.Errorf("Failed to get sessions: %v\n", err)
	}

	if resp.StatusCode() != 200 {
		resp.Close()
		return nil, fmt.Errorf("Failed to get sessions, status code: %d\n", resp.StatusCode())
	}

	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		resp.Close()
		return nil, fmt.Errorf("Failed to parse response: %v\n", err)
	}

	resp.Close()
	if response.Code != 0 {
		return nil, fmt.Errorf("PeerAPI returned error: %s\n", response.Message)
	}

	var data BgpSessionsResponse
	err = json.Unmarshal(response.Data, &data)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse BGP sessions data: %v\n", err)
	}

	return data.BgpSessions, nil
}

func reportNewStatusToCenter(sessionUUID string, status int) error {
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)

	url := fmt.Sprintf("%s/agent/%s/modify", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("Failed to generate token: %v\n", err)
	}
	agent.SetHeader("Authorization", "Bearer\x20"+token)

	resp, err := agent.Post(url, client.Config{
		Body: map[string]any{
			"status":  status,
			"session": sessionUUID,
		},
	})
	if err != nil {
		return fmt.Errorf("Failed to notify deletion: %v\n", err)
	}
	defer resp.Close()

	if resp.StatusCode() != 200 {
		return fmt.Errorf("Failed to notify deletion, status code: %d\n", resp.StatusCode())
	}

	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		return fmt.Errorf("Failed to parse response: %v\n", err)
	}

	if response.Code != 0 {
		return fmt.Errorf("PeerAPI returned error: %s\n", response.Message)
	}

	return nil
}

func syncSessions() {
	// This is a scheduled task that runs every 30 seconds to fetch the latest array of `BgpSession` objects from the server.
	// Each time it runs, it compares the newly fetched array **A** with the existing array **B** in local memory, item by item.

	// ### 1. If an item in **A** (A.UUID) is **not in B**:
	// - **1-1.** If `A.status == PEERING_STATUS_QUEUED_FOR_SETUP`:
	// - Execute `configureInterface()` and `reportStatus()`.
	// - If `reportStatus()` returns HTTP 200 and `resp.code == 0`, then set `A.status = PEERING_STATUS_ENABLED`.
	// - **1-2.** If `A.status == PEERING_STATUS_ENABLED` or `PEERING_STATUS_PROBLEM`:
	// - Execute `configureInterface()`.

	// ### 2. If an item in **B** (B.UUID) is **not in A**:
	// - Execute `deleteInterface()`.

	// ### 3. If an item exists in **both A and B**:
	// - **3a.** If all fields are exactly the same, do nothing and continue.
	// - **3b.** Otherwise:
	// - **3b-1.** If the new `A.status` is one of:
	// 	- `PEERING_STATUS_DISABLED`
	// 	- `PEERING_STATUS_DELETED`
	// 	- `PEERING_STATUS_TEARDOWN`
	// 	- `PEERING_STATUS_QUEUED_FOR_DELETE`
	// 	Then:
	// 	- Execute `deleteInterface()`.
	// 	- If the status is `PEERING_STATUS_QUEUED_FOR_DELETE`, additionally execute `reportStatus()`.
	// 	If `reportStatus()` returns HTTP 200 and `resp.code == 0`, then set `A.status = PEERING_STATUS_DELETED`.

	// - **3b-2.** If the new `A.status == PEERING_STATUS_QUEUED_FOR_SETUP`:
	// 	- Execute `configureInterface()` and `reportStatus()`.
	// 	- If `reportStatus()` returns HTTP 200 and `resp.code == 0`, then set `A.status = PEERING_STATUS_ENABLED`.

	// - **3b-3.** If the new `A.status == PEERING_STATUS_ENABLED`:
	// 	- Execute `configureInterface()`.

	// - **3b-4.** If the new `A.status == PEERING_STATUS_PENDING_APPROVAL`:
	// 	- Do nothing.

	// - **3b-5.** If the new `A.status == PEERING_STATUS_PROBLEM`:
	// 	- Do nothing.

	// ### 4. Set B = A
	// ### 5. For each item in the new **B**, if `status` is `PEERING_STATUS_ENABLED` or `PEERING_STATUS_PROBLEM`, execute `testNet()`.

	sessions, err := getBgpSessions()
	if err != nil {
		log.Printf("[Sync] Failed to pull BGP sessions: %v\n", err)
		return
	}

	// Process each session
	nextLocal := make(map[string]BgpSession)
	for _, r := range sessions {
		b, exists := localSessions[r.UUID]
		if !exists {
			switch r.Status {
			case PEERING_STATUS_QUEUED_FOR_SETUP:
				configureSession(&r)
				err := reportNewStatusToCenter(r.UUID, PEERING_STATUS_ENABLED)
				if err == nil {
					r.Status = PEERING_STATUS_ENABLED
				}
			case PEERING_STATUS_ENABLED, PEERING_STATUS_PROBLEM:
				configureSession(&r)
			}
			nextLocal[r.UUID] = r
			continue
		}

		if reflect.DeepEqual(r, b) {
			nextLocal[r.UUID] = r
			continue
		}

		switch r.Status {
		case PEERING_STATUS_DISABLED, PEERING_STATUS_DELETED, PEERING_STATUS_TEARDOWN:
			deleteSession(&b)
		case PEERING_STATUS_QUEUED_FOR_DELETE:
			deleteSession(&b)
			err := reportNewStatusToCenter(r.UUID, PEERING_STATUS_DELETED)
			if err == nil {
				r.Status = PEERING_STATUS_DELETED
			}
		case PEERING_STATUS_QUEUED_FOR_SETUP:
			configureSession(&r)
			err := reportNewStatusToCenter(r.UUID, PEERING_STATUS_ENABLED)
			if err == nil {
				r.Status = PEERING_STATUS_ENABLED
			}
		case PEERING_STATUS_ENABLED:
			configureSession(&r)
		case PEERING_STATUS_PENDING_APPROVAL, PEERING_STATUS_PROBLEM:
			// does nothing, pass
		}
		nextLocal[r.UUID] = r
	}

	// Case: some local sessions no longer usable
	for uuid, s := range localSessions {
		if _, exists := nextLocal[uuid]; !exists {
			deleteSession(&s)
		}
	}

	// replace local memory copy to new processed one
	mutex.Lock()
	localSessions = nextLocal
	mutex.Unlock()

	// 情况 5：testNet
	for _, s := range localSessions {
		if s.Status == PEERING_STATUS_ENABLED || s.Status == PEERING_STATUS_PROBLEM {
			go collectMetrics(s)
		}
	}

	if _, err := birdPool.Configure(); err != nil {
		log.Printf("[Sync] Failed to send bird configure: %v\n", err)
	}
}

func syncTask() {
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.SyncInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		syncSessions()
	}
}

func metricTask() {
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.MetricInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		collectMetrics()
	}
}

// collectMetrics collects metrics for all sessions or a specific session
func collectMetrics(session ...BgpSession) {
	now := time.Now().UnixMilli()
	newSessionMetrics := make(map[string]SessionMetric)

	// If a specific session is provided, only collect metrics for that session
	if len(session) > 0 {
		s := session[0]
		if s.Status != PEERING_STATUS_ENABLED && s.Status != PEERING_STATUS_PROBLEM {
			return
		}

		collectSessionMetric(s, now, newSessionMetrics)
		return
	}

	// Otherwise collect metrics for all active sessions
	mutex.RLock()
	for _, s := range localSessions {
		if s.Status != PEERING_STATUS_ENABLED && s.Status != PEERING_STATUS_PROBLEM {
			continue
		}

		collectSessionMetric(s, now, newSessionMetrics)
	}
	mutex.RUnlock()

	if len(newSessionMetrics) == 0 {
		log.Println("[Metrics] No active sessions to collect metrics from.")
		return
	}
	// Update the local metric map with the latest metrics	mutex.Lock()
	for uuid, metric := range newSessionMetrics {
		localMetrics[uuid] = metric
	}
	mutex.Unlock()

	// Send metrics to PeerAPI
	url := fmt.Sprintf("%s/agent/%s/metrics", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		log.Printf("[Metrics] Failed to generate token: %v\n", err)
		return
	}
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)
	agent.SetHeader("Authorization", "Bearer\x20"+token)
	resp, err := agent.Post(url, client.Config{
		Body: map[string]any{
			"metrics": newSessionMetrics,
		},
	})
	if err != nil {
		log.Printf("[Metrics] Failed to send metrics: %v\n", err)
		return
	}
	defer resp.Close()
	if resp.StatusCode() != 200 {
		log.Printf("[Metrics] Failed to send metrics, status code: %d\n", resp.StatusCode())
		return
	}
	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		log.Printf("[Metrics] Failed to parse response: %v\n", err)
		return
	}
	if response.Code != 0 {
		log.Printf("[Metrics] PeerAPI returned error: %s\n", response.Message)
		return
	}
}

// collectSessionMetric collects metrics for a single BGP session
func collectSessionMetric(session BgpSession, timestamp int64, metrics map[string]SessionMetric) {
	const MAX_METRICS_HISTORY = 2880 // Store up to 2880 historical metric points (e.g., 2 days at 1 minute intervals)

	// Get BGP session state and route information using the bird ShowProtocolRoutes function
	state, _, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, err := birdPool.ShowProtocolRoutes(session.Interface)
	if err != nil {
		log.Printf("[Metrics] Failed to get protocol routes for %s: %v\n", session.Interface, err)
		// Continue with empty values
	}

	// Initialize new metric
	metric := SessionMetric{
		UUID:      session.UUID,
		ASN:       session.ASN,
		Timestamp: timestamp,
		BGP: BGPMetric{
			State: state,
			Info:  info,
			Routes: BGPRoutesMetric{
				IPv4: RouteMetricStruct{
					Imported: RouteMetrics{
						Current: int(ipv4Import),
						Metric:  make([][2]int64, 0),
					},
					Exported: RouteMetrics{
						Current: int(ipv4Export),
						Metric:  make([][2]int64, 0),
					},
				},
				IPv6: RouteMetricStruct{
					Imported: RouteMetrics{
						Current: int(ipv6Import),
						Metric:  make([][2]int64, 0),
					},
					Exported: RouteMetrics{
						Current: int(ipv6Export),
						Metric:  make([][2]int64, 0),
					},
				},
			},
		},
		Interface: InterfaceMetric{
			IPv4:          session.IPv4,
			IPv6:          session.IPv6,
			IPv6LinkLocal: session.IPv6LinkLocal,
			MAC: func() string {
				mac, _ := GetInterfaceMAC(session.Interface)
				return mac
			}(),
			MTU: func() int {
				mtu, _ := GetInterfaceMTU(session.Interface)
				if mtu <= 0 {
					mtu = session.MTU
				}
				return mtu
			}(),
			Status: func() string {
				flags, _ := GetInterfaceFlags(session.Interface)
				return flags
			}(),
			Traffic: InterfaceTrafficMetric{
				RX: TrafficMetrics{
					Total:   0, // Will be calculated below
					Current: 0, // Will be calculated below
					Metric:  make([][2]int64, 0),
				},
				TX: TrafficMetrics{
					Total:   0, // Will be calculated below
					Current: 0, // Will be calculated below
					Metric:  make([][2]int64, 0),
				},
			},
		},
		RTT: RTT{
			Current: 0, // Will be updated later with ping data
			Metric:  make([][2]int, 0),
		},
	}

	// Get interface traffic statistics
	rx, tx, _ := GetInterfaceTraffic([]string{session.Interface})
	metric.Interface.Traffic.RX.Total = int64(rx)
	metric.Interface.Traffic.TX.Total = int64(tx)
	// Load previous metrics if they exist and append new metrics to history
	mutex.RLock()
	if oldMetric, exists := localMetrics[session.UUID]; exists {
		// Update IPv4 Imported metric history
		ipv4ImportMetric := oldMetric.BGP.Routes.IPv4.Imported.Metric
		ipv4ImportMetric = append(ipv4ImportMetric, [2]int64{timestamp, int64(ipv4Import)})
		if len(ipv4ImportMetric) > MAX_METRICS_HISTORY {
			ipv4ImportMetric = ipv4ImportMetric[1:]
		}
		metric.BGP.Routes.IPv4.Imported.Metric = ipv4ImportMetric

		// Update IPv4 Exported metric history
		ipv4ExportMetric := oldMetric.BGP.Routes.IPv4.Exported.Metric
		ipv4ExportMetric = append(ipv4ExportMetric, [2]int64{timestamp, int64(ipv4Export)})
		if len(ipv4ExportMetric) > MAX_METRICS_HISTORY {
			ipv4ExportMetric = ipv4ExportMetric[1:]
		}
		metric.BGP.Routes.IPv4.Exported.Metric = ipv4ExportMetric

		// Update IPv6 Imported metric history
		ipv6ImportMetric := oldMetric.BGP.Routes.IPv6.Imported.Metric
		ipv6ImportMetric = append(ipv6ImportMetric, [2]int64{timestamp, int64(ipv6Import)})
		if len(ipv6ImportMetric) > MAX_METRICS_HISTORY {
			ipv6ImportMetric = ipv6ImportMetric[1:]
		}
		metric.BGP.Routes.IPv6.Imported.Metric = ipv6ImportMetric

		// Update IPv6 Exported metric history
		ipv6ExportMetric := oldMetric.BGP.Routes.IPv6.Exported.Metric
		ipv6ExportMetric = append(ipv6ExportMetric, [2]int64{timestamp, int64(ipv6Export)})
		if len(ipv6ExportMetric) > MAX_METRICS_HISTORY {
			ipv6ExportMetric = ipv6ExportMetric[1:]
		}
		metric.BGP.Routes.IPv6.Exported.Metric = ipv6ExportMetric

		// Update RX traffic metrics history
		rxMetric := oldMetric.Interface.Traffic.RX.Metric
		rxMetric = append(rxMetric, [2]int64{timestamp, int64(rx)})
		if len(rxMetric) > MAX_METRICS_HISTORY {
			rxMetric = rxMetric[1:]
		}
		metric.Interface.Traffic.RX.Metric = rxMetric

		// Calculate RX current based on delta from previous measurement
		if len(rxMetric) >= 2 {
			prevTimestamp := rxMetric[len(rxMetric)-2][0]
			prevValue := rxMetric[len(rxMetric)-2][1]
			// Calculate bytes per second
			if timestamp > prevTimestamp {
				metric.Interface.Traffic.RX.Current = (int64(rx) - prevValue) * 1000 / (timestamp - prevTimestamp)
			}
		}

		// Update TX traffic metrics history
		txMetric := oldMetric.Interface.Traffic.TX.Metric
		txMetric = append(txMetric, [2]int64{timestamp, int64(tx)})
		if len(txMetric) > MAX_METRICS_HISTORY {
			txMetric = txMetric[1:]
		}
		metric.Interface.Traffic.TX.Metric = txMetric

		// Calculate TX current based on delta from previous measurement
		if len(txMetric) >= 2 {
			prevTimestamp := txMetric[len(txMetric)-2][0]
			prevValue := txMetric[len(txMetric)-2][1]
			// Calculate bytes per second
			if timestamp > prevTimestamp {
				metric.Interface.Traffic.TX.Current = (int64(tx) - prevValue) * 1000 / (timestamp - prevTimestamp)
			}
		}

		// Update RTT metrics
		rttValue := measureRTT(session.IPv4, session.IPv6)
		rttMetric := oldMetric.RTT.Metric
		rttMetric = append(rttMetric, [2]int{int(timestamp), rttValue})
		if len(rttMetric) > MAX_METRICS_HISTORY {
			rttMetric = rttMetric[1:]
		}
		metric.RTT.Current = rttValue
		metric.RTT.Metric = rttMetric
	} else {
		// First time collection, initialize with single data point
		metric.BGP.Routes.IPv4.Imported.Metric = [][2]int64{{timestamp, int64(ipv4Import)}}
		metric.BGP.Routes.IPv4.Exported.Metric = [][2]int64{{timestamp, int64(ipv4Export)}}
		metric.BGP.Routes.IPv6.Imported.Metric = [][2]int64{{timestamp, int64(ipv6Import)}}
		metric.BGP.Routes.IPv6.Exported.Metric = [][2]int64{{timestamp, int64(ipv6Export)}}

		metric.Interface.Traffic.RX.Metric = [][2]int64{{timestamp, int64(rx)}}
		metric.Interface.Traffic.TX.Metric = [][2]int64{{timestamp, int64(tx)}}

		rttValue := measureRTT(session.IPv4, session.IPv6)
		metric.RTT.Current = rttValue
		metric.RTT.Metric = [][2]int{{int(timestamp), rttValue}}
	}
	mutex.RUnlock()

	metrics[session.UUID] = metric
}

// Helper function to measure RTT (ping time) to a peer
func measureRTT(ipv4, ipv6 string) int {
	// First try IPv6
	if ipv6 != "" {
		rtt := pingRTT(ipv6)
		if rtt > 0 {
			return rtt
		}
	}

	// If IPv6 fails or is not available, try IPv4
	if ipv4 != "" {
		rtt := pingRTT(ipv4)
		if rtt > 0 {
			return rtt
		}
	}

	return 0
}

// Actual implementation of ping RTT measurement using tcping
func pingRTT(ip string) int {
	// Use tcping to check both default BGP ports
	// Try port 179 (standard BGP port)
	addr := fmt.Sprintf("%s:179", ip)
	return TcpingAverage(addr, 2, 1)
}
