package main

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3/client"
)

const (
	// MAX_METRICS_HISTORY defines how many historical metric points to store
	// 360 points at 1 minute intervals = 6 hours of history
	MAX_METRICS_HISTORY = 360
)

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

	// Update the local metric map with the latest metrics
	mutex.Lock()
	maps.Copy(localMetrics, newSessionMetrics)
	mutex.Unlock()

	// Send metrics to PeerAPI
	sendMetricsToPeerAPI(newSessionMetrics)
}

// sendMetricsToPeerAPI sends collected metrics to the PeerAPI server
func sendMetricsToPeerAPI(metrics map[string]SessionMetric) {
	url := fmt.Sprintf("%s/agent/%s/report", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
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
			"metrics": metrics,
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
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")

	// Initialize variables for BGP metrics
	var ipv4Import, ipv4Export, ipv6Import, ipv6Export int64
	var bgpMetrics []BGPMetric

	// Collect BGP metrics based on session type
	collectBGPMetrics(sessionName, mpBGP, &ipv4Import, &ipv4Export, &ipv6Import, &ipv6Export, &bgpMetrics)

	// Get interface traffic statistics from /proc/net/dev
	rx, tx, _ := getInterfaceTraffic([]string{session.Interface})

	// Get current traffic rates from localTrafficRate
	rxRate, txRate := getTrafficRates(session.Interface)

	// Initialize new metric
	metric := initializeSessionMetric(session, timestamp, bgpMetrics, rx, tx, rxRate, txRate)

	// Update metrics with historical data if available
	updateMetricsWithHistory(session, timestamp, metric, ipv4Import, ipv4Export, ipv6Import, ipv6Export, mpBGP)

	metrics[session.UUID] = metric
}

// collectBGPMetrics collects BGP-specific metrics based on the session type
func collectBGPMetrics(sessionName string, mpBGP bool, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	if !mpBGP {
		// For traditional BGP, we have two sessions (_v4 and _v6)
		collectTraditionalBGPMetrics(sessionName, ipv4Import, ipv4Export, ipv6Import, ipv6Export, bgpMetrics)
	} else {
		// For MP-BGP, we have a single session with both IPv4 and IPv6
		collectMPBGPMetrics(sessionName, ipv4Import, ipv4Export, ipv6Import, ipv6Export, bgpMetrics)
	}
}

// collectTraditionalBGPMetrics collects metrics for traditional BGP sessions (separate v4 and v6)
func collectTraditionalBGPMetrics(sessionName string, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	// Collect IPv4 metrics
	stateV4, _, infoV4, ipv4ImportV4, ipv4ExportV4, _, _, errV4 := birdPool.ShowProtocolRoutes(sessionName + "_v4")
	if errV4 != nil {
		log.Printf("[Metrics] Failed to get protocol routes for %s_v4: %v\n", sessionName, errV4)
		// Continue with empty values for v4
	}

	// Collect IPv6 metrics
	stateV6, _, infoV6, _, _, ipv6ImportV6, ipv6ExportV6, errV6 := birdPool.ShowProtocolRoutes(sessionName + "_v6")
	if errV6 != nil {
		log.Printf("[Metrics] Failed to get protocol routes for %s_v6: %v\n", sessionName, errV6)
		// Continue with empty values for v6
	}

	// Create two BGP metrics, one for IPv4 and one for IPv6
	*bgpMetrics = []BGPMetric{
		createBGPMetric(stateV4, infoV4, int(ipv4ImportV4), int(ipv4ExportV4), 0, 0),
		createBGPMetric(stateV6, infoV6, 0, 0, int(ipv6ImportV6), int(ipv6ExportV6)),
	}

	// Set variables for history tracking
	*ipv4Import = ipv4ImportV4
	*ipv4Export = ipv4ExportV4
	*ipv6Import = ipv6ImportV6
	*ipv6Export = ipv6ExportV6
}

// collectMPBGPMetrics collects metrics for MP-BGP sessions (combined v4 and v6)
func collectMPBGPMetrics(interfaceName string, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	// For MP-BGP, we have a single session with both IPv4 and IPv6
	state, _, info, ipv4ImportVal, ipv4ExportVal, ipv6ImportVal, ipv6ExportVal, err := birdPool.ShowProtocolRoutes(interfaceName)
	if err != nil {
		log.Printf("[Metrics] Failed to get protocol routes for %s: %v\n", interfaceName, err)
		// Continue with empty values
	}

	// For MP-BGP, we only need one BGP metric
	*bgpMetrics = []BGPMetric{
		createBGPMetric(state, info, int(ipv4ImportVal), int(ipv4ExportVal), int(ipv6ImportVal), int(ipv6ExportVal)),
	}

	// Set variables for history tracking
	*ipv4Import = ipv4ImportVal
	*ipv4Export = ipv4ExportVal
	*ipv6Import = ipv6ImportVal
	*ipv6Export = ipv6ExportVal
}

// createBGPMetric creates a BGP metric object with the given parameters
func createBGPMetric(state, info string, ipv4Import, ipv4Export, ipv6Import, ipv6Export int) BGPMetric {
	return BGPMetric{
		State: state,
		Info:  info,
		Routes: BGPRoutesMetric{
			IPv4: RouteMetricStruct{
				Imported: RouteMetrics{
					Current: ipv4Import,
					Metric:  make([][2]int64, 0),
				},
				Exported: RouteMetrics{
					Current: ipv4Export,
					Metric:  make([][2]int64, 0),
				},
			},
			IPv6: RouteMetricStruct{
				Imported: RouteMetrics{
					Current: ipv6Import,
					Metric:  make([][2]int64, 0),
				},
				Exported: RouteMetrics{
					Current: ipv6Export,
					Metric:  make([][2]int64, 0),
				},
			},
		},
	}
}

// getTrafficRates retrieves current traffic rates for an interface
func getTrafficRates(interfaceName string) (int64, int64) {
	var rxRate, txRate int64 = 0, 0

	mutex.RLock()
	if trafficRate, exists := localTrafficRate[interfaceName]; exists {
		rxRate = int64(trafficRate.RxRate)
		txRate = int64(trafficRate.TxRate)
	}
	mutex.RUnlock()

	return rxRate, txRate
}

// initializeSessionMetric creates and initializes a new session metric
func initializeSessionMetric(session BgpSession, timestamp int64, bgpMetrics []BGPMetric, rx, tx uint64, rxRate, txRate int64) SessionMetric {
	return SessionMetric{
		UUID:      session.UUID,
		ASN:       session.ASN,
		Timestamp: timestamp,
		BGP:       bgpMetrics,
		Interface: InterfaceMetric{
			IPv4:          session.IPv4,
			IPv6:          session.IPv6,
			IPv6LinkLocal: session.IPv6LinkLocal,
			MAC: func() string {
				mac, _ := getInterfaceMAC(session.Interface)
				return mac
			}(),
			MTU: func() int {
				mtu, _ := getInterfaceMTU(session.Interface)
				if mtu <= 0 {
					mtu = session.MTU
				}
				return mtu
			}(),
			Status: func() string {
				flags, _ := getInterfaceFlags(session.Interface)
				return flags
			}(),
			Traffic: InterfaceTrafficMetric{
				Total:   []int64{int64(tx), int64(rx)}, // [Tx, Rx] - total bytes
				Current: []int64{txRate, rxRate},       // [Tx, Rx] - current rate in bytes per second
				Metric:  make([][3]int64, 0),           // [timestamp, Tx, Rx]
			},
		},
		RTT: RTT{
			Current: 0, // Will be updated later with ping data
			Metric:  make([][2]int, 0),
		},
	}
}

// updateMetricsWithHistory updates metrics with historical data if available
func updateMetricsWithHistory(session BgpSession, timestamp int64, metric SessionMetric,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64, mpBGP bool) {

	mutex.RLock()
	defer mutex.RUnlock()

	// Get old metrics if available
	oldMetric, exists := localMetrics[session.UUID]

	if exists {
		// Update traffic metrics history
		updateTrafficMetrics(&metric, oldMetric, timestamp)

		// Update RTT metrics
		updateRTTMetrics(&metric, oldMetric, session, timestamp)

		// Update route metrics
		if mpBGP {
			updateMPBGPRouteMetrics(&metric, oldMetric, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export)
		} else {
			updateTraditionalBGPRouteMetrics(&metric, oldMetric, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export)
		}
	} else {
		// First time collection, initialize with single data points
		initializeFirstTimeMetrics(&metric, session, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export, mpBGP)
	}
}

// updateTrafficMetrics updates traffic metrics history
func updateTrafficMetrics(metric *SessionMetric, oldMetric SessionMetric, timestamp int64) {
	trafficMetric := oldMetric.Interface.Traffic.Metric

	// Add new measurement [timestamp, txRate, rxRate]
	trafficMetric = append(trafficMetric, [3]int64{
		timestamp,
		metric.Interface.Traffic.Current[0],
		metric.Interface.Traffic.Current[1],
	})

	if len(trafficMetric) > MAX_METRICS_HISTORY {
		trafficMetric = trafficMetric[1:]
	}

	metric.Interface.Traffic.Metric = trafficMetric
}

// updateRTTMetrics updates RTT (ping) metrics
func updateRTTMetrics(metric *SessionMetric, oldMetric SessionMetric, session BgpSession, timestamp int64) {
	// Measure current RTT value
	rttValue := measureRTT(
		session.IPv4,
		session.IPv6,
		fmt.Sprintf("%s%%%s", session.IPv6LinkLocal, session.Interface),
	)

	rttMetric := oldMetric.RTT.Metric
	rttMetric = append(rttMetric, [2]int{int(timestamp), rttValue})

	if len(rttMetric) > MAX_METRICS_HISTORY {
		rttMetric = rttMetric[1:]
	}

	metric.RTT.Current = rttValue
	metric.RTT.Metric = rttMetric
}

// updateMPBGPRouteMetrics updates route metrics for MP-BGP sessions
func updateMPBGPRouteMetrics(metric *SessionMetric, oldMetric SessionMetric, timestamp int64,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64) {

	if len(oldMetric.BGP) > 0 && len(metric.BGP) > 0 {
		// Update IPv4 Imported metric history
		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv4.Imported.Metric,
			oldMetric.BGP[0].Routes.IPv4.Imported.Metric,
			timestamp,
			ipv4Import,
		)

		// Update IPv4 Exported metric history
		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv4.Exported.Metric,
			oldMetric.BGP[0].Routes.IPv4.Exported.Metric,
			timestamp,
			ipv4Export,
		)

		// Update IPv6 Imported metric history
		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv6.Imported.Metric,
			oldMetric.BGP[0].Routes.IPv6.Imported.Metric,
			timestamp,
			ipv6Import,
		)

		// Update IPv6 Exported metric history
		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv6.Exported.Metric,
			oldMetric.BGP[0].Routes.IPv6.Exported.Metric,
			timestamp,
			ipv6Export,
		)
	}
}

// updateTraditionalBGPRouteMetrics updates route metrics for traditional BGP sessions
func updateTraditionalBGPRouteMetrics(metric *SessionMetric, oldMetric SessionMetric, timestamp int64,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64) {

	// Update IPv4 metrics (first session)
	if len(oldMetric.BGP) > 0 && len(metric.BGP) > 0 {
		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv4.Imported.Metric,
			oldMetric.BGP[0].Routes.IPv4.Imported.Metric,
			timestamp,
			ipv4Import,
		)

		updateRouteMetricsArray(
			&metric.BGP[0].Routes.IPv4.Exported.Metric,
			oldMetric.BGP[0].Routes.IPv4.Exported.Metric,
			timestamp,
			ipv4Export,
		)
	}

	// Update IPv6 metrics (second session)
	if len(oldMetric.BGP) > 1 && len(metric.BGP) > 1 {
		updateRouteMetricsArray(
			&metric.BGP[1].Routes.IPv6.Imported.Metric,
			oldMetric.BGP[1].Routes.IPv6.Imported.Metric,
			timestamp,
			ipv6Import,
		)

		updateRouteMetricsArray(
			&metric.BGP[1].Routes.IPv6.Exported.Metric,
			oldMetric.BGP[1].Routes.IPv6.Exported.Metric,
			timestamp,
			ipv6Export,
		)
	}
}

// updateRouteMetricsArray updates a route metrics array with new data
func updateRouteMetricsArray(metricArray *[][2]int64, oldArray [][2]int64, timestamp, value int64) {
	newArray := append(oldArray, [2]int64{timestamp, value})
	if len(newArray) > MAX_METRICS_HISTORY {
		newArray = newArray[1:]
	}
	*metricArray = newArray
}

// initializeFirstTimeMetrics initializes metrics for the first time collection
func initializeFirstTimeMetrics(metric *SessionMetric, session BgpSession, timestamp int64,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64, mpBGP bool) {

	// Initialize traffic metric with a single data point
	metric.Interface.Traffic.Metric = [][3]int64{{
		timestamp,
		metric.Interface.Traffic.Current[0],
		metric.Interface.Traffic.Current[1],
	}}

	// Initialize RTT metric with a single data point
	rttValue := measureRTT(
		session.IPv4,
		session.IPv6,
		fmt.Sprintf("%s%%%s", session.IPv6LinkLocal, session.Interface),
	)
	metric.RTT.Current = rttValue
	metric.RTT.Metric = [][2]int{{int(timestamp), rttValue}}

	// Initialize route metrics
	if mpBGP {
		// For MP-BGP (single session)
		if len(metric.BGP) > 0 {
			metric.BGP[0].Routes.IPv4.Imported.Metric = [][2]int64{{timestamp, int64(ipv4Import)}}
			metric.BGP[0].Routes.IPv4.Exported.Metric = [][2]int64{{timestamp, int64(ipv4Export)}}
			metric.BGP[0].Routes.IPv6.Imported.Metric = [][2]int64{{timestamp, int64(ipv6Import)}}
			metric.BGP[0].Routes.IPv6.Exported.Metric = [][2]int64{{timestamp, int64(ipv6Export)}}
		}
	} else {
		// For traditional BGP (two sessions)
		if len(metric.BGP) > 0 {
			// Initialize IPv4 metrics (first session)
			metric.BGP[0].Routes.IPv4.Imported.Metric = [][2]int64{{timestamp, int64(ipv4Import)}}
			metric.BGP[0].Routes.IPv4.Exported.Metric = [][2]int64{{timestamp, int64(ipv4Export)}}
		}

		if len(metric.BGP) > 1 {
			// Initialize IPv6 metrics (second session)
			metric.BGP[1].Routes.IPv6.Imported.Metric = [][2]int64{{timestamp, int64(ipv6Import)}}
			metric.BGP[1].Routes.IPv6.Exported.Metric = [][2]int64{{timestamp, int64(ipv6Export)}}
		}
	}
}

// Helper function to measure RTT (ping time) to a peer
func measureRTT(ipv4, ipv6, ipv6ll string) int {
	// First try IPv6LL
	if ipv6ll != "" {
		rtt := pingRTT(fmt.Sprintf("[%s]", ipv6ll))
		if rtt > 0 {
			return rtt
		}
	}

	// try IPv6
	if ipv6 != "" {
		rtt := pingRTT(fmt.Sprintf("[%s]", ipv6))
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
	return tcpingAverage(addr, cfg.Metric.PingCount, cfg.Metric.PingTimeout)
}

// metricTask schedules periodic metrics collection
func metricTask() {
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.MetricInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		collectMetrics()
	}
}
