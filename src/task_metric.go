package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v3/client"
)

const (
	MAX_METRICS_HISTORY = 100 // MAX_METRICS_HISTORY defines how many historical metric points to store
	PING_WORKER_COUNT   = 64  // Number of workers for parallel pinging, don't create too many or we might overwhelm the system
)

// Flag to prevent multiple concurrent batchMeasureRTT operations
var batchRTTRunning int32 // Use atomic operations for this flag

// collectMetrics collects metrics for all sessions or a specific session
func collectMetrics(session ...BgpSession) {
	// Background RTT measurement Task in parallel for better performance (asynchronous)
	go batchMeasureRTT()

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
	sessionMutex.RLock()
	for _, s := range localSessions {
		if s.Status != PEERING_STATUS_ENABLED && s.Status != PEERING_STATUS_PROBLEM {
			continue
		}

		collectSessionMetric(s, now, newSessionMetrics)
	}
	sessionMutex.RUnlock()

	if len(newSessionMetrics) == 0 {
		log.Println("[Metrics] No active sessions to collect metrics from.")
		return
	}

	// Update the local metric map with the latest metrics
	metricMutex.Lock()
	maps.Copy(localMetrics, newSessionMetrics)
	metricMutex.Unlock()

	// Send metrics to PeerAPI
	sendMetricsToPeerAPI(newSessionMetrics)
}

// sendMetricsToPeerAPI sends collected metrics to the PeerAPI server
func sendMetricsToPeerAPI(metrics map[string]SessionMetric) {
	startTime := time.Now()

	if len(metrics) == 0 {
		return
	}

	url := fmt.Sprintf("%s/agent/%s/report", cfg.PeerAPI.URL, cfg.PeerAPI.RouterUUID)
	token, err := generateToken()
	if err != nil {
		log.Printf("[Metrics] Failed to generate token: %v\n", err)
		return
	}

	// Create HTTP client with timeout and context
	agent := client.New().SetTimeout(time.Duration(cfg.PeerAPI.RequestTimeout) * time.Second)
	agent.SetUserAgent(SERVER_SIGNATURE)
	agent.SetHeader("Authorization", "Bearer\x20"+token)

	// Convert metrics map to array
	sessionMutex.RLock()
	metricsArray := make([]SessionMetric, 0, len(metrics))
	for _, metric := range metrics {
		metricsArray = append(metricsArray, metric)
	}
	sessionMutex.RUnlock()

	// Log the metrics being sent for debugging
	log.Printf("[Metrics] Sending %d session metrics to PeerAPI (%s)", len(metricsArray), url)

	// Create request body
	requestBody := map[string]any{
		"metrics": metricsArray,
	}

	resp, err := agent.Post(url, client.Config{
		Body: requestBody,
	})
	if err != nil {
		log.Printf("[Metrics] Failed to send metrics to %s: %v (took %v)", url, err, time.Since(startTime))
		return
	}
	defer resp.Close()

	// Check HTTP status code
	if resp.StatusCode() != 200 {
		bodyText := string(resp.Body())
		log.Printf("[Metrics] Failed to send metrics, status code: %d, response body: %s (took %v)",
			resp.StatusCode(), bodyText, time.Since(startTime))
		return
	}

	// Parse response
	var response PeerApiResponse
	if err := json.Unmarshal(resp.Body(), &response); err != nil {
		log.Printf("[Metrics] Failed to parse response: %v, response body: %s (took %v)",
			err, string(resp.Body()), time.Since(startTime))
		return
	}

	// Check API response code
	if response.Code != 0 {
		log.Printf("[Metrics] PeerAPI returned error: %s (code: %d, took %v)",
			response.Message, response.Code, time.Since(startTime))
		return
	}

	// Success - log completion
	log.Printf("[Metrics] Successfully sent %d session metrics to PeerAPI (took %v)",
		len(metricsArray), time.Since(startTime))
}

// collectSessionMetric collects metrics for a single BGP session
func collectSessionMetric(session BgpSession, timestamp int64, metrics map[string]SessionMetric) {
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")

	// Initialize variables for BGP metrics
	var ipv4Import, ipv4Export, ipv6Import, ipv6Export int64
	var bgpMetrics []BGPMetric

	// Collect BGP metrics based on session type
	collectBGPMetrics(sessionName, session, mpBGP, &ipv4Import, &ipv4Export, &ipv6Import, &ipv6Export, &bgpMetrics)

	// Get interface traffic statistics from /proc/net/dev
	rx, tx, _ := getInterfaceTraffic([]string{session.Interface})

	// Get current traffic rates from localTrafficRate
	rxRate, txRate := getTrafficRates(session.Interface)

	// Initialize new metric
	metric := initializeSessionMetric(session, timestamp, bgpMetrics, rx, tx, rxRate, txRate)
	// Update metrics with historical data if available
	updateMetricsWithHistory(session, timestamp, &metric, ipv4Import, ipv4Export, ipv6Import, ipv6Export, mpBGP)

	metrics[session.UUID] = metric
}

// collectBGPMetrics collects BGP-specific metrics based on the session type
func collectBGPMetrics(sessionName string, session BgpSession, mpBGP bool, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	if !mpBGP {
		// For traditional BGP, we have two sessions (_v4 and _v6)
		collectTraditionalBGPMetrics(sessionName, session, ipv4Import, ipv4Export, ipv6Import, ipv6Export, bgpMetrics)
	} else {
		// For MP-BGP, we have a single session with both IPv4 and IPv6
		collectMPBGPMetrics(sessionName, ipv4Import, ipv4Export, ipv6Import, ipv6Export, bgpMetrics)
	}
}

// collectTraditionalBGPMetrics collects metrics for traditional BGP sessions (separate v4 and v6)
func collectTraditionalBGPMetrics(sessionName string, session BgpSession, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	// Initialize the metrics array
	*bgpMetrics = make([]BGPMetric, 0, 2)

	if session.IPv6LinkLocal != "" || session.IPv6 != "" {
		// Collect IPv6 metrics
		stateV6, _, infoV6, _, _, ipv6ImportVal, ipv6ExportVal, errV6 := birdPool.ShowProtocolRoutes(sessionName + "_v6")
		if errV6 != nil {
			log.Printf("[Metrics] Failed to get protocol routes for %s_v6: %v\n", sessionName, errV6)
			// Continue with empty values for v6
		}

		// Add IPv6 metric to the array
		*bgpMetrics = append(*bgpMetrics, createBGPMetric(sessionName+"_v6", stateV6, infoV6, BGP_SESSION_TYPE_IPV6, 0, 0, int(ipv6ImportVal), int(ipv6ExportVal)))

		// Set variables for history tracking
		*ipv6Import = ipv6ImportVal
		*ipv6Export = ipv6ExportVal

		if session.IPv4 == "" {
			*ipv4Import = 0
			*ipv4Export = 0
		}
	}

	if session.IPv4 != "" {
		// Collect IPv4 metrics
		stateV4, _, infoV4, ipv4ImportVal, ipv4ExportVal, _, _, errV4 := birdPool.ShowProtocolRoutes(sessionName + "_v4")
		if errV4 != nil {
			log.Printf("[Metrics] Failed to get protocol routes for %s_v4: %v\n", sessionName, errV4)
			// Continue with empty values for v4
		}

		// Add IPv4 metric to the array
		*bgpMetrics = append(*bgpMetrics, createBGPMetric(sessionName+"_v4", stateV4, infoV4, BGP_SESSION_TYPE_IPV4, int(ipv4ImportVal), int(ipv4ExportVal), 0, 0))

		// Set variables for history tracking
		*ipv4Import = ipv4ImportVal
		*ipv4Export = ipv4ExportVal
		if session.IPv6LinkLocal == "" && session.IPv6 == "" {
			*ipv6Import = 0
			*ipv6Export = 0
		}
	}
}

// collectMPBGPMetrics collects metrics for MP-BGP sessions (combined v4 and v6)
func collectMPBGPMetrics(sessionName string, ipv4Import, ipv4Export, ipv6Import, ipv6Export *int64, bgpMetrics *[]BGPMetric) {
	// For MP-BGP, we have a single session with both IPv4 and IPv6
	state, _, info, ipv4ImportVal, ipv4ExportVal, ipv6ImportVal, ipv6ExportVal, err := birdPool.ShowProtocolRoutes(sessionName)
	if err != nil {
		log.Printf("[Metrics] Failed to get protocol routes for %s: %v\n", sessionName, err)
		// Continue with empty values
	}

	// For MP-BGP, we only need one BGP metric
	*bgpMetrics = []BGPMetric{
		createBGPMetric(sessionName, state, info, BGP_SESSION_TYPE_MPBGP, int(ipv4ImportVal), int(ipv4ExportVal), int(ipv6ImportVal), int(ipv6ExportVal)),
	}

	// Set variables for history tracking
	*ipv4Import = ipv4ImportVal
	*ipv4Export = ipv4ExportVal
	*ipv6Import = ipv6ImportVal
	*ipv6Export = ipv6ExportVal
}

// createBGPMetric creates a BGP metric object with the given parameters
func createBGPMetric(name, state, info, sessionType string, ipv4Import, ipv4Export, ipv6Import, ipv6Export int) BGPMetric {
	return BGPMetric{
		Name:  name,
		State: state,
		Info:  info,
		Type:  sessionType,
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
	trafficMutex.RLock()
	if trafficRate, exists := localTrafficRate[interfaceName]; exists {
		rxRate = int64(trafficRate.RxRate)
		txRate = int64(trafficRate.TxRate)
	}
	trafficMutex.RUnlock()

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
			Current: -1, // Will be updated later with ping data
			Metric:  make([][2]int, 0),
		},
	}
}

// updateMetricsWithHistory updates metrics with historical data if available
func updateMetricsWithHistory(session BgpSession, timestamp int64, metric *SessionMetric,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64, mpBGP bool) {

	metricMutex.RLock()
	defer metricMutex.RUnlock()

	// Get old metrics if available
	oldMetric, exists := localMetrics[session.UUID]
	if exists {
		// Update traffic metrics history
		updateTrafficMetrics(metric, oldMetric, timestamp)

		// Update RTT metrics
		updateRTTMetrics(metric, oldMetric, session, timestamp)
		// Update route metrics
		if mpBGP {
			updateMPBGPRouteMetrics(metric, oldMetric, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export)
		} else {
			updateTraditionalBGPRouteMetrics(metric, oldMetric, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export)
		}
	} else {
		// First time collection, initialize with single data points
		initializeFirstTimeMetrics(metric, timestamp, ipv4Import, ipv4Export, ipv6Import, ipv6Export, mpBGP)
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

// updateRTTMetrics updates RTT (ping) metrics with improved efficiency
func updateRTTMetrics(metric *SessionMetric, oldMetric SessionMetric, session BgpSession, timestamp int64) {
	// Check if we have a recent RTT value (less than 5 minutes old)
	var rttValue int

	// Use dedicated rttMutex to protect access to rttTrackers map
	rttMutex.Lock()
	tracker, exists := rttTrackers[session.UUID]

	if exists {
		// Use the cached RTT value if recent enough
		rttValue = tracker.LastRTT
	} else {
		rttValue = -1 // Default to -1 if no tracker exists
	}
	rttMutex.Unlock()

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

	// Find IPv4 and IPv6 metrics by type instead of relying on index
	var oldIPv4Metric, oldIPv6Metric *BGPMetric
	var newIPv4Metric, newIPv6Metric *BGPMetric

	// Find old metrics by type
	for i := range oldMetric.BGP {
		switch oldMetric.BGP[i].Type {
		case BGP_SESSION_TYPE_IPV4:
			oldIPv4Metric = &oldMetric.BGP[i]
		case BGP_SESSION_TYPE_IPV6:
			oldIPv6Metric = &oldMetric.BGP[i]
		}
	}

	// Find new metrics by type
	for i := range metric.BGP {
		switch metric.BGP[i].Type {
		case BGP_SESSION_TYPE_IPV4:
			newIPv4Metric = &metric.BGP[i]
		case BGP_SESSION_TYPE_IPV6:
			newIPv6Metric = &metric.BGP[i]
		}
	}

	// Update IPv4 metrics if both old and new exist
	if oldIPv4Metric != nil && newIPv4Metric != nil {
		updateRouteMetricsArray(
			&newIPv4Metric.Routes.IPv4.Imported.Metric,
			oldIPv4Metric.Routes.IPv4.Imported.Metric,
			timestamp,
			ipv4Import,
		)

		updateRouteMetricsArray(
			&newIPv4Metric.Routes.IPv4.Exported.Metric,
			oldIPv4Metric.Routes.IPv4.Exported.Metric,
			timestamp,
			ipv4Export,
		)
	}

	// Update IPv6 metrics if both old and new exist
	if oldIPv6Metric != nil && newIPv6Metric != nil {
		updateRouteMetricsArray(
			&newIPv6Metric.Routes.IPv6.Imported.Metric,
			oldIPv6Metric.Routes.IPv6.Imported.Metric,
			timestamp,
			ipv6Import,
		)

		updateRouteMetricsArray(
			&newIPv6Metric.Routes.IPv6.Exported.Metric,
			oldIPv6Metric.Routes.IPv6.Exported.Metric,
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
func initializeFirstTimeMetrics(metric *SessionMetric, timestamp int64,
	ipv4Import, ipv4Export, ipv6Import, ipv6Export int64, mpBGP bool) {

	// Initialize traffic metric with a single data point
	metric.Interface.Traffic.Metric = [][3]int64{{
		timestamp,
		metric.Interface.Traffic.Current[0],
		metric.Interface.Traffic.Current[1],
	}}

	// Initialize RTT metric with a single data point(-1: timeout for initial)
	rttValue := -1
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
		// For traditional BGP - find metrics by type instead of using indices
		for i := range metric.BGP {
			switch metric.BGP[i].Type {
			case BGP_SESSION_TYPE_IPV4:
				// Initialize IPv4 metrics
				metric.BGP[i].Routes.IPv4.Imported.Metric = [][2]int64{{timestamp, int64(ipv4Import)}}
				metric.BGP[i].Routes.IPv4.Exported.Metric = [][2]int64{{timestamp, int64(ipv4Export)}}
			case BGP_SESSION_TYPE_IPV6:
				// Initialize IPv6 metrics
				metric.BGP[i].Routes.IPv6.Imported.Metric = [][2]int64{{timestamp, int64(ipv6Import)}}
				metric.BGP[i].Routes.IPv6.Exported.Metric = [][2]int64{{timestamp, int64(ipv6Export)}}
			}
		}
	}
}

// Tries to use the most recently successful IP protocol first, before falling back to others
func measureRTT(sessionUUID, ipv4, ipv6, ipv6ll string) int {
	// Check if we have a preferred protocol for this session
	rttMutex.RLock()
	tracker, exists := rttTrackers[sessionUUID]
	rttMutex.RUnlock()

	// Order of attempts based on previous success
	var attemptOrder []string

	if exists && tracker.PreferredProtocol != "" {
		// Try the previously successful protocol first
		attemptOrder = []string{tracker.PreferredProtocol}

		// Then add the other protocols
		for _, proto := range []string{"ipv6ll", "ipv6", "ipv4"} {
			if proto != tracker.PreferredProtocol {
				attemptOrder = append(attemptOrder, proto)
			}
		}
	} else {
		// Default order: IPv6 link-local first (usually faster), then IPv6, then IPv4
		attemptOrder = []string{"ipv6ll", "ipv6", "ipv4"}
	}

	// Try protocols in determined order
	for _, proto := range attemptOrder {
		var rtt int

		switch proto {
		case "ipv6ll":
			if ipv6ll != "" {
				rtt = pingRTT(fmt.Sprintf("[%s]", ipv6ll))
				if rtt != -1 {
					updateRTTTracker(sessionUUID, "ipv6ll", rtt)
					return rtt
				}
			}
		case "ipv6":
			if ipv6 != "" {
				rtt = pingRTT(fmt.Sprintf("[%s]", ipv6))
				if rtt != -1 {
					updateRTTTracker(sessionUUID, "ipv6", rtt)
					return rtt
				}
			}
		case "ipv4":
			if ipv4 != "" {
				rtt = pingRTT(ipv4)
				if rtt != -1 {
					updateRTTTracker(sessionUUID, "ipv4", rtt)
					return rtt
				}
			}
		}
	}

	// If all attempts fail, update tracker with failure and return 0
	updateRTTTracker(sessionUUID, "", -1)
	return -1
}

// updateRTTTracker updates the RTT tracking information for a session
func updateRTTTracker(sessionUUID, preferredProtocol string, rtt int) {
	rttMutex.Lock()
	defer rttMutex.Unlock()

	tracker, exists := rttTrackers[sessionUUID]
	if !exists {
		tracker = &RTTTracker{}
		rttTrackers[sessionUUID] = tracker
	}

	if preferredProtocol != "" {
		// which means we have a successful ping
		tracker.PreferredProtocol = preferredProtocol
		tracker.LastRTT = rtt
	}
}

// Actual implementation of ping RTT measurement using tcping
func pingRTT(ip string) int {
	// Track recently failed destinations to use shorter timeouts
	rttMutex.RLock()
	lastKnownFailedIP, exists := failedPingCache[ip]
	rttMutex.RUnlock()

	// If this IP has failed recently, force using a shorter timeout for the next attempt
	timeout := cfg.Metric.PingTimeout
	pingCount := cfg.Metric.PingCount

	if exists && time.Since(lastKnownFailedIP) < 10*time.Minute {
		pingCount = 1 // Just do a single ping attempt for recently failed destinations
	}

	// Try port 179 (standard BGP port)
	addr := fmt.Sprintf("%s:179", ip)
	rtt := tcpingAverage(addr, pingCount, timeout)

	// Update the failed IP cache
	rttMutex.Lock()
	if rtt <= 0 {
		// Remember this as a failed IP
		failedPingCache[ip] = time.Now()
	} else {
		// Remove from failed cache if it succeeds
		delete(failedPingCache, ip)
	}
	rttMutex.Unlock()

	// log.Printf("[Metrics] Ping RTT for %s: %d ms (timeout: %d s, count: %d)\n", ip, rtt, timeout, pingCount)
	return rtt
}

// Map to cache recently failed ping attempts to reduce timeout for known bad IPs
var failedPingCache = make(map[string]time.Time)

// batchMeasureRTT processes multiple RTT measurements in parallel
// This function is meant to be called before the regular metric collection cycle
func batchMeasureRTT() {
	// Use atomic operations to prevent multiple concurrent batch operations
	if !atomic.CompareAndSwapInt32(&batchRTTRunning, 0, 1) {
		// Another batch operation is already running, skip this one
		log.Println("[Metrics] Skipping batch RTT measurement - another operation is in progress, ping worker may not enough, current worker count:", PING_WORKER_COUNT)
		return
	}
	defer atomic.StoreInt32(&batchRTTRunning, 0)

	sessionMutex.RLock()
	sessions := make([]BgpSession, 0, len(localSessions))
	for _, session := range localSessions {
		if session.Status == PEERING_STATUS_ENABLED || session.Status == PEERING_STATUS_PROBLEM {
			sessions = append(sessions, session)
		}
	}
	sessionMutex.RUnlock()

	if len(sessions) == 0 {
		return
	}

	log.Printf("[Metrics] Starting batch RTT measurement for %d sessions", len(sessions))
	startTime := time.Now()

	// Create a worker pool with a reasonable number of workers
	workerCount := min(len(sessions), PING_WORKER_COUNT)

	// Create channels for work distribution
	jobs := make(chan BgpSession, len(sessions))
	results := make(chan struct{}, len(sessions))

	// Start worker goroutines
	for w := 1; w <= workerCount; w++ {
		go rttWorker(jobs, results)
	}

	// Send sessions to be processed
	for _, session := range sessions {
		jobs <- session
	}
	close(jobs)

	// Wait for all jobs to complete
	for range sessions {
		<-results
	}

	duration := time.Since(startTime)
	log.Printf("[Metrics] Completed batch RTT measurement for %d sessions in %v", len(sessions), duration)
}

// rttWorker is a worker goroutine that processes RTT measurements
func rttWorker(jobs <-chan BgpSession, results chan<- struct{}) {
	for session := range jobs {
		ipv6LinkLocal := session.IPv6LinkLocal
		if ipv6LinkLocal != "" {
			ipv6LinkLocal = fmt.Sprintf("%s%%%s", session.IPv6LinkLocal, session.Interface)
		}

		// Perform RTT measurement
		measureRTT(
			session.UUID,
			session.IPv4,
			session.IPv6,
			ipv6LinkLocal,
		)

		// Signal that this job is done
		results <- struct{}{}
	}
}

// cleanupRTTCache periodically cleans up the RTT trackers and failed ping cache
// to prevent memory leaks from accumulating over time
func cleanupRTTCache(ctx context.Context) {
	// Run this cleanup task every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[Metrics] Shutting down RTT cache cleanup task...")

			// Perform one final cleanup during shutdown with timeout
			cleanupDone := make(chan struct{})
			go func() {
				performRTTCacheCleanup()
				close(cleanupDone)
			}()

			// Wait with timeout
			select {
			case <-cleanupDone:
				log.Printf("[Metrics] Final RTT cache cleanup completed in %v", time.Since(shutdownStart))
			case <-time.After(2 * time.Second):
				log.Printf("[Metrics] Final RTT cache cleanup timed out after %v", time.Since(shutdownStart))
			}

			return
		case <-ticker.C:
			performRTTCacheCleanup()
		}
	}
}

// performRTTCacheCleanup does the actual work of cleaning up RTT caches
func performRTTCacheCleanup() {
	cleanupTime := time.Now()

	// Get the current list of active session UUIDs
	sessionMutex.RLock()
	activeUUIDs := make(map[string]bool)
	for _, s := range localSessions {
		activeUUIDs[s.UUID] = true
	}
	sessionMutex.RUnlock()

	// Cleanup RTT trackers
	rttMutex.Lock()
	defer rttMutex.Unlock()

	// Track cleanup stats
	trackersRemoved := 0
	cacheEntriesRemoved := 0

	for uuid := range rttTrackers {
		// Remove trackers for sessions that no longer exist
		if !activeUUIDs[uuid] {
			delete(rttTrackers, uuid)
			trackersRemoved++
		}
	}

	// Cleanup failed ping cache (remove entries older than 12 hours)
	for ip, lastFailTime := range failedPingCache {
		if time.Since(lastFailTime) > 12*time.Hour {
			delete(failedPingCache, ip)
			cacheEntriesRemoved++
		}
	}

	log.Printf("[Metrics] Cleaned up RTT caches at %s (removed %d trackers, %d failed cache entries)",
		cleanupTime.Format(time.RFC3339), trackersRemoved, cacheEntriesRemoved)
}

// metricTask schedules periodic metrics collection
func metricTask(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	// Start the RTT cache cleanup routine with context
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	var cleanupWg sync.WaitGroup
	cleanupWg.Add(1)
	go func() {
		defer cleanupWg.Done()
		cleanupRTTCache(cleanupCtx)
	}()

	// Make sure to wait for cleanup goroutine to finish
	defer func() {
		shutdownStart := time.Now()
		log.Println("[Metrics] Canceling RTT cache cleanup routine...")
		cleanupCancel()

		// Set a timeout for cleanup
		cleanupDone := make(chan struct{})
		go func() {
			cleanupWg.Wait()
			close(cleanupDone)
		}()

		// Wait for cleanup with timeout
		select {
		case <-cleanupDone:
			log.Printf("[Metrics] RTT cache cleanup completed in %v", time.Since(shutdownStart))
		case <-time.After(5 * time.Second):
			log.Printf("[Metrics] RTT cache cleanup timed out after %v", time.Since(shutdownStart))
		}
	}()

	// Start the regular metrics collection
	ticker := time.NewTicker(time.Duration(cfg.PeerAPI.MetricInterval) * time.Second)
	defer ticker.Stop()

	// Collect metrics immediately on startup
	collectMetrics()

	for {
		select {
		case <-ctx.Done():
			shutdownStart := time.Now()
			log.Println("[Metrics] Shutting down metrics collection task...")

			// Perform any cleanup specific to metrics
			metricMutex.Lock()
			log.Printf("[Metrics] Cleaning up %d metric entries", len(localMetrics))
			metricMutex.Unlock()

			log.Printf("[Metrics] Metrics collection task shutdown completed in %v", time.Since(shutdownStart))
			return
		case <-ticker.C:
			collectMetrics()
		}
	}
}
