package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/client"
	"github.com/iedon/peerapi-agent/bird"
)

// MetricJob represents a single metric collection job
type MetricJob struct {
	Session   BgpSession
	Timestamp int64
}

// MetricResult represents the result of metric collection for one session
type MetricResult struct {
	UUID   string
	Metric SessionMetric
	Error  error
}

// collectMetrics collects metrics for all sessions or a specific session using optimized worker pools
func collectMetrics() {
	now := time.Now().Unix()

	// Get active sessions first
	sessionMutex.RLock()
	activeSessions := make([]BgpSession, 0, len(localSessions))
	for _, s := range localSessions {
		if s.Status == PEERING_STATUS_ENABLED || s.Status == PEERING_STATUS_PROBLEM {
			activeSessions = append(activeSessions, s)
		}
	}
	sessionMutex.RUnlock()

	if len(activeSessions) == 0 {
		log.Println("[Metrics] No active sessions to collect metrics from.")
		return
	}

	// Use concurrent processing for metric collection
	newSessionMetrics := batchCollectSessionMetrics(activeSessions, now)

	if len(newSessionMetrics) == 0 {
		log.Println("[Metrics] No metrics collected from active sessions.")
		return
	}

	// Update the local metric map with the latest metrics
	metricMutex.Lock()
	maps.Copy(localMetrics, newSessionMetrics)
	metricMutex.Unlock()

	// Send metrics to PeerAPI
	sendMetricsToPeerAPI(newSessionMetrics)
}

// batchCollectSessionMetrics collects metrics for multiple sessions concurrently
func batchCollectSessionMetrics(sessions []BgpSession, timestamp int64) map[string]SessionMetric {
	if len(sessions) == 0 {
		return make(map[string]SessionMetric)
	}

	startTime := time.Now()

	// Pre-collect BIRD protocol data for all sessions in parallel
	sessionNames := make([]string, 0, len(sessions)*2) // Estimate for traditional BGP
	sessionNameMap := make(map[string]BgpSession)

	for _, session := range sessions {
		sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)
		mpBGP := slices.Contains(session.Extensions, "mp-bgp")

		if mpBGP {
			// MP-BGP uses single session
			sessionNames = append(sessionNames, sessionName)
			sessionNameMap[sessionName] = session
		} else {
			// Traditional BGP uses separate v4 and v6 sessions
			if session.IPv4 != "" {
				v4Name := sessionName + "_v4"
				sessionNames = append(sessionNames, v4Name)
				sessionNameMap[v4Name] = session
			}
			if session.IPv6LinkLocal != "" || session.IPv6 != "" {
				v6Name := sessionName + "_v6"
				sessionNames = append(sessionNames, v6Name)
				sessionNameMap[v6Name] = session
			}
		}
	}

	// Batch query BIRD for all protocol statuses concurrently
	birdMetrics := birdPool.BatchGetProtocolStatus(sessionNames)

	// Create worker pool for concurrent session processing
	workerCount := min(len(sessions), cfg.Metric.SessionWorkerCount)
	if workerCount == 0 {
		workerCount = min(len(sessions), 8) // Default fallback
	}

	jobs := make(chan MetricJob, len(sessions))
	results := make(chan MetricResult, len(sessions))

	// Start worker goroutines
	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go metricWorker(jobs, results, birdMetrics, &wg)
	}

	// Send jobs to workers
	for _, session := range sessions {
		jobs <- MetricJob{
			Session:   session,
			Timestamp: timestamp,
		}
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	newSessionMetrics := make(map[string]SessionMetric, len(sessions))
	for result := range results {
		if result.Error != nil {
			log.Printf("[Metrics] Failed to collect metrics for session %s: %v", result.UUID, result.Error)
			continue
		}
		newSessionMetrics[result.UUID] = result.Metric
	}

	duration := time.Since(startTime)
	log.Printf("[Metrics] Collected metrics for %d sessions using %d workers in %v",
		len(newSessionMetrics), workerCount, duration)

	return newSessionMetrics
}

// metricWorker processes metric collection jobs concurrently
func metricWorker(jobs <-chan MetricJob, results chan<- MetricResult, birdMetrics map[string]bird.ProtocolMetrics, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		result := MetricResult{
			UUID: job.Session.UUID,
		}

		// Collect metrics for this session
		metric, err := collectSessionMetric(job.Session, job.Timestamp, birdMetrics)
		if err != nil {
			result.Error = err
		} else {
			result.Metric = metric
		}

		results <- result
	}
}

// collectSessionMetric collects metrics for a single session using pre-fetched BIRD data
func collectSessionMetric(session BgpSession, timestamp int64, birdMetrics map[string]bird.ProtocolMetrics) (SessionMetric, error) {
	sessionName := fmt.Sprintf("DN42_%d_%s", session.ASN, session.Interface)
	mpBGP := slices.Contains(session.Extensions, "mp-bgp")

	// Initialize variables for BGP metrics
	var ipv4Import, ipv4Export, ipv6Import, ipv6Export int64
	var bgpMetrics []BGPMetric

	// Collect BGP metrics using pre-fetched data
	if mpBGP {
		// For MP-BGP, look up the single session
		if metrics, exists := birdMetrics[sessionName]; exists {
			bgpMetrics = []BGPMetric{
				createBGPMetric(sessionName, metrics.State, metrics.Info, BGP_SESSION_TYPE_MPBGP,
					int(metrics.IPv4Import), int(metrics.IPv4Export),
					int(metrics.IPv6Import), int(metrics.IPv6Export)),
			}
			ipv4Import = metrics.IPv4Import
			ipv4Export = metrics.IPv4Export
			ipv6Import = metrics.IPv6Import
			ipv6Export = metrics.IPv6Export
		} else {
			// Default empty metrics if BIRD data is missing
			bgpMetrics = []BGPMetric{
				createBGPMetric(sessionName, "Unknown", "No data", BGP_SESSION_TYPE_MPBGP, 0, 0, 0, 0),
			}
		}
	} else {
		// For traditional BGP, look up v4 and v6 sessions separately
		bgpMetrics = make([]BGPMetric, 0, 2)

		if session.IPv6LinkLocal != "" || session.IPv6 != "" {
			v6Name := sessionName + "_v6"
			if metrics, exists := birdMetrics[v6Name]; exists {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v6Name, metrics.State, metrics.Info, BGP_SESSION_TYPE_IPV6,
					0, 0, int(metrics.IPv6Import), int(metrics.IPv6Export)))
				ipv6Import = metrics.IPv6Import
				ipv6Export = metrics.IPv6Export
			} else {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v6Name, "Unknown", "No data", BGP_SESSION_TYPE_IPV6, 0, 0, 0, 0))
			}
		}

		if session.IPv4 != "" {
			v4Name := sessionName + "_v4"
			if metrics, exists := birdMetrics[v4Name]; exists {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v4Name, metrics.State, metrics.Info, BGP_SESSION_TYPE_IPV4,
					int(metrics.IPv4Import), int(metrics.IPv4Export), 0, 0))
				ipv4Import = metrics.IPv4Import
				ipv4Export = metrics.IPv4Export
			} else {
				bgpMetrics = append(bgpMetrics, createBGPMetric(v4Name, "Unknown", "No data", BGP_SESSION_TYPE_IPV4, 0, 0, 0, 0))
			}
		}
	}

	// Get interface traffic statistics from /proc/net/dev
	rx, tx, _ := getInterfaceTraffic([]string{session.Interface})

	// Get current traffic rates from localTrafficRate
	rxRate, txRate := getTrafficRates(session.Interface)

	// Initialize new metric
	metric := initializeSessionMetric(session, timestamp, bgpMetrics, rx, tx, rxRate, txRate)

	// Update metrics with historical data if available
	updateMetricsWithHistory(session, timestamp, &metric, ipv4Import, ipv4Export, ipv6Import, ipv6Export, mpBGP)

	return metric, nil
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
	log.Printf("[Metrics] Sending %d session metrics to PeerAPI...", len(metricsArray))

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

	if len(trafficMetric) > cfg.Metric.MaxMetricsHistroy {
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

	if len(rttMetric) > cfg.Metric.MaxMetricsHistroy {
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
	if len(newArray) > cfg.Metric.MaxMetricsHistroy {
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
		tracker = &RTTTracker{LastRTT: -1} // Initialize LastRTT with -1
		rttTrackers[sessionUUID] = tracker
	}

	if preferredProtocol != "" {
		// which means we have a successful ping
		tracker.PreferredProtocol = preferredProtocol
		tracker.LastRTT = rtt
	}
}

// Map to cache recently failed ping attempts to reduce timeout for known bad IPs
var failedPingCache = make(map[string]time.Time)

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
		pingCount = cfg.Metric.PingCountOnFail // Just do PingCountOnFail attempts for recently failed destinations
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

// batchMeasureRTT processes multiple RTT measurements in parallel with context cancellation support
// This function is meant to be called as a background task before the regular metric collection cycle
func batchMeasureRTT(ctx context.Context) {
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
	workerCount := min(len(sessions), cfg.Metric.PingWorkerCount)

	// Create channels for work distribution
	jobs := make(chan BgpSession, len(sessions))
	results := make(chan struct{}, len(sessions))

	// Start worker goroutines
	for w := 1; w <= workerCount; w++ {
		go rttWorker(ctx, jobs, results)
	}

	// Send sessions to be processed
	for _, session := range sessions {
		select {
		case jobs <- session:
		case <-ctx.Done():
			close(jobs)
			log.Printf("[Metrics] Batch RTT measurement cancelled")
			return
		}
	}
	close(jobs)

	// Wait for all jobs to complete or context cancellation
	completedJobs := 0
	for completedJobs < len(sessions) {
		select {
		case <-results:
			completedJobs++
		case <-ctx.Done():
			log.Printf("[Metrics] Batch RTT measurement cancelled after %d/%d jobs", completedJobs, len(sessions))
			return
		}
	}

	duration := time.Since(startTime)
	log.Printf("[Metrics] Completed batch RTT measurement for %d sessions using %d workers in %v", len(sessions), workerCount, duration)
}

// rttWorker is a worker goroutine that processes RTT measurements with context cancellation support
func rttWorker(ctx context.Context, jobs <-chan BgpSession, results chan<- struct{}) {
	for {
		select {
		case session, ok := <-jobs:
			if !ok {
				return
			}

			// Check if context is cancelled before processing
			select {
			case <-ctx.Done():
				return
			default:
			}

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
			select {
			case results <- struct{}{}:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
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

// metricTask schedules periodic metrics collection with integrated RTT measurement
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

	// Start the RTT measurement routine as a background sub task
	rttCtx, rttCancel := context.WithCancel(ctx)
	var rttWg sync.WaitGroup
	rttWg.Add(1)
	go func() {
		defer rttWg.Done()
		batchRTTSubTask(rttCtx)
	}()

	// Make sure to wait for all background goroutines to finish
	defer func() {
		shutdownStart := time.Now()
		log.Println("[Metrics] Canceling RTT measurement and cache cleanup routines...")

		// Cancel both background tasks
		rttCancel()
		cleanupCancel()

		// Set a timeout for cleanup
		cleanupDone := make(chan struct{})
		go func() {
			rttWg.Wait()
			cleanupWg.Wait()
			close(cleanupDone)
		}()

		// Wait for cleanup with timeout
		select {
		case <-cleanupDone:
			log.Printf("[Metrics] RTT measurement and cache cleanup completed in %v", time.Since(shutdownStart))
		case <-time.After(5 * time.Second):
			log.Printf("[Metrics] RTT measurement and cache cleanup timed out after %v", time.Since(shutdownStart))
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

// batchRTTTask runs periodic RTT measurements as a background task
func batchRTTSubTask(ctx context.Context) {
	// Create a ticker for RTT measurement interval
	// RTT measurements should be more frequent than metric collection to provide fresh data
	rttInterval := max(time.Duration(cfg.PeerAPI.MetricInterval)*time.Second, 60*time.Second)

	ticker := time.NewTicker(rttInterval)
	defer ticker.Stop()

	// Perform initial RTT measurement
	log.Printf("[Metrics] Starting RTT measurement task with interval %v", rttInterval)
	batchMeasureRTT(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Metrics] RTT measurement task shutting down...")
			return
		case <-ticker.C:
			batchMeasureRTT(ctx)
		}
	}
}
