package bird

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	conn     *BirdConn
	lastUsed time.Time
	inUse    bool
	// id       int // Add connection ID for faster lookup
}

// BirdPool manages a pool of BIRD connections
type BirdPool struct {
	sync.RWMutex
	pool        []*PooledConnection
	available   chan *PooledConnection // Channel for available connections
	poolSize    int
	poolSizeMax int
	socketPath  string
	// nextID      int           // For assigning connection IDs
	shutdown chan struct{} // Graceful shutdown signal
}

// ProtocolMetrics represents the metrics for a single BGP protocol/session
type ProtocolMetrics struct {
	State      string
	Since      string
	Info       string
	IPv4Import int64
	IPv4Export int64
	IPv6Import int64
	IPv6Export int64
}

// ProtocolResult represents the result of a single protocol query
type ProtocolResult struct {
	SessionName string
	Metrics     ProtocolMetrics
	Error       error
}

// BatchQuery represents a BIRD query request
type BatchQuery struct {
	SessionName string
	Command     string
}

// BatchResult represents the result of a batch query
type BatchResult struct {
	SessionName string
	Output      string
	Error       error
}

// NewBirdPool creates a new BIRD connection pool
func NewBirdPool(socketPath string, poolSize, poolSizeMax int) (*BirdPool, error) {
	if poolSizeMax < poolSize {
		poolSizeMax = poolSize * 4 // Default max is 4x the base pool size
	}

	bp := &BirdPool{
		poolSize:    poolSize,
		poolSizeMax: poolSizeMax,
		socketPath:  socketPath,
		available:   make(chan *PooledConnection, poolSizeMax), // Buffered channel
		shutdown:    make(chan struct{}),
	}

	// Initialize connection pool
	for i := range bp.poolSize {
		bc, err := bp.createConnection()
		if err != nil {
			bp.Close()
			return nil, fmt.Errorf("failed to initialize connection %d: %v", i, err)
		}
		pc := &PooledConnection{
			conn:     bc,
			lastUsed: time.Now(),
			// id:       bp.nextID,
		}
		// bp.nextID++
		bp.pool = append(bp.pool, pc)
		// Pre-populate available channel
		bp.available <- pc
	}

	// Start pool maintenance goroutine
	go bp.poolMaintenance()

	return bp, nil
}

func (bp *BirdPool) createConnection() (*BirdConn, error) {
	bc, err := NewBirdConnection(bp.socketPath)
	if err != nil {
		return nil, err
	}

	restricted, err := bc.Restrict()
	if err != nil || !restricted {
		bc.Close()
		if err == nil {
			err = fmt.Errorf("failed to enter restricted mode")
		}
		return nil, err
	}

	return bc, nil
}

func (bp *BirdPool) GetConnection() (*PooledConnection, error) {
	// Try to get an available connection from channel first (fast path)
	select {
	case pc := <-bp.available:
		bp.Lock()
		pc.inUse = true
		pc.lastUsed = time.Now()
		bp.Unlock()
		return pc, nil
	default:
		// No immediately available connection, try to create new one or wait
	}

	bp.Lock()
	currentSize := len(bp.pool)
	if currentSize < bp.poolSizeMax {
		// Create a new connection
		birdConn, err := bp.createConnection()
		if err != nil {
			bp.Unlock()
			return nil, fmt.Errorf("failed to create new connection: %v", err)
		}

		pc := &PooledConnection{
			conn:     birdConn,
			lastUsed: time.Now(),
			inUse:    true,
			// id:       bp.nextID,
		}
		// bp.nextID++
		bp.pool = append(bp.pool, pc)
		bp.Unlock()
		return pc, nil
	}
	bp.Unlock()

	// Wait for an available connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case pc := <-bp.available:
		bp.Lock()
		pc.inUse = true
		pc.lastUsed = time.Now()
		bp.Unlock()
		return pc, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting for available connection")
	case <-bp.shutdown:
		return nil, fmt.Errorf("connection pool is shutting down")
	}
}

func (bp *BirdPool) ReleaseConnection(pc *PooledConnection) {
	bp.Lock()
	pc.inUse = false
	pc.lastUsed = time.Now()
	bp.Unlock()

	// Return connection to available pool (non-blocking)
	select {
	case bp.available <- pc:
		// Successfully returned to pool
	default:
		// Channel is full, connection will be picked up by maintenance
	}
}

// Close closes all connections in the pool
func (bp *BirdPool) Close() {
	close(bp.shutdown) // Signal shutdown

	bp.Lock()
	defer bp.Unlock()

	// Close available channel
	close(bp.available)

	// Drain the channel and close connections
	for {
		select {
		case pc := <-bp.available:
			if pc.conn != nil {
				pc.conn.Close()
			}
		default:
			goto drainComplete
		}
	}
drainComplete:

	// Close remaining connections in pool
	for _, pc := range bp.pool {
		if pc.conn != nil {
			pc.conn.Close()
			pc.conn = nil
		}
	}
	bp.pool = nil
}

// poolMaintenance periodically checks for and removes stale connections
func (bp *BirdPool) poolMaintenance() {
	ticker := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ticker.C:
			bp.Lock()
			if len(bp.pool) > bp.poolSize {
				now := time.Now()
				newPool := make([]*PooledConnection, 0, bp.poolSize)
				for _, pc := range bp.pool {
					// Keep if in use or if it's part of the base pool size
					if pc.inUse || len(newPool) < bp.poolSize {
						newPool = append(newPool, pc)
						continue
					}

					// Remove if connection is old and unused
					if now.Sub(pc.lastUsed) > 5*time.Minute {
						if pc.conn != nil {
							pc.conn.Close()
							pc.conn = nil
						}
					} else {
						newPool = append(newPool, pc)
					}
				}
				bp.pool = newPool
			}
			bp.Unlock()
		case <-bp.shutdown:
			ticker.Stop()
			return
		}
	}
}

func (bp *BirdPool) WithConnection(fn func(conn *BirdConn) error) error {
	pc, err := bp.GetConnection()
	if err != nil {
		return err
	}
	defer bp.ReleaseConnection(pc)

	err = fn(pc.conn)
	if err != nil {
		// Try to reconnect on error
		if newConn, reconnErr := bp.createConnection(); reconnErr == nil {
			bp.Lock()
			pc.conn.Close()
			pc.conn = newConn
			bp.Unlock()

			// Retry the operation once
			err = fn(pc.conn)
		}
	}
	return err
}

func (bp *BirdPool) ShowStatus() (string, error) {
	var output string
	err := bp.WithConnection(func(conn *BirdConn) error {
		var buf bytes.Buffer
		if err := conn.Write("show status"); err != nil {
			return err
		}
		conn.Read(&buf)
		output = buf.String()
		return nil
	})
	return output, err
}

// This does not affect by pool size, always use a new conn
func (bp *BirdPool) Configure() (bool, error) {
	bc, err := NewBirdConnection(bp.socketPath)
	if err != nil {
		return false, err
	}
	defer bc.Close()

	if err := bc.Write("configure"); err != nil {
		return false, nil
	}

	// Dismiss output
	bc.Read(nil)
	return true, nil
}

// BatchShowProtocols executes multiple BIRD protocol queries concurrently
// This will utilize connection pool and return results in a map
func (bp *BirdPool) BatchGetProtocolStatus(sessionNames []string) map[string]ProtocolMetrics {
	if len(sessionNames) == 0 {
		return make(map[string]ProtocolMetrics)
	}

	results := make(map[string]ProtocolMetrics)
	resultsChan := make(chan ProtocolResult, len(sessionNames))

	// Execute queries in parallel using goroutines
	var wg sync.WaitGroup
	for _, name := range sessionNames {
		wg.Add(1)
		go func(sessionName string) {
			defer wg.Done()

			// Call the optimized version of ShowProtocolRoutes
			state, since, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, err := bp.GetProtocolStatus(sessionName)

			metrics := ProtocolMetrics{
				State:      state,
				Since:      since,
				Info:       info,
				IPv4Import: ipv4Import,
				IPv4Export: ipv4Export,
				IPv6Import: ipv6Import,
				IPv6Export: ipv6Export,
			}

			resultsChan <- ProtocolResult{
				SessionName: sessionName,
				Metrics:     metrics,
				Error:       err,
			}
		}(name)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultsChan)

	// Collect results
	for result := range resultsChan {
		if result.Error == nil {
			results[result.SessionName] = result.Metrics
		}
	}

	return results
}

// GetProtocolStatus executes "show protocols all <sessionName>" and extracts route statistics
// Returns route counts for IPv4 and IPv6 (imported and exported), along with protocol state, since time, and info
func (bp *BirdPool) GetProtocolStatus(sessionName string) (string, string, string, int64, int64, int64, int64, error) {
	var output string

	err := bp.WithConnection(func(conn *BirdConn) error {
		var buf bytes.Buffer
		buf.Grow(4096) // Pre-allocate buffer to reduce allocations

		if err := conn.Write("show protocols all " + sessionName); err != nil {
			return err
		}
		conn.Read(&buf)
		output = buf.String()
		return nil
	})
	if err != nil {
		return "", "", "", 0, 0, 0, 0, err
	}

	// Parse the output using optimized byte operations
	return parseProtocolOutput([]byte(output))
}

// parseProtocolOutput optimizes the parsing of BIRD protocol output
func parseProtocolOutput(data []byte) (string, string, string, int64, int64, int64, int64, error) {
	var (
		state      string
		since      string
		info       string
		ipv4Import int64
		ipv4Export int64
		ipv6Import int64
		ipv6Export int64
	)

	lines := bytes.Split(data, []byte("\n"))
	var currentChannel string

	// Parse first line for state, since, and info
	if len(lines) > 1 {
		dataLine := lines[1]
		fields := bytes.Fields(dataLine)

		// Fields: [Name, Proto, Table, State, Since+Date, Since+Time, Info...]
		// xxxx BGP        ---        up     2025-06-12 16:11:45  Established
		// yyyy BGP        ---        down   2025-06-12 16:11:45  Active Socket: Reason
		if len(fields) >= 7 {
			state = string(fields[3])

			// Combine date and time for since field
			since = string(fields[4])
			if len(fields) > 5 {
				since += " " + string(fields[5])
			}

			// Combine remaining fields for info
			if len(fields) > 6 {
				infoFields := fields[6:]
				infoBytes := bytes.Join(infoFields, []byte(" "))
				info = string(infoBytes)
			}
		}
	}

	// Process remaining lines for channel information
	for _, line := range lines[2:] {
		lineStr := string(bytes.TrimSpace(line))

		// Detect channel using regex
		if matches := channelRegex.FindStringSubmatch(lineStr); len(matches) > 1 {
			currentChannel = matches[1]
			continue
		}

		// Check for DOWN state using regex
		if stateDownRegex.Match(bytes.TrimSpace(line)) {
			if currentChannel == "ipv4" {
				ipv4Import = 0
				ipv4Export = 0
			} else if currentChannel == "ipv6" {
				ipv6Import = 0
				ipv6Export = 0
			}
			continue
		}

		// Extract route counts using regex
		if matches := routeLineRegex.FindStringSubmatch(lineStr); len(matches) > 2 {
			imported, err1 := strconv.ParseInt(matches[1], 10, 64)
			exported, err2 := strconv.ParseInt(matches[2], 10, 64)

			if err1 == nil && err2 == nil {
				if currentChannel == "ipv4" {
					ipv4Import = imported
					ipv4Export = exported
				} else if currentChannel == "ipv6" {
					ipv6Import = imported
					ipv6Export = exported
				}
			}
		}
	}

	return state, since, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, nil
}

// Pre-compiled regex patterns for better performance
var (
	routeLineRegex = regexp.MustCompile(`^Routes:\s+(\d+)\s+imported,\s+(\d+)\s+exported`)
	channelRegex   = regexp.MustCompile(`^Channel\s+(ipv[46])$`)
	stateDownRegex = regexp.MustCompile(`^State:.*DOWN`)

	// Additional optimized patterns for protocol parsing
	protocolLineRegex = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`)
	sinceTimeRegex    = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)
)

// Compile patterns once at package initialization for optimal performance
func init() {
	// Verify all patterns compile correctly
	patterns := []*regexp.Regexp{
		routeLineRegex,
		channelRegex,
		stateDownRegex,
		protocolLineRegex,
		sinceTimeRegex,
	}

	for i, pattern := range patterns {
		if pattern == nil {
			panic(fmt.Sprintf("Failed to compile regex pattern %d", i))
		}
	}
}
