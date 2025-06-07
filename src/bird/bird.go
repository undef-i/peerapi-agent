package bird

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	conn     *BirdConn
	lastUsed time.Time
	inUse    bool
}

// BirdPool manages a pool of BIRD connections
type BirdPool struct {
	sync.RWMutex
	pool        []*PooledConnection
	poolSize    int
	poolSizeMax int
	socketPath  string
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
	}

	// Initialize connection pool
	for i := range bp.poolSize {
		bc, err := bp.createConnection()
		if err != nil {
			bp.Close()
			return nil, fmt.Errorf("failed to initialize connection %d: %v", i, err)
		}
		bp.pool = append(bp.pool, &PooledConnection{
			conn:     bc,
			lastUsed: time.Now(),
		})
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
	bp.Lock()
	defer bp.Unlock()

	// Try to find an available connection in the pool
	for _, pc := range bp.pool {
		if !pc.inUse {
			pc.inUse = true
			pc.lastUsed = time.Now()
			return pc, nil
		}
	}

	// If all connections are in use, check if we can create a new one
	currentSize := len(bp.pool)
	if currentSize >= bp.poolSizeMax {
		// We've hit the maximum pool size, wait for a connection to become available
		bp.Unlock() // Unlock before waiting

		// Wait for a connection with timeout
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				return nil, fmt.Errorf("timeout waiting for available connection")
			case <-ticker.C:
				bp.Lock()
				// Check again for available connection
				for _, pc := range bp.pool {
					if !pc.inUse {
						pc.inUse = true
						pc.lastUsed = time.Now()
						bp.Unlock()
						return pc, nil
					}
				}
				bp.Unlock()
			}
		}
	}

	// Create a new connection
	birdConn, err := bp.createConnection()
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %v", err)
	}

	pc := &PooledConnection{
		conn:     birdConn,
		lastUsed: time.Now(),
		inUse:    true,
	}
	bp.pool = append(bp.pool, pc)
	return pc, nil
}

func (bp *BirdPool) ReleaseConnection(pc *PooledConnection) {
	bp.Lock()
	defer bp.Unlock()

	// Mark the connection as not in use
	pc.inUse = false
	pc.lastUsed = time.Now()
}

// Close closes all connections in the pool
func (bp *BirdPool) Close() {
	bp.Lock()
	defer bp.Unlock()

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
	for range ticker.C {
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
			pc.conn.Close()
			pc.conn = newConn
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

	return true, nil
}

// ShowProtocolRoutes executes "show protocols all <sessionName>" and extracts route statistics
// Returns route counts for IPv4 and IPv6 (imported and exported), along with protocol state, since time, and info
func (bp *BirdPool) ShowProtocolRoutes(sessionName string) (string, string, string, int64, int64, int64, int64, error) {
	var (
		state      string = ""
		since      string = ""
		info       string = ""
		ipv4Import int64  = 0
		ipv4Export int64  = 0
		ipv6Import int64  = 0
		ipv6Export int64  = 0
		output     string
	)

	err := bp.WithConnection(func(conn *BirdConn) error {
		var buf bytes.Buffer
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

	// Parse the output
	lines := bytes.Split([]byte(output), []byte("\n"))
	var currentChannel string

	// First line typically contains the state, since, and info fields
	if len(lines) > 0 {
		// Expected format: "Name       Proto      Table      State  Since         Info"
		if len(lines) > 1 {
			dataLine := string(lines[1])
			fields := bytes.Fields([]byte(dataLine))

			// Fields should be [Name, Proto, Table, State, Since+Date, Since+Time, Info]
			if len(fields) >= 7 {
				stateIndex := 3
				sinceIndex := 4 // This might include date
				infoIndex := 6  // This might be the info field

				state = string(fields[stateIndex])

				// Since field might be spread across two fields (date and time)
				since = string(fields[sinceIndex])
				if len(fields) > sinceIndex+1 {
					since += " " + string(fields[sinceIndex+1])
				}

				// Info field might be the last field or could be multiple fields
				if len(fields) > infoIndex {
					info = string(fields[infoIndex])
					// Combine any remaining fields as part of info
					for i := infoIndex + 1; i < len(fields); i++ {
						info += " " + string(fields[i])
					}
				}
			}
		}
	}

	for _, line := range lines {
		lineStr := string(bytes.TrimSpace(line))

		// Detect which channel we're processing
		if lineStr == "Channel ipv4" {
			currentChannel = "ipv4"
			continue
		} else if lineStr == "Channel ipv6" {
			currentChannel = "ipv6"
			continue
		}

		// Check if the channel is DOWN
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("State:")) && bytes.Contains(bytes.TrimSpace(line), []byte("DOWN")) {
			if currentChannel == "ipv4" {
				ipv4Import = 0
				ipv4Export = 0
			} else if currentChannel == "ipv6" {
				ipv6Import = 0
				ipv6Export = 0
			}
			continue
		}

		// Extract route counts from "Routes:" line
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("Routes:")) {
			var imported, exported int64
			// Extract numbers from format: "Routes: X imported, Y exported, Z preferred"
			routesLine := string(bytes.TrimSpace(line))
			_, err := fmt.Sscanf(routesLine, "Routes: %d imported, %d exported", &imported, &exported)
			if err != nil {
				continue // Skip if parsing fails
			}

			if currentChannel == "ipv4" {
				ipv4Import = imported
				ipv4Export = exported
			} else if currentChannel == "ipv6" {
				ipv6Import = imported
				ipv6Export = exported
			}
		}
	}

	return state, since, info, ipv4Import, ipv4Export, ipv6Import, ipv6Export, nil
}
