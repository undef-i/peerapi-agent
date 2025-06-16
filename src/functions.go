package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"slices"

	"github.com/go-ping/ping"
	"github.com/matishsiao/goInfo"
	"github.com/oschwald/geoip2-golang"
)

func getOsUname() string {
	gi, _ := goInfo.GetInfo()
	platform := gi.Platform
	if strings.ToLower(platform) == "unknown" {
		platform = runtime.GOARCH
	}
	return fmt.Sprintf("%s %s %s", gi.Kernel, gi.Core, platform)
}

func countConnections(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		// It’s fine if the system doesn't support IPv6, just return 0
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	firstLine := true
	for scanner.Scan() {
		if firstLine {
			firstLine = false // skip header
			continue
		}
		count++
	}
	return count, scanner.Err()
}

func getTcpConnections() int {
	tcp4, _ := countConnections("/proc/net/tcp")
	tcp6, _ := countConnections("/proc/net/tcp6")
	return tcp4 + tcp6
}

func getUdpConnections() int {
	udp4, _ := countConnections("/proc/net/udp")
	udp6, _ := countConnections("/proc/net/udp6")
	return udp4 + udp6
}

func getUptimeSeconds() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return 0
	}
	uptime, _ := strconv.ParseFloat(parts[0], 64)
	return uptime
}

func getInterfaceTraffic(interfaces []string) (rxTotal, txTotal uint64, err error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	ifaceSet := make(map[string]struct{})
	for _, iface := range interfaces {
		ifaceSet[iface] = struct{}{}
	}

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount <= 2 {
			// Skip headers
			continue
		}

		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if _, ok := ifaceSet[iface]; !ok {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		// RX bytes = fields[0], TX bytes = fields[8]
		var rx, tx uint64
		fmt.Sscanf(fields[0], "%d", &rx)
		fmt.Sscanf(fields[8], "%d", &tx)

		rxTotal += rx
		txTotal += tx
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	return rxTotal, txTotal, nil
}

func getLoadAverage() (load1, load5, load15 float64, err error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}

	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("unexpected format: %s", data)
	}

	load1, err = strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return
	}
	load5, err = strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return
	}
	load15, err = strconv.ParseFloat(parts[2], 64)
	return
}

func getLoadAverageStr() string {
	load1, load5, load15, err := getLoadAverage()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.2f %.2f %.2f", load1, load5, load15)
}

func interfaceExists(iface string) (exist bool, err error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount <= 2 {
			// Skip headers
			continue
		}

		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		_iface := strings.TrimSpace(parts[0])
		if _iface == iface {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	return false, nil
}

func icmpPingAverage(address string, tries, timeoutSeconds int) int {
	// Create pinger
	pinger, err := ping.NewPinger(address)
	if err != nil {
		return -1
	}

	// Needs root privileges for ICMP or NET capabilities
	pinger.SetPrivileged(true)

	// Configure ping parameters
	pinger.Count = tries
	pinger.Timeout = time.Duration(timeoutSeconds) * time.Second
	pinger.Interval = time.Second // 1 second interval

	// Run the ping
	err = pinger.Run()
	if err != nil {
		return -1
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1
	}

	// Use built-in average calculation from go-ping
	return int(stats.AvgRtt.Milliseconds())
}

// Parse input string (with or without port) and extract IP/hostname
func extractHost(addr string) string {
	// Handle IPv6 [::1]:443
	if strings.HasPrefix(addr, "[") {
		if i := strings.Index(addr, "]"); i != -1 {
			return addr[1:i]
		}
	}
	// For host:port
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr // No port
}

// Resolve hostname to IP
func resolveToIP(host string) (net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	return ips[0], nil // fallback to first (IPv6)
}

// geoIPCountryCode returns the 2-letter country code from IP/hostname
func geoIPCountryCode(db *geoip2.Reader, input string) (string, error) {
	host := extractHost(input)
	ip, err := resolveToIP(host)
	if err != nil {
		return "", err
	}
	record, err := db.Country(ip)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(record.Country.IsoCode), nil
}

// getInterfaceMTU returns the MTU of the given interface from /sys/class/net/<iface>/mtu
func getInterfaceMTU(name string) (int, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/mtu")
	if err != nil {
		return 0, fmt.Errorf("failed to read MTU: %w", err)
	}
	mtuStr := strings.TrimSpace(string(data))
	mtu, err := strconv.Atoi(mtuStr)
	if err != nil {
		return 0, fmt.Errorf("invalid MTU format: %w", err)
	}
	return mtu, nil
}

func getInterfaceMAC(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	mac := iface.HardwareAddr.String()
	if mac == "" {
		return "", fmt.Errorf("no MAC address found for interface %s", ifaceName)
	}
	return mac, nil
}

// getInterfaceFlags returns the list of string flags (e.g. UP, BROADCAST) for the given interface
func getInterfaceFlags(name string) (string, error) {
	data, err := os.ReadFile("/sys/class/net/" + name + "/flags")
	if err != nil {
		return "", fmt.Errorf("failed to read flags: %w", err)
	}
	flagStr := strings.TrimSpace(string(data))
	flags, err := strconv.ParseUint(flagStr, 0, 64)
	if err != nil {
		return "", fmt.Errorf("invalid flags format: %w", err)
	}

	var result []string
	for bit, name := range interfaceFlagMap {
		if flags&bit != 0 {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	return strings.Join(result, ",\x20"), nil
}

var interfaceFlagMap = map[uint64]string{
	0x1:     "UP",
	0x2:     "Broadcast",
	0x4:     "Debug",
	0x8:     "Loopback",
	0x10:    "PointToPoint",
	0x20:    "NoTrailers",
	0x40:    "Running",
	0x80:    "NoARP",
	0x100:   "Promisc",
	0x200:   "AllMulti",
	0x400:   "Master",
	0x800:   "Slave",
	0x1000:  "Multicast",
	0x2000:  "PortSel",
	0x4000:  "AutoMedia",
	0x8000:  "Dynamic",
	0x10000: "LowerUp",
	0x20000: "Dormant",
	0x40000: "Echo",
}

func _getRandomUnusedPort(proto string) (int, error) {
	var addr *net.UDPAddr
	var err error

	switch proto {
	case "tcp":
		// Use port :0 to let the OS choose a free port
		l, err := net.Listen("tcp", ":0")
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port, nil
	case "udp":
		addr, err = net.ResolveUDPAddr("udp", ":0")
		if err != nil {
			return 0, err
		}
		c, err := net.ListenUDP("udp", addr)
		if err != nil {
			return 0, err
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

var (
	reservedPorts      = make(map[int]int64)
	reservedPortsMutex sync.Mutex
)

// GetRandomUnusedPort returns a random unused port based on protocol ("tcp" or "udp")
func getRandomUnusedPort(proto string) (int, error) {
	const maxRetries = 10

	for i := 0; i < maxRetries; i++ {
		port, err := _getRandomUnusedPort(proto)
		if err != nil {
			return 0, fmt.Errorf("failed to get random unused port: %w", err)
		}
		reservedPortsMutex.Lock()
		if expireTimestamp, exists := reservedPorts[port]; exists {
			if time.Now().Unix() < expireTimestamp {
				// Port is reserved, skip it
				reservedPortsMutex.Unlock()
				continue // try again
			}
		}
		reservedPorts[port] = time.Now().Unix() + 300
		reservedPortsMutex.Unlock()
		return port, nil
	}

	return 0, fmt.Errorf("unable to find unused port after %d attempts", maxRetries)
}
