package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/matishsiao/goInfo"
	"github.com/oschwald/geoip2-golang"
)

func GetOsUname() string {
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

func GetTcpConnections() int {
	tcp4, _ := countConnections("/proc/net/tcp")
	tcp6, _ := countConnections("/proc/net/tcp6")
	return tcp4 + tcp6
}

func GetUdpConnections() int {
	udp4, _ := countConnections("/proc/net/udp")
	udp6, _ := countConnections("/proc/net/udp6")
	return udp4 + udp6
}

func GetUptimeSeconds() float64 {
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

func GetInterfaceTraffic(interfaces []string) (rxTotal, txTotal uint64, err error) {
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

func GetLoadAverageStr() string {
	load1, load5, load15, err := getLoadAverage()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.2f %.2f %.2f", load1, load5, load15)
}

func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func InterfaceExists(iface string) (exist bool, err error) {
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

func tcping(address string, timeout time.Duration) int {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return -1
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

func TcpingAverage(address string, tries, timeoutSeconds int) int {
	var total int
	for range tries {
		delay := tcping(address, time.Duration(timeoutSeconds)*time.Second)
		if delay == -1 {
			return -1
		}
		total += delay
		time.Sleep(1 * time.Second)
	}
	return total / tries
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

// GeoIPCountryCode returns the 2-letter country code from IP/hostname
func GeoIPCountryCode(db *geoip2.Reader, input string) (string, error) {
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

// GetInterfaceMTU returns the MTU of the given interface from /sys/class/net/<iface>/mtu
func GetInterfaceMTU(name string) (int, error) {
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

func GetInterfaceMAC(ifaceName string) (string, error) {
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

// GetInterfaceFlags returns the list of string flags (e.g. UP, BROADCAST) for the given interface
func GetInterfaceFlags(name string) (string, error) {
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
	return strings.Join(result, ",\x20"), nil
}

var interfaceFlagMap = map[uint64]string{
	0x1:     "UP",
	0x2:     "BROADCAST",
	0x4:     "DEBUG",
	0x8:     "LOOPBACK",
	0x10:    "POINTOPOINT",
	0x20:    "NOTRAILERS",
	0x40:    "RUNNING",
	0x80:    "NOARP",
	0x100:   "PROMISC",
	0x200:   "ALLMULTI",
	0x400:   "MASTER",
	0x800:   "SLAVE",
	0x1000:  "MULTICAST",
	0x2000:  "PORTSEL",
	0x4000:  "AUTOMEDIA",
	0x8000:  "DYNAMIC",
	0x10000: "LOWER_UP",
	0x20000: "DORMANT",
	0x40000: "ECHO",
}
