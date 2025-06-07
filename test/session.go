package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

// tcping performs a single TCP connection attempt and returns latency in milliseconds.
// Returns 9999 on timeout or error.
func tcping(address string, timeout time.Duration) int {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return 9999
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

// TcpingAverage pings the address 4 times, 1 second apart, returns average latency.
func TcpingAverage(address string) int {
	var total int
	const tries = 4
	for i := 0; i < tries; i++ {
		delay := tcping(address, 1*time.Second)
		log.Println(delay)
		total += delay
		time.Sleep(1 * time.Second)
	}
	return total / tries
}

func main() {
	target := "[fd42:4242:2189::1]:1791" // Replace with your target
	avg := TcpingAverage(target)
	fmt.Printf("Average TCP ping to %s: %dms\n", target, avg)
}
