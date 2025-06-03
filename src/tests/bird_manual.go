package main

import (
	"fmt"
	"log"
	"os"

	"github.com/iedon/peerapi-agent/bird"
)

func main() {
	// Open connection to bird socket
	conn, err := bird.Open("/var/run/bird/bird.ctl")
	if err != nil {
		log.Fatalf("[Debug] Failed to open bird socket: %v", err)
	}
	defer bird.Close(conn)

	// Enter restricted mode
	restricted, err := bird.Restrict(conn)
	if err != nil {
		log.Fatalf("[Debug] Failed to enter restricted mode: %v", err)
	}
	if restricted {
		fmt.Println("[Debug] Successfully entered restricted mode.")
	} else {
		fmt.Println("[Debug] Failed to enter restricted mode.")
	}

	// Example command usage
	bird.Write(conn, "show protocols")
	bird.Read(conn, os.Stdout)

	fmt.Println("\n[Debug] Try ospf.")
	bird.Write(conn, "show ospf neighbors")
	bird.Read(conn, os.Stdout)

	fmt.Println("\n[Debug] show pro all")
	bird.Write(conn, "show protocols all")
	bird.Read(conn, os.Stdout)

	fmt.Println("\n[Debug] Ended.")
}
