package bird

// Some code taken from https://github.com/xddxdd/bird-lg-go/blob/master/proxy/bird.go

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
)

type BirdConn net.Conn

// isNumeric checks if a byte represents a numeric character.
func isNumeric(b byte) bool {
	return b >= byte('0') && b <= byte('9')
}

// Reads output from a bird socket, removes preceding status numbers,
// and writes the result to the output buffer.
func Read(birdConn BirdConn, outputBuffer io.Writer) {
	const (
		StatusSize  = 4
		NewlineChar = '\n'
	)
	reader := bufio.NewReader(birdConn)

	for {
		line, err := reader.ReadBytes(NewlineChar)
		if err != nil {
			// EOF or error
			break
		}

		lineLen := len(line)

		// Check if the line starts with a status number
		if lineLen > StatusSize && isNumeric(line[0]) && isNumeric(line[1]) && isNumeric(line[2]) && isNumeric(line[3]) {
			// Ensure there's content after the status number
			if outputBuffer != nil && lineLen > StatusSize+1 {
				outputBuffer.Write(line[StatusSize+1:])
			}
			// Status indicates no more lines could be read
			if line[0] == byte('0') || line[0] == byte('8') || line[0] == byte('9') {
				break
			}
		} else if outputBuffer != nil {
			// Removes starting space and output
			outputBuffer.Write(line[1:])
		}
	}
}

// Write writes a command string to the bird socket with a newline appended.
func Write(birdConn BirdConn, s string) error {
	if _, err := birdConn.Write([]byte(s + "\n")); err != nil {
		return fmt.Errorf("failed to write command: %w", err)
	}
	return nil
}

// Open establishes a connection to the bird socket and removes banner/startup messages.
func Open(unixPath string) (BirdConn, error) {
	conn, err := net.Dial("unix", unixPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bird socket: %w", err)
	}

	// Remove banner/startup messages by reading the first line
	Read(conn, nil)

	return conn, nil
}

// Close closes the bird socket connection.
func Close(birdConn BirdConn) error {
	if err := birdConn.Close(); err != nil {
		return fmt.Errorf("failed to close bird socket: %w", err)
	}
	return nil
}

// Restrict sends the "restrict" command to the bird socket and checks for confirmation.
func Restrict(birdConn BirdConn) (bool, error) {
	if err := Write(birdConn, "restrict"); err != nil {
		return false, fmt.Errorf("failed to send restrict command: %w", err)
	}

	var reply bytes.Buffer
	Read(birdConn, &reply)

	return strings.Contains(reply.String(), "Access restricted"), nil
}
