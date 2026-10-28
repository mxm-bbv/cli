package system

import (
	"net"
	"os"
	"runtime"
)

// IsRoot reports whether the process runs as uid 0.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// Arch returns the Docker-style architecture string.
func Arch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

// Hostname returns the host's name, best-effort.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "server"
	}
	return h
}

// PrimaryIP returns the outbound IP address of the host, best-effort.
func PrimaryIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
