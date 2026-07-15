package system

import (
	"net"
	"os"
	"runtime"
	"strings"
)

// IsRoot reports whether the process runs as uid 0.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// OSRelease holds the parsed fields of /etc/os-release we care about.
type OSRelease struct {
	ID       string // e.g. "ubuntu", "debian"
	IDLike   string
	Codename string // e.g. "noble", "bookworm"
	Pretty   string
}

// ReadOSRelease parses /etc/os-release.
func ReadOSRelease() OSRelease {
	var r OSRelease
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return r
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(val, `"`)
		switch key {
		case "ID":
			r.ID = val
		case "ID_LIKE":
			r.IDLike = val
		case "VERSION_CODENAME":
			r.Codename = val
		case "PRETTY_NAME":
			r.Pretty = val
		}
	}
	return r
}

// IsDebianLike reports whether the host is Ubuntu/Debian (apt-based).
func (r OSRelease) IsDebianLike() bool {
	if r.ID == "ubuntu" || r.ID == "debian" {
		return true
	}
	return strings.Contains(r.IDLike, "debian")
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
