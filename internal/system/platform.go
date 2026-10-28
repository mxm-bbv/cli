package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OSRelease holds the parsed fields of os-release(5) we care about.
type OSRelease struct {
	ID             string // e.g. "ubuntu", "debian", "linuxmint"
	IDLike         string // e.g. "ubuntu debian"
	VersionID      string // e.g. "24.04", "12"
	Codename       string // VERSION_CODENAME, e.g. "noble", "bookworm"
	UbuntuCodename string // set by Ubuntu and its derivatives (Mint, Pop!_OS, Zorin…)
	DebianCodename string // set by some Debian derivatives (LMDE…)
	Pretty         string
}

// ReadOSRelease parses /etc/os-release, falling back to /usr/lib/os-release
// (the spec allows either; minimal images sometimes only ship the latter).
func ReadOSRelease() OSRelease {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, err := os.ReadFile(p); err == nil {
			return ParseOSRelease(string(data))
		}
	}
	return OSRelease{}
}

// ParseOSRelease parses os-release content: KEY=value lines, values optionally
// single- or double-quoted, comments and blank lines ignored.
func ParseOSRelease(data string) OSRelease {
	var r OSRelease
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		switch key {
		case "ID":
			r.ID = strings.ToLower(val)
		case "ID_LIKE":
			r.IDLike = strings.ToLower(val)
		case "VERSION_ID":
			r.VersionID = val
		case "VERSION_CODENAME":
			r.Codename = strings.ToLower(val)
		case "UBUNTU_CODENAME":
			r.UbuntuCodename = strings.ToLower(val)
		case "DEBIAN_CODENAME":
			r.DebianCodename = strings.ToLower(val)
		case "PRETTY_NAME":
			r.Pretty = val
		}
	}
	return r
}

// IsDebianLike reports whether the host is Ubuntu/Debian or a derivative
// (apt-based).
func (r OSRelease) IsDebianLike() bool {
	if r.ID == "ubuntu" || r.ID == "debian" {
		return true
	}
	for _, like := range strings.Fields(r.IDLike) {
		if like == "debian" || like == "ubuntu" {
			return true
		}
	}
	return false
}

// Name returns a human-readable name for messages.
func (r OSRelease) Name() string {
	if r.Pretty != "" {
		return r.Pretty
	}
	if r.ID != "" {
		return strings.TrimSpace(r.ID + " " + r.VersionID)
	}
	return "unknown Linux"
}

// Support grades how well forge knows a release.
type Support int

const (
	// SupportTested: a current Ubuntu LTS or Debian stable that forge is
	// tested against.
	SupportTested Support = iota
	// SupportLegacy: an older release that still works in principle but is at
	// or past end of standard support — upstream repos may drop it any time.
	SupportLegacy
	// SupportUnknown: an interim, testing or brand-new release forge has no
	// data about. Provisioning continues; repo availability is checked live.
	SupportUnknown
)

// Upstream releases forge knows. Docker and Tailscale publish their apt repos
// per (family, codename), so this is also the list of repo suites we expect to
// exist. Keep it short and current: anything not listed is "unknown", not
// rejected.
var (
	ubuntuReleases = map[string]struct {
		version string
		support Support
	}{
		"bionic":   {"18.04", SupportLegacy},
		"focal":    {"20.04", SupportLegacy},
		"jammy":    {"22.04", SupportTested},
		"noble":    {"24.04", SupportTested},
		"resolute": {"26.04", SupportTested},
	}
	debianReleases = map[string]struct {
		version string
		support Support
	}{
		"buster":   {"10", SupportLegacy},
		"bullseye": {"11", SupportLegacy},
		"bookworm": {"12", SupportTested},
		"trixie":   {"13", SupportTested},
	}
)

// Platform is the host mapped onto the upstream release that third-party apt
// repos (Docker, Tailscale) are keyed by. Derivatives such as Linux Mint or
// Pop!_OS have their own ID and codename, which those repos don't know — they
// must use the Ubuntu/Debian release they are built on.
type Platform struct {
	OS         OSRelease
	Family     string // "ubuntu" or "debian" — the repo path component
	Codename   string // upstream codename, e.g. "noble", "bookworm"
	Version    string // upstream version when known, e.g. "24.04"
	Derivative bool   // Family/Codename were mapped from a derivative
	Support    Support
}

// String renders e.g. "Ubuntu 24.04 (noble)" or "Linux Mint 22 → ubuntu noble".
func (p Platform) String() string {
	up := p.Family + " " + p.Codename
	if p.Version != "" {
		up = p.Family + " " + p.Version + " (" + p.Codename + ")"
	}
	if p.Derivative {
		return p.OS.Name() + " → " + up
	}
	return up
}

// DetectPlatform maps an os-release onto an upstream Ubuntu/Debian release.
// It errors only when the host is not apt-based or cannot be mapped at all.
func DetectPlatform(r OSRelease) (Platform, error) {
	p := Platform{OS: r}
	switch {
	case r.ID == "ubuntu":
		p.Family, p.Codename = "ubuntu", firstNonEmpty(r.Codename, r.UbuntuCodename)
	case r.ID == "debian":
		p.Family, p.Codename = "debian", r.Codename
	case r.UbuntuCodename != "":
		// Linux Mint, Pop!_OS, Zorin, elementary, KDE neon…
		p.Family, p.Codename, p.Derivative = "ubuntu", r.UbuntuCodename, true
	case r.DebianCodename != "":
		// LMDE and other derivatives that declare their Debian base.
		p.Family, p.Codename, p.Derivative = "debian", r.DebianCodename, true
	case hasLike(r, "ubuntu") && known(ubuntuReleases, r.Codename):
		p.Family, p.Codename, p.Derivative = "ubuntu", r.Codename, true
	case hasLike(r, "debian") && known(debianReleases, r.Codename):
		// e.g. Raspberry Pi OS, which reuses Debian's codenames.
		p.Family, p.Codename, p.Derivative = "debian", r.Codename, true
	case r.IsDebianLike():
		return p, fmt.Errorf("%s is Debian-based but forge cannot tell which Ubuntu/Debian release it is built on "+
			"(no UBUNTU_CODENAME/DEBIAN_CODENAME in /etc/os-release)", r.Name())
	default:
		return p, fmt.Errorf("unsupported OS %q — forge supports Ubuntu, Debian and their derivatives", r.Name())
	}
	if p.Codename == "" {
		return p, fmt.Errorf("%s: /etc/os-release has no release codename (rolling/testing release?)", r.Name())
	}

	table := debianReleases
	if p.Family == "ubuntu" {
		table = ubuntuReleases
	}
	if rel, ok := table[p.Codename]; ok {
		p.Version, p.Support = rel.version, rel.support
	} else {
		p.Support = SupportUnknown
	}
	return p, nil
}

// SupportNote returns a one-line warning for non-tested releases ("" when
// tested).
func (p Platform) SupportNote() string {
	switch p.Support {
	case SupportLegacy:
		return p.String() + " is past (or near) end of standard support — it may work, but upgrade to a current LTS/stable release"
	case SupportUnknown:
		return p.String() + " is not a release forge is tested on (interim/testing/new) — continuing; upstream repos are checked live"
	}
	return ""
}

func hasLike(r OSRelease, family string) bool {
	for _, like := range strings.Fields(r.IDLike) {
		if like == family {
			return true
		}
	}
	return false
}

func known[V any](table map[string]V, codename string) bool {
	_, ok := table[codename]
	return ok
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// HasSystemd reports whether systemd is the running init (sd_booted(3)). forge
// manages services, timers and sshd through systemctl, so it is required.
func HasSystemd() bool {
	return FileExists("/run/systemd/system")
}

// ContainerType returns the container technology the host runs in ("lxc",
// "openvz", "docker", "wsl", …) or "" on a VM / bare metal. Cheap VPSes are
// often LXC/OpenVZ containers, where swap and some kernel features are
// unavailable.
func ContainerType() string {
	out, err := exec.Command("systemd-detect-virt", "--container").Output()
	v := strings.TrimSpace(string(out))
	if err != nil || v == "none" {
		return ""
	}
	return v
}
