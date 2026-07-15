// Package lint implements `forge lint <docker-compose.yml>`: a static check of
// a Compose file for the risky settings that turned a single misconfig into a
// full host compromise (public root-equivalent ports, host mounts, floating
// tags). It reads the file only; it never runs docker.
package lint

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/mxm-bbv/cli/internal/ui"
)

// composeFile is the subset of the Compose schema we inspect.
type composeFile struct {
	Services map[string]service `yaml:"services"`
}

type service struct {
	Image       string   `yaml:"image"`
	Privileged  bool     `yaml:"privileged"`
	NetworkMode string   `yaml:"network_mode"`
	PidMode     string   `yaml:"pid"`
	Restart     string   `yaml:"restart"`
	Ports       []any    `yaml:"ports"` // strings or long-form maps
	Volumes     []any    `yaml:"volumes"`
	CapAdd      []string `yaml:"cap_add"`
}

type finding struct {
	crit bool
	svc  string
	msg  string
}

// Run lints the given compose file and returns a process exit code:
// 0 clean, 1 warnings only, 2 critical findings.
func Run(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println(ui.StyleErr.Render("  cannot read " + path + ": " + err.Error()))
		return 2
	}
	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		fmt.Println(ui.StyleErr.Render("  " + path + " is not valid YAML: " + err.Error()))
		return 2
	}

	fmt.Println(ui.StyleTitle.Render("  forge lint — " + path))
	fmt.Println()
	if len(cf.Services) == 0 {
		fmt.Println(ui.StyleWarn.Render("  no services found — is this a Compose file?"))
		return 1
	}

	var fs []finding
	for name, svc := range cf.Services {
		fs = append(fs, lintService(name, svc)...)
	}

	if len(fs) == 0 {
		fmt.Println(ui.StyleOK.Render("  ✓  no risky settings found"))
		return 0
	}

	crits, warns := 0, 0
	for _, f := range fs {
		if f.crit {
			crits++
			fmt.Println("  " + ui.StyleErr.Render("✗") + "  " + ui.StyleKey.Render(f.svc) + ": " + ui.StyleErr.Render(f.msg))
		} else {
			warns++
			fmt.Println("  " + ui.StyleWarn.Render("⚠") + "  " + ui.StyleKey.Render(f.svc) + ": " + f.msg)
		}
	}
	fmt.Println()
	switch {
	case crits > 0:
		fmt.Println(ui.StyleErr.Render(fmt.Sprintf("  %d critical, %d warning(s) — fix before deploying.", crits, warns)))
		return 2
	default:
		fmt.Println(ui.StyleWarn.Render(fmt.Sprintf("  %d warning(s) — review before deploying.", warns)))
		return 1
	}
}

// publicPortRe matches a Compose short-form port that binds to all interfaces:
// "8080:80", "0.0.0.0:8080:80" — but NOT "127.0.0.1:8080:80" or "127.0.0.1:5432:5432".
var publicPortRe = regexp.MustCompile(`^(?:0\.0\.0\.0:)?\d+:\d+(?:/\w+)?$`)

func lintService(name string, s service) []finding {
	var fs []finding
	add := func(crit bool, msg string) { fs = append(fs, finding{crit, name, msg}) }

	// Image tag hygiene.
	switch {
	case s.Image == "":
		// built locally via `build:` — nothing to pin here.
	case !strings.Contains(imageRef(s.Image), ":"):
		add(false, "image '"+s.Image+"' has no tag (defaults to :latest) — pin a version")
	default:
		tag := s.Image[strings.LastIndex(s.Image, ":")+1:]
		if tag == "latest" || tag == "lts" || tag == "stable" || tag == "main" {
			add(false, "image '"+s.Image+"' uses a floating tag ':"+tag+"' — a repushed tag can swap the image; pin a version or @sha256 digest")
		}
	}

	// Privilege / namespace escapes.
	if s.Privileged {
		add(true, "privileged: true — full host access, drop it")
	}
	if s.NetworkMode == "host" {
		add(false, "network_mode: host — bypasses docker's network isolation and any port firewall")
	}
	if s.PidMode == "host" {
		add(false, "pid: host — can see and signal every host process")
	}
	for _, c := range s.CapAdd {
		if strings.EqualFold(c, "SYS_ADMIN") || strings.EqualFold(c, "ALL") {
			add(true, "cap_add: "+c+" — near-root capability, remove it")
		}
	}

	// Port exposure.
	for _, p := range s.Ports {
		ps := portString(p)
		if ps == "" {
			continue
		}
		if strings.HasPrefix(ps, "127.0.0.1:") || strings.HasPrefix(ps, "::1:") {
			continue // loopback-only is fine
		}
		if !publicPortRe.MatchString(ps) {
			continue // named ranges / already-scoped forms we don't judge
		}
		cport := ps[strings.LastIndex(ps, ":")+1:]
		switch {
		case strings.HasPrefix(cport, "9001"):
			add(true, "publishes Portainer agent port ("+ps+") to all interfaces — root-equivalent; bind to a tailnet/loopback IP")
		case strings.HasPrefix(cport, "80") && (cport == "80" || cport == "80/tcp"),
			strings.HasPrefix(cport, "443") && (cport == "443" || cport == "443/tcp"):
			// expected public web ports
		default:
			add(false, "publishes '"+ps+"' to all interfaces (docker bypasses UFW) — bind to 127.0.0.1 or a tailnet IP if it's not meant to be public")
		}
	}

	// Host mounts.
	for _, v := range s.Volumes {
		src := volumeSource(v)
		switch {
		case src == "/":
			add(true, "mounts the entire host filesystem ('/') — root-equivalent, remove it")
		case src == "/var/run/docker.sock" || src == "/run/docker.sock":
			add(false, "mounts the docker socket — root-equivalent; only for trusted management containers, keep it read-only if possible")
		case src == "/etc" || src == "/root" || src == "/usr":
			add(false, "mounts a sensitive host path ('"+src+"') — scope it down")
		}
	}

	// Availability: production services should come back after a reboot.
	if s.Restart == "" && s.NetworkMode != "host" {
		add(false, "no restart policy — add 'restart: unless-stopped' so it survives reboots")
	}
	return fs
}

// imageRef strips a registry host:port prefix so the ':' tag check isn't fooled
// by "registry.example.com:5000/img".
func imageRef(img string) string {
	if i := strings.LastIndex(img, "/"); i >= 0 {
		return img[i:]
	}
	return img
}

// portString renders a Compose port entry (short string or long-form map).
func portString(p any) string {
	switch v := p.(type) {
	case string:
		return v
	case int:
		return fmt.Sprintf("%d", v)
	case map[string]any:
		host := anyToString(v["published"])
		target := anyToString(v["target"])
		hostIP := anyToString(v["host_ip"])
		if target == "" {
			return ""
		}
		if hostIP != "" {
			return hostIP + ":" + host + ":" + target
		}
		if host != "" {
			return host + ":" + target
		}
		return target
	}
	return ""
}

// volumeSource extracts the host side of a Compose volume entry.
func volumeSource(v any) string {
	switch e := v.(type) {
	case string:
		parts := strings.SplitN(e, ":", 2)
		return strings.TrimSpace(parts[0])
	case map[string]any:
		if anyToString(e["type"]) == "bind" {
			return anyToString(e["source"])
		}
	}
	return ""
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
