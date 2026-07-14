// Package audit implements `forge audit`: a read-only sweep of a host for the
// indicators of compromise from a real proxyjacking/rootkit incident (public
// Portainer Agent on :9001) plus the risky Docker/network configurations that
// enabled it. It changes nothing; it only reports.
package audit

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mxm-bbv/cli/internal/ui"
)

type severity int

const (
	sevOK severity = iota
	sevInfo
	sevWarn
	sevCrit
)

type report struct {
	warns, crits int
	// compromised is set only by the IOC checks (rootkit, malware artifacts,
	// persistence) — a critical *exposure* is urgent but not evidence of a
	// breach, and the closing advice must not confuse the two.
	compromised bool
}

func (r *report) line(sev severity, msg string) {
	switch sev {
	case sevOK:
		fmt.Println("  " + ui.StyleOK.Render("✓") + "  " + msg)
	case sevInfo:
		fmt.Println("  " + ui.StyleMuted.Render("·") + "  " + ui.StyleMuted.Render(msg))
	case sevWarn:
		r.warns++
		fmt.Println("  " + ui.StyleWarn.Render("⚠") + "  " + msg)
	case sevCrit:
		r.crits++
		fmt.Println("  " + ui.StyleErr.Render("✗") + "  " + ui.StyleErr.Render(msg))
	}
}

// Run executes all checks and returns the process exit code:
// 0 clean, 1 warnings only, 2 critical findings.
func Run() int {
	fmt.Println(ui.StyleTitle.Render("  forge audit — host compromise & exposure check"))
	fmt.Println()
	if os.Geteuid() != 0 {
		fmt.Println(ui.StyleWarn.Render("  Not running as root — some checks (docker, iptables, cron) may be incomplete.\n"))
	}

	r := &report{}
	checkRootkit(r)
	checkIOCPaths(r)
	checkPersistence(r)
	checkContainers(r)
	checkFirewall(r)
	checkAuthorizedKeys(r)

	fmt.Println()
	switch {
	case r.crits > 0:
		fmt.Println(ui.StyleErr.Render(fmt.Sprintf("  %d critical finding(s), %d warning(s).", r.crits, r.warns)))
		if r.compromised {
			fmt.Println(ui.StyleErr.Render("  Malware indicators found — treat this as an active compromise: snapshot"))
			fmt.Println(ui.StyleErr.Render("  for evidence, isolate the host and plan a clean reinstall — do not just"))
			fmt.Println(ui.StyleErr.Render("  delete the files."))
		} else {
			fmt.Println(ui.StyleErr.Render("  Critical exposure — an attacker who finds it gains root-equivalent access."))
			fmt.Println(ui.StyleErr.Render("  Fix it now (rerunning forge fixes its own components; compose files are yours)."))
		}
		return 2
	case r.warns > 0:
		fmt.Println(ui.StyleWarn.Render(fmt.Sprintf("  %d warning(s) — review and fix (rerunning `forge` fixes most of them).", r.warns)))
		return 1
	default:
		fmt.Println(ui.StyleOK.Render("  No indicators of compromise or risky exposure found."))
		return 0
	}
}

// --- rootkit & IOC checks (from the incident report) ---

func checkRootkit(r *report) {
	data, err := os.ReadFile("/etc/ld.so.preload")
	switch {
	case err == nil && strings.TrimSpace(string(data)) != "":
		r.compromised = true
		r.line(sevCrit, "/etc/ld.so.preload is non-empty — LD_PRELOAD rootkit indicator: "+strings.TrimSpace(string(data)))
		r.line(sevInfo, "note: ls/ps/ss output on this host can no longer be trusted; verify from a rescue system")
	case err == nil:
		r.line(sevWarn, "/etc/ld.so.preload exists (empty) — unusual; verify why")
	default:
		r.line(sevOK, "no /etc/ld.so.preload (LD_PRELOAD rootkit indicator absent)")
	}
}

// iocPaths are the exact artifacts from the July 2026 incident (perfcc /
// proxyjacking toolkit). Their presence means active compromise.
var iocPaths = []string{
	"/lib/libgcwrap.so",
	"/usr/bin/perfcc",
	"/root/.config/cron/perfcc",
	"/etc/cron.d/perfclean",
	"/etc/cron.daily/perfclean",
	"/var/.r.rpk",
	"/var/.e.efm",
	"/tmp/.t.trf",
	"/usr/bin/gnufalseusbhid-dump",
}

func checkIOCPaths(r *report) {
	found := false
	for _, p := range iocPaths {
		if _, err := os.Stat(p); err == nil {
			found = true
			r.compromised = true
			r.line(sevCrit, "known-malware artifact present: "+p)
		}
	}
	if !found {
		r.line(sevOK, "no known malware artifacts (perfcc / libgcwrap / proxyjacking runtimes)")
	}
}

// checkPersistence sweeps cron and systemd for names tied to the incident's
// malware families and traffic-monetisation clients.
func checkPersistence(r *report) {
	pattern := "perfcc|perfclean|libgcwrap|earnfm|repocket|traffmonetizer|gnufalseusbhid|kubeupd"
	dirs := []string{
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
		"/etc/cron.monthly", "/var/spool/cron", "/etc/systemd/system", "/usr/lib/systemd/system",
	}
	out, _ := exec.Command("grep", append([]string{"-rliE", pattern}, dirs...)...).Output()
	hits := strings.Fields(strings.TrimSpace(string(out)))
	if len(hits) == 0 {
		r.line(sevOK, "cron/systemd contain no known malware persistence names")
		return
	}
	for _, h := range hits {
		r.compromised = true
		r.line(sevCrit, "malware persistence reference in "+h)
	}
}

// --- exposure checks (the configuration that made the incident possible) ---

func checkContainers(r *report) {
	out, err := exec.Command("docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}").Output()
	if err != nil {
		r.line(sevInfo, "docker not available — container checks skipped")
		return
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		r.line(sevOK, "no running containers")
		return
	}
	publicOK := true
	for _, l := range lines {
		f := strings.SplitN(l, "\t", 4)
		if len(f) < 4 {
			continue
		}
		id, name, image, ports := f[0], f[1], f[2], f[3]

		// Public port exposure. 80/443 are expected for a web host.
		if strings.Contains(ports, "0.0.0.0:") || strings.Contains(ports, ":::") {
			for _, p := range strings.Split(ports, ",") {
				p = strings.TrimSpace(p)
				if !strings.Contains(p, "0.0.0.0:") && !strings.Contains(p, ":::") {
					continue
				}
				switch {
				case strings.Contains(p, ":9001->"):
					publicOK = false
					r.line(sevCrit, name+": Portainer Agent port 9001 published to the internet — root-equivalent if unauthenticated")
				case strings.Contains(p, ":80->") || strings.Contains(p, ":443->"):
					// expected
				default:
					publicOK = false
					r.line(sevWarn, name+": port published to the internet: "+p+" (docker bypasses UFW — is this intended?)")
				}
			}
		}

		// Floating tags.
		if !strings.Contains(image, ":") ||
			strings.HasSuffix(image, ":latest") || strings.HasSuffix(image, ":lts") || strings.HasSuffix(image, ":stable") {
			r.line(sevWarn, name+": floating image tag ("+image+") — pin a version so a repushed tag can't swap the image")
		}

		// Dangerous privileges / mounts.
		insp, err := exec.Command("docker", "inspect", id, "--format",
			`{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{range .HostConfig.Binds}}{{.}} {{end}}`).Output()
		if err != nil {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(string(insp)), "|", 3)
		if len(parts) == 3 {
			if parts[0] == "true" {
				r.line(sevCrit, name+": runs --privileged — full host access")
			}
			if parts[1] == "host" {
				r.line(sevWarn, name+": uses --pid=host")
			}
			for _, b := range strings.Fields(parts[2]) {
				src := strings.SplitN(b, ":", 2)[0]
				switch src {
				case "/":
					r.line(sevCrit, name+": mounts / (entire host filesystem) — root-equivalent")
				case "/var/run/docker.sock":
					r.line(sevInfo, name+": holds the docker socket (root-equivalent by design — keep this list short)")
				}
			}
		}

		// Watchtower doing silent auto-updates.
		if strings.Contains(image, "watchtower") {
			args, _ := exec.Command("docker", "inspect", id, "--format", `{{range .Args}}{{.}} {{end}}`).Output()
			if !strings.Contains(string(args), "--monitor-only") {
				r.line(sevWarn, name+": Watchtower auto-replaces containers (supply-chain risk) — switch to --monitor-only")
			}
		}
	}
	if publicOK {
		r.line(sevOK, "no unexpected container ports published to the internet")
	}
}

func checkFirewall(r *report) {
	out, err := exec.Command("ufw", "status").Output()
	if err != nil || !strings.Contains(string(out), "Status: active") {
		r.line(sevWarn, "UFW is not active")
	} else {
		r.line(sevOK, "UFW is active")
	}

	rules, err := exec.Command("iptables", "-S", "DOCKER-USER").Output()
	if err != nil {
		r.line(sevInfo, "DOCKER-USER chain not inspectable (no docker/iptables?)")
		return
	}
	if strings.Contains(string(rules), "DROP") {
		r.line(sevOK, "DOCKER-USER filters container traffic (docker cannot bypass the firewall)")
	} else {
		r.line(sevWarn, "DOCKER-USER has no DROP policy — published container ports bypass UFW entirely (rerun forge with the firewall enabled)")
	}
}

func checkAuthorizedKeys(r *report) {
	paths, _ := exec.Command("sh", "-c", "ls /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null").Output()
	for _, p := range strings.Fields(strings.TrimSpace(string(paths))) {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		n := 0
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				n++
				comment := ""
				if f := strings.Fields(l); len(f) >= 3 {
					comment = " (" + f[len(f)-1] + ")"
				}
				r.line(sevInfo, p+": key"+comment+" — verify you recognise it")
			}
		}
		if n == 0 {
			r.line(sevInfo, p+": empty")
		}
	}
}
