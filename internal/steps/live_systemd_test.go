package steps

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// TestLiveSSHPortMoveSystemd moves sshd from 22 to 2222 for real — firewall
// transition, sshd restart (socket-activated or not), banner probe, old port
// closed — inside a disposable container that boots systemd as PID 1:
//
//	docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
//	  -v $PWD/steps.test:/steps.test:ro <image-with-systemd+openssh+ufw> /sbin/init
//	docker exec -e FORGE_LIVE_SYSTEMD=1 <ctr> /steps.test -test.run LiveSSHPortMove -test.v
func TestLiveSSHPortMoveSystemd(t *testing.T) {
	if os.Getenv("FORGE_LIVE_SYSTEMD") != "1" || os.Geteuid() != 0 ||
		!system.FileExists("/.dockerenv") || !system.HasSystemd() {
		t.Skip("set FORGE_LIVE_SYSTEMD=1 and run as root in a disposable container booted with systemd")
	}
	system.DryRun = false
	system.CommandLog = nil

	cfg := config.Default()
	cfg.SSHPort = 2222
	cfg.EnableFirewall = true
	cfg.InstallPortainer = false
	c := &Context{Cfg: cfg, AdminKeyInstalled: true}

	if err := sshBanner("127.0.0.1:22"); err != nil {
		t.Fatalf("precondition: sshd must answer on 22: %v", err)
	}
	socket := sshSocketActivated()
	t.Logf("socket-activated sshd: %v", socket)

	if err := firewallStep().Run(c); err != nil {
		t.Fatalf("firewall: %v", err)
	}
	ufw, _ := system.Output("ufw", "status")
	if !strings.Contains(ufw, "22/tcp") || !strings.Contains(ufw, "2222/tcp") {
		t.Fatalf("both the old and new SSH ports must be open during the move:\n%s", ufw)
	}

	if err := sshHardeningStep().Run(c); err != nil {
		t.Fatalf("hardening: %v\n--- log ---\n%s", err, strings.Join(system.CommandLog, "\n"))
	}
	if err := sshBanner("127.0.0.1:2222"); err != nil {
		t.Errorf("sshd must answer on 2222 over IPv4: %v", err)
	}
	if err := sshBanner("[::1]:2222"); err != nil {
		t.Logf("IPv6 loopback on 2222: %v (fine if the container has no IPv6)", err)
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second); err == nil {
		conn.Close()
		t.Error("nothing should listen on 22 any more")
	}
	ufw, _ = system.Output("ufw", "status")
	if strings.Contains(ufw, "22/tcp ") && !strings.Contains(ufw, "2222/tcp") {
		t.Errorf("unexpected UFW state:\n%s", ufw)
	}
	for _, l := range strings.Split(ufw, "\n") {
		if strings.HasPrefix(l, "22/tcp") {
			t.Errorf("old port rule left behind: %q", l)
		}
	}
	t.Logf("UFW after move:\n%s", ufw)
	t.Logf("notes: %s", strings.Join(c.Notes, " | "))

	// Rollback: occupy 2223 and ask for it — forge must refuse before touching
	// sshd, and sshd must still answer on 2222.
	ln, err := net.Listen("tcp", ":2223")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c.Cfg.SSHPort = 2223
	if err := sshHardeningStep().Run(c); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("expected a port-in-use refusal, got %v", err)
	}
	if err := sshBanner("127.0.0.1:2222"); err != nil {
		t.Errorf("sshd must be untouched after the refusal: %v", err)
	}
	out, _ := system.Output("sshd", "-T")
	t.Logf("effective: %s", sshdSummary(out))
}

// sshdSummary keeps the security-relevant lines of `sshd -T`.
func sshdSummary(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		for _, k := range []string{"port ", "listenaddress ", "passwordauthentication ", "permitrootlogin ", "allowusers "} {
			if strings.HasPrefix(l, k) {
				keep = append(keep, l)
			}
		}
	}
	return strings.Join(keep, "; ")
}
