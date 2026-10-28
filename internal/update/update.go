// Package update implements `forge update` (self-update the binary) and
// `forge update images` (re-pull pinned container images). The self-update path
// fails closed: a release is installed only after both its SHA256 checksum and
// its minisign signature verify against forge's pinned public key.
package update

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mxm-bbv/cli/internal/steps"
	"github.com/mxm-bbv/cli/internal/ui"
)

const releaseBase = "https://github.com/mxm-bbv/cli/releases/latest/download"

// Images re-pulls pinned images and recreates drifted agent/watchtower
// containers. Deliberate, not automatic — the counterpart to monitor-only
// Watchtower.
func Images() int {
	agent, wt := steps.PinnedImages()
	ui.Println(ui.StyleTitle.Render("  forge update images"))
	ui.Println(ui.StyleMuted.Render("  pinned: " + agent + ", " + wt))
	ui.Println()

	done, err := steps.UpdateImages()
	if err != nil {
		ui.Println(ui.StyleErr.Render("  update failed: " + err.Error()))
		return 1
	}
	if len(done) == 0 {
		ui.Println(ui.StyleOK.Render("  ✓  containers already on the pinned images — nothing to do"))
		return 0
	}
	for _, d := range done {
		ui.Println("  " + ui.StyleOK.Render("✓") + "  recreated " + d)
	}
	return 0
}

// SelfUpdate downloads the latest release binary for this architecture,
// verifies its signature + checksum, and atomically replaces the running
// binary. allowUnsigned permits install when no signature is published yet
// (transition only); the checksum is still enforced.
func SelfUpdate(allowUnsigned bool) int {
	ui.Println(ui.StyleTitle.Render("  forge update"))
	ui.Println()

	self, err := os.Executable()
	if err != nil {
		ui.Println(ui.StyleErr.Render("  cannot locate the running binary: " + err.Error()))
		return 1
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		ui.Println(ui.StyleErr.Render("  unsupported architecture: " + arch))
		return 1
	}
	asset := "forge-linux-" + arch

	ui.Println(ui.StyleMuted.Render("  fetching latest release…"))
	binary, err := httpGet(releaseBase + "/" + asset)
	if err != nil {
		ui.Println(ui.StyleErr.Render("  download failed: " + err.Error()))
		return 1
	}
	sums, err := httpGet(releaseBase + "/checksums.txt")
	if err != nil {
		ui.Println(ui.StyleErr.Render("  could not fetch checksums.txt: " + err.Error()))
		return 1
	}

	// 1. Signature over checksums.txt (fail closed).
	sig, sigErr := httpGet(releaseBase + "/checksums.txt.minisig")
	switch {
	case sigErr == nil:
		if err := verifyMinisign(steps.ReleasePubKey, sig, sums); err != nil {
			ui.Println(ui.StyleErr.Render("  " + err.Error()))
			return 1
		}
		ui.Println("  " + ui.StyleOK.Render("✓") + "  release signature verified (minisign)")
	case allowUnsigned:
		ui.Println("  " + ui.StyleWarn.Render("⚠") + "  no signature published — proceeding on checksum only (--allow-unsigned)")
	default:
		ui.Println(ui.StyleErr.Render("  checksums.txt.minisig not found — refusing to update unsigned."))
		ui.Println(ui.StyleErr.Render("  Re-run with --allow-unsigned to trust the checksum alone."))
		return 1
	}

	// 2. SHA256 of the binary against the (now-trusted) checksums list.
	want := checksumFor(sums, asset)
	if want == "" {
		ui.Println(ui.StyleErr.Render("  no checksum for " + asset + " in checksums.txt — aborting"))
		return 1
	}
	got := fmt.Sprintf("%x", sha256.Sum256(binary))
	if !strings.EqualFold(want, got) {
		ui.Println(ui.StyleErr.Render("  checksum MISMATCH — aborting"))
		ui.Println(ui.StyleMuted.Render("    expected: " + want))
		ui.Println(ui.StyleMuted.Render("    actual:   " + got))
		return 1
	}
	ui.Println("  " + ui.StyleOK.Render("✓") + "  checksum verified (sha256:" + got[:16] + "…)")

	// 3. Atomic replace: write next to the target (same filesystem), then rename.
	dir := filepath.Dir(self)
	tmp, err := os.CreateTemp(dir, ".forge-update-*")
	if err != nil {
		ui.Println(ui.StyleErr.Render("  cannot write to " + dir + " (need root?): " + err.Error()))
		return 1
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		ui.Println(ui.StyleErr.Render("  write failed: " + err.Error()))
		return 1
	}
	tmp.Close()
	if err := os.Chmod(tmpName, 0o755); err != nil {
		ui.Println(ui.StyleErr.Render("  chmod failed: " + err.Error()))
		return 1
	}
	if err := os.Rename(tmpName, self); err != nil {
		ui.Println(ui.StyleErr.Render("  could not replace " + self + ": " + err.Error()))
		return 1
	}

	ui.Println("  " + ui.StyleOK.Render("✓") + "  installed to " + self)
	if out, err := osexec.Command(self, "--version").Output(); err == nil {
		ui.Println(ui.StyleMuted.Render("  now: " + strings.TrimSpace(string(out))))
	}
	return 0
}

// checksumFor finds the hash for an asset in a `sha256  name` list, tolerating
// the leading `*` that some tools add to the filename.
func checksumFor(sums []byte, asset string) string {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset {
			return fields[0]
		}
	}
	return ""
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20)) // 200 MiB cap
}
