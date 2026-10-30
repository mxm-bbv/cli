// Package update implements `forge update` (self-update the binary) and
// `forge update images` (re-pull pinned container images). The self-update path
// fails closed: a release is installed only after both its SHA256 checksum and
// its minisign signature verify against forge's pinned public key.
package update

import (
	"crypto/sha256"
	"errors"
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

	self, err := executable()
	if err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		return 1
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		ui.Println(ui.StyleErr.Render("  unsupported architecture: " + arch))
		return 1
	}

	ui.Println(ui.StyleMuted.Render("  fetching latest release…"))
	binary, signed, err := download(releaseBase, "forge-linux-"+arch, allowUnsigned)
	if err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		if errors.Is(err, errUnsigned) {
			ui.Println(ui.StyleErr.Render("  Re-run with --allow-unsigned to trust the checksum alone."))
		}
		return 1
	}
	if signed {
		ui.Println("  " + ui.StyleOK.Render("✓") + "  release signature verified (minisign)")
	} else {
		ui.Println("  " + ui.StyleWarn.Render("⚠") + "  no signature published — proceeding on checksum only (--allow-unsigned)")
	}
	ui.Println("  " + ui.StyleOK.Render("✓") + "  checksum verified")

	if err := replace(self, binary, false); err != nil {
		ui.Println(ui.StyleErr.Render("  " + err.Error()))
		return 1
	}

	ui.Println("  " + ui.StyleOK.Render("✓") + "  installed to " + self)
	if out, err := osexec.Command(self, "--version").Output(); err == nil {
		ui.Println(ui.StyleMuted.Render("  now: " + strings.TrimSpace(string(out))))
	}
	// Where automatic updates are on, the new release writes its own timer.
	_ = osexec.Command(self, "update", "auto", "refresh").Run()
	return 0
}

var errUnsigned = errors.New("checksums.txt.minisig not found — refusing to update unsigned")

// download fetches a release's binary for asset from base (a release's
// download URL) and verifies it: the minisign signature over checksums.txt
// (fail closed unless allowUnsigned), then the binary's SHA256 against it.
func download(base, asset string, allowUnsigned bool) (binary []byte, signed bool, err error) {
	binary, err = httpGet(base + "/" + asset)
	if err != nil {
		return nil, false, fmt.Errorf("download failed: %w", err)
	}
	sums, err := httpGet(base + "/checksums.txt")
	if err != nil {
		return nil, false, fmt.Errorf("could not fetch checksums.txt: %w", err)
	}

	// 1. Signature over checksums.txt (fail closed).
	sig, sigErr := httpGet(base + "/checksums.txt.minisig")
	switch {
	case sigErr == nil:
		if err := verifyMinisign(steps.ReleasePubKey, sig, sums); err != nil {
			return nil, false, err
		}
		signed = true
	case !allowUnsigned:
		return nil, false, errUnsigned
	}

	// 2. SHA256 of the binary against the (now-trusted) checksums list.
	want := checksumFor(sums, asset)
	if want == "" {
		return nil, false, fmt.Errorf("no checksum for %s in checksums.txt", asset)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(binary)); !strings.EqualFold(want, got) {
		return nil, false, fmt.Errorf("checksum mismatch: expected %s, got %s", want, got)
	}
	return binary, signed, nil
}

// replace installs binary over self atomically: written next to it (same
// filesystem), then renamed. keepPrev leaves the binary it replaces at
// self.prev, to go back to.
func replace(self string, binary []byte, keepPrev bool) error {
	dir := filepath.Dir(self)
	tmp, err := os.CreateTemp(dir, ".forge-update-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (need root?): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return fmt.Errorf("write failed: %w", err)
	}
	tmp.Close()
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}
	if keepPrev {
		old, err := os.ReadFile(self)
		if err != nil {
			return err
		}
		if err := os.WriteFile(self+".prev", old, 0o755); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, self); err != nil {
		return fmt.Errorf("could not replace %s: %w", self, err)
	}
	return nil
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
