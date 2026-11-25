package update

// A release a program brought: deploy.me keeps which forge its servers run and
// carries the binary over its own ssh connection, so the server never asks
// GitHub (`forge run update` with file, sha256 and version). No signature: the
// program signs in as a user forge already lets run every module as root, so
// one would guard nothing more. What it checks is that the file is what the
// program meant to send.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
)

var (
	sumPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	setAuto    = SetAuto
)

// FromFile installs the binary at path as this forge when its SHA256 is sum.
// The file has to be a plain file of owner (the user sudo ran this for) or
// root, and it's read once: the bytes checked are the bytes installed. The new
// forge has to say tag and answer modules --json, or the one it replaced goes
// back. Automatic updates go off with it, since the timer would put GitHub's
// latest over the version the program keeps. The file stays where it is: it's
// the program's to remove, never a path root deletes on someone's word.
func FromFile(path, sum, tag string, owner int) (notes []string, err error) {
	if !tagPattern.MatchString(tag) {
		return nil, fmt.Errorf("version: a release such as v1.2.3, not %q", tag)
	}
	if !sumPattern.MatchString(sum) {
		return nil, errors.New("sha256: 64 hex digits")
	}
	binary, err := readOwned(path, owner)
	if err != nil {
		return nil, err
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(binary)); !strings.EqualFold(got, sum) {
		return nil, fmt.Errorf("%s isn't the release it should be: its SHA256 is %s, not %s", path, got, strings.ToLower(sum))
	}

	self, err := selfPath()
	if err != nil {
		return nil, err
	}
	if err := replace(self, binary, true); err != nil {
		return nil, err
	}
	if err := runs(self, tag); err != nil {
		if rerr := os.Rename(self+".prev", self); rerr != nil {
			return nil, fmt.Errorf("%s didn't run here (%v), and putting the one before back failed too: %v", tag, err, rerr)
		}
		return nil, fmt.Errorf("%s didn't run here (%v), so the one before is back", tag, err)
	}
	notes = []string{"forge " + tag + " is installed; the one before stays as " + self + ".prev"}
	if State().On {
		if err := setAuto(false); err != nil {
			return notes, fmt.Errorf("forge %s is installed, but automatic updates are still on: %w", tag, err)
		}
		notes = append(notes, "Automatic updates are off: the program that brought this release keeps forge's version")
	}
	return notes, nil
}

// readOwned reads a plain file of owner or root, never through a symlink at
// its end, and checks whose it is on the file it opened.
func readOwned(path string, owner int) ([]byte, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("file: an absolute path, not %q", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("can't open %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s isn't a plain file", path)
	case !ok || (int(st.Uid) != owner && st.Uid != 0):
		return nil, fmt.Errorf("%s isn't a file of the user that asked", path)
	}
	return io.ReadAll(io.LimitReader(f, 200<<20)) // 200 MiB cap, as for a download
}
