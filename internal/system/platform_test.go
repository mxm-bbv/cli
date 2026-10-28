package system

import (
	"strings"
	"testing"
)

// Real /etc/os-release contents (trimmed to the fields that matter).
var osReleaseFixtures = map[string]string{
	"ubuntu-22.04": `PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=jammy`,
	"ubuntu-24.04": `PRETTY_NAME="Ubuntu 24.04.3 LTS"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble`,
	"ubuntu-26.04": `PRETTY_NAME="Ubuntu 26.04 LTS"
VERSION_ID="26.04"
VERSION_CODENAME=resolute
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=resolute`,
	"ubuntu-25.10": `PRETTY_NAME="Ubuntu 25.10"
VERSION_ID="25.10"
VERSION_CODENAME=questing
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=questing`,
	"ubuntu-20.04": `PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
VERSION_CODENAME=focal
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=focal`,
	"debian-12": `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`,
	"debian-13": `PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
VERSION_ID="13"
VERSION_CODENAME=trixie
ID=debian`,
	"mint-22": `NAME="Linux Mint"
VERSION="22 (Wilma)"
ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 22"
VERSION_ID="22"
VERSION_CODENAME=wilma
UBUNTU_CODENAME=noble`,
	"lmde-6": `PRETTY_NAME="LMDE 6 (faye)"
NAME="LMDE"
VERSION_ID="6"
ID=linuxmint
ID_LIKE=debian
VERSION_CODENAME=faye
DEBIAN_CODENAME=bookworm`,
	"pop-22.04": `NAME="Pop!_OS"
VERSION_ID="22.04"
ID=pop
ID_LIKE="ubuntu debian"
PRETTY_NAME="Pop!_OS 22.04 LTS"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy`,
	"raspios-12": `PRETTY_NAME="Raspbian GNU/Linux 12 (bookworm)"
NAME="Raspbian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=raspbian
ID_LIKE=debian`,
	"kali": `PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.3"
ID=kali
ID_LIKE=debian
VERSION_CODENAME=kali-rolling`,
	"fedora": `NAME="Fedora Linux"
VERSION_ID=42
ID=fedora
PRETTY_NAME="Fedora Linux 42 (Server Edition)"`,
}

// fixture parses a named os-release fixture.
func fixture(t *testing.T, name string) OSRelease {
	t.Helper()
	data, ok := osReleaseFixtures[name]
	if !ok {
		t.Fatalf("no fixture %q", name)
	}
	return ParseOSRelease(data)
}

func TestDetectPlatform(t *testing.T) {
	cases := []struct {
		fixture    string
		family     string
		codename   string
		derivative bool
		support    Support
	}{
		{"ubuntu-22.04", "ubuntu", "jammy", false, SupportTested},
		{"ubuntu-24.04", "ubuntu", "noble", false, SupportTested},
		{"ubuntu-26.04", "ubuntu", "resolute", false, SupportTested},
		{"ubuntu-25.10", "ubuntu", "questing", false, SupportUnknown},
		{"ubuntu-20.04", "ubuntu", "focal", false, SupportLegacy},
		{"debian-12", "debian", "bookworm", false, SupportTested},
		{"debian-13", "debian", "trixie", false, SupportTested},
		{"mint-22", "ubuntu", "noble", true, SupportTested},
		{"lmde-6", "debian", "bookworm", true, SupportTested},
		{"pop-22.04", "ubuntu", "jammy", true, SupportTested},
		{"raspios-12", "debian", "bookworm", true, SupportTested},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			p, err := DetectPlatform(fixture(t, tc.fixture))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Family != tc.family || p.Codename != tc.codename {
				t.Errorf("got %s/%s, want %s/%s", p.Family, p.Codename, tc.family, tc.codename)
			}
			if p.Derivative != tc.derivative {
				t.Errorf("derivative = %v, want %v", p.Derivative, tc.derivative)
			}
			if p.Support != tc.support {
				t.Errorf("support = %v, want %v", p.Support, tc.support)
			}
			if (p.Support == SupportTested) != (p.SupportNote() == "") {
				t.Errorf("SupportNote() = %q inconsistent with support %v", p.SupportNote(), p.Support)
			}
		})
	}
}

func TestDetectPlatformRejects(t *testing.T) {
	for name, want := range map[string]string{
		"kali":   "cannot tell which Ubuntu/Debian release",
		"fedora": "unsupported OS",
	} {
		if _, err := DetectPlatform(fixture(t, name)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: expected error containing %q, got %v", name, want, err)
		}
	}
	// Debian sid/testing snapshots can lack a codename entirely.
	if _, err := DetectPlatform(ParseOSRelease("ID=debian\nPRETTY_NAME=\"Debian GNU/Linux trixie/sid\"")); err == nil {
		t.Error("expected an error for a Debian release without a codename")
	}
}

func TestParseOSReleaseQuotingAndComments(t *testing.T) {
	r := ParseOSRelease("# comment\n\nID='ubuntu'\n  VERSION_CODENAME=\"Noble\"  \nPRETTY_NAME=\"Ubuntu \\\"x\\\"\"\nBROKEN LINE\n")
	if r.ID != "ubuntu" || r.Codename != "noble" {
		t.Fatalf("got %+v", r)
	}
	if !r.IsDebianLike() {
		t.Error("ubuntu must be Debian-like")
	}
}

func TestIsDebianLikeUsesWholeWords(t *testing.T) {
	if (OSRelease{ID: "foo", IDLike: "notdebian"}).IsDebianLike() {
		t.Error("ID_LIKE=notdebian must not count as Debian-like")
	}
	if !(OSRelease{ID: "pop", IDLike: "ubuntu debian"}).IsDebianLike() {
		t.Error("Pop!_OS must count as Debian-like")
	}
}
