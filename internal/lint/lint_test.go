package lint

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A file reproducing the incident's mistakes must return a critical exit code.
func TestLintFlagsCriticalIssues(t *testing.T) {
	body := `services:
  agent:
    image: portainer/agent:latest
    ports:
      - "9001:9001"
    volumes:
      - /:/host
  api:
    image: myapp:1.2.3
    privileged: true
    ports:
      - "0.0.0.0:5432:5432"
`
	if code := Run(writeTemp(t, body)); code != 2 {
		t.Fatalf("expected exit code 2 (critical), got %d", code)
	}
}

// A clean, well-scoped file must pass.
func TestLintPassesCleanFile(t *testing.T) {
	body := `services:
  web:
    image: nginx:1.27.3
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
  db:
    image: postgres:16.4
    restart: unless-stopped
    ports:
      - "127.0.0.1:5432:5432"
`
	if code := Run(writeTemp(t, body)); code != 0 {
		t.Fatalf("expected exit code 0 (clean), got %d", code)
	}
}

// Floating tags and a missing restart policy are warnings, not criticals.
func TestLintWarnsOnFloatingTag(t *testing.T) {
	body := `services:
  web:
    image: nginx:stable
    ports:
      - "127.0.0.1:8080:80"
`
	if code := Run(writeTemp(t, body)); code != 1 {
		t.Fatalf("expected exit code 1 (warnings), got %d", code)
	}
}
