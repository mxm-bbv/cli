package steps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mxm-bbv/cli/internal/config"
	"github.com/mxm-bbv/cli/internal/system"
)

// The agent comes off with its secret; a firewall forge never set up gets no
// rules from it.
func TestRemoveAgentSteps(t *testing.T) {
	prev := agentEnvPath
	agentEnvPath = filepath.Join(t.TempDir(), "agent.env")
	t.Cleanup(func() { agentEnvPath = prev })
	if err := os.WriteFile(agentEnvPath, []byte("AGENT_SECRET=0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	system.DryRun = true
	t.Cleanup(func() { system.DryRun = false })

	st, ctx := RemoveAgentSteps(config.Default())
	if ctx.Cfg.InstallPortainer {
		t.Error("the config still installs the agent")
	}
	want := []string{"Portainer Agent removed", "Its AGENT_SECRET forgotten", "Port 9001 closed in the container firewall"}
	if len(st) != len(want) {
		t.Fatalf("got %d steps, want %d", len(st), len(want))
	}
	for i, s := range st {
		if s.Name != want[i] {
			t.Errorf("step %d: got %q, want %q", i, s.Name, want[i])
		}
	}
	// No agent container in a dry run, and no forge firewall script on this machine.
	if !st[0].Skip(ctx) || !st[2].Skip(ctx) {
		t.Error("removing an agent that isn't there, or rewriting a firewall forge didn't set up")
	}
	if st[1].Skip(ctx) {
		t.Fatal("the kept secret wasn't going to be forgotten")
	}
	if err := st[1].Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(agentEnvPath); !os.IsNotExist(err) {
		t.Errorf("the secret file is still there: %v", err)
	}
	if !st[1].Skip(ctx) {
		t.Error("forgetting the secret again isn't skipped")
	}
}
