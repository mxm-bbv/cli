package steps

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/mxm-bbv/cli/internal/system"
)

const (
	ghKeyring = "/usr/share/keyrings/githubcli-archive-keyring.gpg"
	ghList    = "/etc/apt/sources.list.d/github-cli.list"
	ghRepoURL = "https://cli.github.com/packages"

	// ghConfigDir holds the GitHub CLI's login while forge uses it: tmpfs,
	// root-only, removed afterwards (and by Cleanup if forge is aborted).
	ghConfigDir = "/run/forge-gh"
)

// Cleanup removes what an interrupted run may have left behind.
func Cleanup() {
	if !system.DryRun {
		_ = os.RemoveAll(ghConfigDir)
	}
}

// githubStep gives the deploy user one read-only deploy key per repo. A deploy
// key opens exactly one repository, read-only — so a compromised server leaks
// those repos and nothing else, unlike a key on the GitHub account, which can
// read and push everything the account can.
//
// Keys are registered through the GitHub API by the official GitHub CLI: the
// operator approves a one-time code on github.com (a phone is enough), forge
// adds the keys and throws the login away. Repos whose key already works are
// left alone, so re-running is cheap and asks nothing.
func githubStep() Step {
	return Step{
		Name: "GitHub: read-only deploy keys for your repos",
		Skip: func(c *Context) bool { return len(c.Cfg.GitHubRepos) == 0 },
		Run:  setupGitHubRepos,
	}
}

// deployKey is one repo's key file and the ssh host alias that selects it.
type deployKey struct{ repo, alias, path string }

// deployKeyFor names repo's key and alias. GitHub owners cannot contain "--",
// so owner--repo never collides between repos.
func deployKeyFor(sshDir, repo string) deployKey {
	slug := strings.ToLower(strings.Replace(repo, "/", "--", 1))
	return deployKey{repo: repo, alias: "github-" + slug, path: sshDir + "/github-" + slug}
}

func setupGitHubRepos(c *Context) error {
	cfg := c.Cfg
	user, sshDir := cfg.Username, cfg.HomeDir()+"/.ssh"
	if _, err := system.Output("id", "-u", user); err != nil && !system.DryRun {
		return fmt.Errorf("user %q does not exist — run the forge setup first", user)
	}
	if err := aptInstall("git", "openssh-client"); err != nil {
		return err
	}
	if _, err := system.Run("install", "-d", "-m", "700", "-o", user, "-g", user, sshDir); err != nil {
		return err
	}
	if err := ensureGitHubKnownHost(sshDir); err != nil {
		return err
	}

	keys := make([]deployKey, 0, len(cfg.GitHubRepos))
	for _, repo := range cfg.GitHubRepos {
		k := deployKeyFor(sshDir, repo)
		if err := prepareDeployKey(c, k); err != nil {
			return err
		}
		keys = append(keys, k)
	}
	if _, err := system.Run("chown", "-R", user+":"+user, sshDir); err != nil {
		return err
	}
	_, _ = system.RunShell(fmt.Sprintf("chmod 600 %s/config %s/known_hosts %s/github-* 2>/dev/null; chmod 644 %s/github-*.pub 2>/dev/null; true",
		sshDir, sshDir, sshDir, sshDir))

	var pending []deployKey
	for _, k := range keys {
		if !deployKeyWorks(user, k) {
			pending = append(pending, k)
		}
	}
	if len(pending) > 0 {
		if err := registerDeployKeys(pending); err != nil {
			return err
		}
	}

	var failed []string
	for _, k := range keys {
		if system.DryRun || deployKeyWorks(user, k) {
			c.GitHubRepos = append(c.GitHubRepos, k.repo)
		} else {
			failed = append(failed, k.repo)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("GitHub still refuses the deploy key for %s — check the repo's Settings → Deploy keys", strings.Join(failed, ", "))
	}
	c.Notes = append(c.Notes, fmt.Sprintf("GitHub: read-only deploy keys for %s. Clone as %s the usual way, e.g.  git clone git@github.com:%s.git",
		strings.Join(c.GitHubRepos, ", "), user, c.GitHubRepos[0]))
	if len(pending) > 0 {
		// GitHub ties a deploy key to the OAuth token that created it.
		c.Notes = append(c.Notes, "Don't revoke \"GitHub CLI\" under github.com/settings/applications — GitHub would delete these deploy keys with it")
	}
	return nil
}

// prepareDeployKey creates k's key pair, its ~/.ssh/config alias and the git
// rewrite that routes the repo's normal GitHub URLs through that alias — so
// `git clone git@github.com:owner/repo.git` just works with the right key.
func prepareDeployKey(c *Context, k deployKey) error {
	user := c.Cfg.Username
	if !system.FileExists(k.path) {
		comment := fmt.Sprintf("%s@%s %s (forge)", user, system.Hostname(), k.repo)
		if _, err := system.Run("runuser", "-u", user, "--",
			"ssh-keygen", "-q", "-t", "ed25519", "-C", comment, "-f", k.path, "-N", ""); err != nil {
			return err
		}
	}

	cfgPath := c.Cfg.HomeDir() + "/.ssh/config"
	if !system.FileContains(cfgPath, "Host "+k.alias+"\n") {
		entry := fmt.Sprintf("Host %s\n    HostName github.com\n    User git\n    IdentityFile %s\n    IdentitiesOnly yes\n",
			k.alias, k.path)
		if err := appendLine(cfgPath, entry); err != nil {
			return err
		}
	}

	// Only the .git forms: "…/repo" without it would also be a prefix of
	// "…/repo-other" and send that repo through this key.
	target := "url.git@" + k.alias + ":" + k.repo + ".git.insteadOf"
	have, _ := system.Output("runuser", "-u", user, "--", "git", "config", "--global", "--get-all", target)
	for _, from := range []string{"git@github.com:" + k.repo + ".git", "https://github.com/" + k.repo + ".git"} {
		if strings.Contains("\n"+have+"\n", "\n"+from+"\n") {
			continue
		}
		if _, err := system.Run("runuser", "-u", user, "--", "git", "config", "--global", "--add", target, from); err != nil {
			return err
		}
	}
	return nil
}

// deployKeyWorks asks GitHub whether k's key opens k's repo. GitHub answers
// every key login with "Hi owner/repo! You've successfully authenticated…" and
// exit status 1 (no shell), so the text is what counts.
func deployKeyWorks(user string, k deployKey) bool {
	if system.DryRun {
		return false
	}
	out, _ := system.Output("runuser", "-u", user, "--",
		"ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "git@"+k.alias)
	return strings.Contains(out, "successfully authenticated")
}

// registerDeployKeys logs in to the GitHub CLI with a one-time device code,
// adds each key as a read-only deploy key, then logs out. The CLI keeps its
// token under GH_CONFIG_DIR, which here is a private directory on tmpfs that
// is deleted afterwards — the token never reaches the disk.
func registerDeployKeys(keys []deployKey) error {
	if err := installGitHubCLI(); err != nil {
		return err
	}
	if !system.DryRun {
		Cleanup()
		if err := os.Mkdir(ghConfigDir, 0o700); err != nil {
			return err
		}
		defer Cleanup()
	}
	env := []string{"GH_CONFIG_DIR=" + ghConfigDir, "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1"}

	defer system.SetAttention(nil)
	if _, err := system.RunWatchEnv("gh auth login --web (one-time code)", env, watchGitHubLogin,
		// --insecure-storage: the token goes to GH_CONFIG_DIR (tmpfs), never
		// into a system keyring where it would outlive this step.
		"gh", "auth", "login", "--hostname", "github.com", "--web", "--skip-ssh-key", "--git-protocol", "ssh",
		"--insecure-storage"); err != nil {
		return fmt.Errorf("GitHub login was not completed — press r for a new code: %w", err)
	}
	system.SetAttention(nil)
	defer func() { _, _ = system.RunEnv(env, "gh", "auth", "logout", "--hostname", "github.com") }()

	title := system.Hostname() + " (forge, read-only)"
	for _, k := range keys {
		out, err := system.RunEnv(env, "gh", "repo", "deploy-key", "add", k.path+".pub", "--repo", k.repo, "--title", title)
		if err == nil || strings.Contains(out, "key is already in use") {
			continue
		}
		if strings.Contains(out, "HTTP 404") {
			return fmt.Errorf("GitHub: %s not found — check the name; adding deploy keys needs admin rights on the repo", k.repo)
		}
		return fmt.Errorf("GitHub: add deploy key to %s: %w", k.repo, err)
	}
	return nil
}

// ghCodeRe finds the device code in `gh auth login --web` output:
// "! First copy your one-time code: ABCD-1234".
var ghCodeRe = regexp.MustCompile(`one-time code: ([A-Z0-9]{4}-[A-Z0-9]{4})`)

// watchGitHubLogin turns the device code gh prints into an operator action.
func watchGitHubLogin(line string) {
	if m := ghCodeRe.FindStringSubmatch(line); m != nil {
		system.SetAttention(&system.Attention{
			Title: "Approve forge on GitHub to add the deploy keys",
			URL:   "https://github.com/login/device",
			Code:  m[1],
			Hint: "Open the link (or scan the QR code with your phone), sign in, enter the code and " +
				"authorize GitHub CLI. forge adds the keys, then deletes the login.",
		})
	}
}

// installGitHubCLI installs gh from GitHub's apt repo, with the same
// fingerprint-pinned, fail-closed trust as Docker and Tailscale.
func installGitHubCLI() error {
	if system.CommandExists("gh") {
		return nil
	}
	if !system.FileExists(ghKeyring) {
		if _, err := system.Run("curl", "-fsSL", ghRepoURL+"/githubcli-archive-keyring.gpg", "-o", ghKeyring); err != nil {
			return err
		}
		if err := verifyKeyFingerprint(ghKeyring, githubCLIGPGFingerprint, "GitHub CLI"); err != nil {
			return err
		}
	}
	line := fmt.Sprintf("deb [arch=%s signed-by=%s] %s stable main", system.Arch(), ghKeyring, ghRepoURL)
	if err := system.WriteFile(ghList, line+"\n", 0o644); err != nil {
		return err
	}
	if _, err := aptGet("update", "-y"); err != nil {
		return err
	}
	return aptInstall("gh")
}
