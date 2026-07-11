```
 ██████╗██╗     ██╗
██╔════╝██║     ██║
██║     ██║     ██║
██║     ██║     ██║
╚██████╗███████╗██║
 ╚═════╝╚══════╝╚═╝
  Created by mxm_bbv
```

# ServerForge (`forge`)

A single-binary TUI wizard that turns a **clean Ubuntu/Debian** box into a
production-ready host in one pass — no runtime, no dependencies on the server.

## What it does

| Area        | Actions |
|-------------|---------|
| **Docker**  | Docker Engine + Compose V2 + Buildx from the official apt repo |
| **Logging** | `daemon.json` with json-file log rotation (10m × 3) so logs never fill the disk |
| **Portainer** | Portainer Agent on `:9001` (optional) |
| **Watchtower** | Auto-update running containers (optional) |
| **User**    | Creates `deploy` with a password you set, in the `sudo` and `docker` groups |
| **SSH keys**| Imports *your* public key into `authorized_keys`; generates an ed25519 **deploy key for GitHub** (+ `known_hosts` + `~/.ssh/config`) |
| **Hardening** | `sshd`: disable root login, key-only auth, optional port change, `AllowUsers` — validated with `sshd -t` before restart |
| **Firewall** | UFW (allow SSH/80/443) + fail2ban SSH jail |
| **Updates** | unattended-upgrades for automatic security patches |
| **Base**    | hostname, timezone, NTP, swap file, operator utilities (htop, ncdu, jq, tmux…) |

Every step is **idempotent** — re-running skips what's already done. SSH
hardening always runs **last**, so the box stays reachable until everything
else succeeds.

## Install & run (one command)

On a fresh server, download the prebuilt binary and launch the wizard:

```bash
curl -fsSL https://raw.githubusercontent.com/mxm-bbv/cli/main/install.sh | bash
```

The installer detects your architecture (amd64/arm64), verifies the binary's
SHA256, drops `forge` into `/usr/local/bin`, and starts the wizard. Afterwards
it's always available as:

```bash
sudo forge
```

> Prefer a vanity URL like `mxm-bbv.dev/cli.sh`? See [`deploy/`](deploy/) for a
> self-hosted Caddy setup that serves the installer + binary from your domain.

Binaries are published automatically by GitHub Actions when a version tag is
pushed (`git tag v0.1.0 && git push origin v0.1.0`), so you never build by hand.

## Build from source (optional)

```bash
make build            # -> ./forge for this platform
make build-linux      # -> dist/forge-linux-{amd64,arm64}
sudo ./forge
```

The wizard walks you through the deploy user, your SSH key, GitHub key,
features and hardening, shows a confirmation, then executes with a live
progress view. At the end it prints a summary including the **GitHub public
key to paste into your repo's Deploy keys**.

### Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Walk the wizard and print every action without changing anything (works without root) |
| `--config <file>` | Replay answers from a YAML file (only the password is prompted) |
| `--save-config <file>` | Save your answers to YAML for reuse (the password is **never** written) |
| `--yes` | Skip the final confirmation prompt |
| `--version` | Print version and exit |

### Reusable config

```bash
sudo ./forge --save-config server.yaml      # run once, save answers
sudo ./forge --config server.yaml --yes     # replay on the next box
```

## ⚠ Safety

When root login or password auth is disabled, **open a new terminal and verify
`ssh deploy@host` works before closing your current session.** If the key
isn't right, fix it from the still-open session — `forge` validates `sshd -t`
before restarting, but it can't test *your* key for you.

## Security

Supply-chain hardening is a first-class concern — see [`SECURITY.md`](SECURITY.md)
for the full picture. In short:

- Docker's apt key is **fingerprint-verified** (fail-closed) before it can sign packages.
- Container images are **pinned to versions** (never `:latest`) and run with `no-new-privileges`.
- GitHub's SSH host key is **pinned**, not trust-on-first-use.
- Installers **verify SHA256** and fail closed on mismatch.
- Usernames are regex-validated and all downloads run **without a shell** (no injection).
- Preview everything first: `forge --dry-run` prints every command and changes nothing.

## Layout

```
main.go                 entrypoint: flags, checks, banner, wizard → runner
internal/config         Config struct + YAML load/save (password excluded)
internal/system         shell exec wrappers (dry-run aware) + host facts
internal/steps          ordered, idempotent provisioning steps
internal/ui             banner, huh wizard, bubbletea runner, summary
deploy/                 self-hosted Caddy installer (cli.sh + site block)
```
```bash
go test ./...           # exercises the full step engine in dry-run mode
```
