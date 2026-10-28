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

## Supported systems

| Release | Status |
|---------|--------|
| **Ubuntu 22.04 / 24.04 / 26.04 LTS** | Supported — provisioned for real in CI containers |
| **Debian 12 (bookworm) / 13 (trixie)** | Supported — provisioned for real in CI containers |
| Ubuntu derivatives (Linux Mint, Pop!_OS, Zorin, elementary…) | Work — mapped to their Ubuntu base via `UBUNTU_CODENAME` |
| Debian derivatives (LMDE, Raspberry Pi OS 64-bit, Proxmox VE…) | Work — mapped via `DEBIAN_CODENAME` / Debian codename |
| Ubuntu interim releases, Debian testing | Run with a warning; Docker/Tailscale repo availability is checked live |
| Ubuntu 20.04, Debian 11 | Legacy — run with a warning |
| Anything non-apt, or without systemd | Refused up front |

Architectures: `amd64`, `arm64`. Distro-specific details forge handles for you:
`sudo` on minimal Debian, fail2ban's journald backend (Debian 12+ has no
`auth.log`), Ubuntu's socket-activated `ssh.socket`, cloud-init's sshd and
hostname overrides, snap-packaged Docker, and LXC/OpenVZ containers (no swap).

## What it does

| Area        | Actions |
|-------------|---------|
| **Docker**  | Docker Engine + Compose V2 + Buildx from the official apt repo |
| **Daemon**  | `daemon.json`: json-file log rotation (10m × 3), `no-new-privileges` for every container, `live-restore` |
| **Tailscale** | Installs Tailscale (fingerprint-verified apt repo); **log in whenever you like** with `sudo forge tailscale` — scan a QR code with your phone, no auth key. The tailnet-only Portainer Agent starts right after that login. Optional Tailscale SSH for emergency phone access. Unattended runs: `TS_AUTHKEY=… sudo forge` |
| **Portainer** | Portainer Agent bound to the **tailnet IP only** + `AGENT_SECRET` (public `0.0.0.0:9001` is a known root-compromise vector; a discouraged public+secret mode exists) |
| **Watchtower** | **Monitor-only** update checks — never auto-replaces containers (optional; maintained `nickfedor/watchtower` fork) |
| **User**    | Creates `deploy` with a password you set, in the `sudo` and `docker` groups |
| **SSH keys**| Imports *your* public key into `authorized_keys` |
| **GitHub**  | One **read-only deploy key per repo** you list, registered through the GitHub API — approve once with a one-time code on your phone; forge throws the login away afterwards. `git clone git@github.com:owner/repo.git` just works as the deploy user. More repos later: `sudo forge github owner/repo` |
| **Hardening** | `sshd`: disable root login, key-only auth, optional port change, `AllowUsers`, no NIST-curve/SHA-1 key exchange or MACs (post-quantum ML-KEM stays on where OpenSSH has it), no agent/X11 forwarding, 30 s login grace — in `sshd_config.d/00-forge.conf`, validated with `sshd -t`, read back with `sshd -T`, rolled back on any failure |
| **Kernel** | `sysctl.d/90-forge.conf`: no ICMP redirects or source routing, anti-spoofing (loose `rp_filter`, Tailscale-safe), SYN cookies, hidden kernel pointers and `dmesg`, no unprivileged BPF, restricted `ptrace` and setuid core dumps |
| **Firewall** | UFW (allow SSH/80/443; the old SSH port stays open until sshd answers on the new one) + fail2ban SSH jail (journald) + **DOCKER-USER rules** (IPv4 + IPv6) so published container ports can't bypass UFW |
| **Updates** | unattended-upgrades for automatic security patches; `needrestart` restarts services still running old libraries; optional reboot at 04:00 when a kernel fix needs it |
| **Alerts**  | Telegram push (optional): daily `forge audit`, host-health warnings (load/disk/reboot), SSH-login notices |
| **Tripwire** | With alerts: every minute, a Telegram alarm on what intruders change to stay — new SSH keys (and `command=`/`from=` options), accounts, sudo rights, sshd auth policy, listening ports, systemd units, cron jobs, startup files (`ld.so.preload`, `.bashrc`…), SUID/SGID files, kernel taint from foreign modules, container images. Each change is reported once; forge's own changes never alarm |
| **Web server** | Your Caddy setup (`caddy_repo`, a repo with `docker-compose.prod.yml`) on :80/:443 — a private repo is cloned with its own read-only deploy key; creates the `proxy-network` network and `PROJECTS_PATH` |
| **Base**    | hostname (+ `/etc/hosts`, kept across cloud-init reboots), timezone, NTP, swap file, journal capped at 500 MB, operator utilities (htop, ncdu, jq, tmux…) |
| **Audit**   | `sudo forge audit` — read-only scan for rootkit/proxyjacking IOCs and risky Docker exposure |

## Day-2 commands

Beyond the provisioning wizard, `forge` doubles as an operations tool:

| Command | What it does |
|---------|--------------|
| `sudo forge audit` | Read-only compromise & exposure scan (IOCs, public ports, floating tags, `/` mounts, docker.sock, UFW bypass). Exit 2 = critical. `--quiet` prints only findings |
| `forge status` | One-glance summary: Docker, agent exposure, firewall, tailnet, alert timers, swap |
| `forge lint <compose.yml>` | Static-check a Compose file **before** deploy for the same risky settings |
| `sudo forge update` | Self-update the binary — verifies **minisign signature + SHA256**, fails closed |
| `sudo forge agent-secret` | Switch this server's Portainer Agent to your shared `AGENT_SECRET` (asked hidden). A Portainer Server takes one secret for all agents — start it with `-e AGENT_SECRET=…` and use the same one on every server (also the wizard field, or `PORTAINER_AGENT_SECRET=…`) |
| `forge rotate-agents [--portainer DIR] [user@host …]` | **Red button** for a lost/leaked `AGENT_SECRET`, run where your Portainer Server lives: a new secret goes to every server's agent over SSH (stdin only — never a command line), then into `DIR/.env`, and Portainer restarts with it. Servers and DIR are remembered; unreachable servers are listed with the fix |
| `sudo forge tailscale` | Log in to Tailscale (QR code) and start the tailnet-only Portainer Agent. Safe to re-run |
| `sudo forge github owner/repo …` | Add read-only deploy keys for more repos (one-time code on your phone) |
| `sudo forge caddy [owner/repo]` | Install or update the Caddy web server from your repo |
| `sudo forge ssh tailnet-only` | **Optional**: close SSH to the internet, so only Tailscale reaches it. Refuses unless you're connected over Tailscale right now and the node key never expires; `sudo forge ssh public` reopens it, `sudo forge ssh` shows the state |
| `sudo forge tripwire --show` | What the tripwire watches right now (`--baseline` re-records it) |
| `sudo forge update images` | Re-pull pinned images and recreate drifted agent/watchtower (the deliberate counterpart to monitor-only Watchtower) |
| `forge modules --json` | **Machine mode** (for deploy.me or any program over SSH): the catalog of modules — what each does, whether it changes access or waits for a person, its inputs |
| `sudo forge run <module>` | Runs one module with its inputs as JSON on the first line of stdin (`{"inputs": {…}}`, so secrets never reach a command line); reports as `::forge::{json}` lines: steps, login links and codes to act on, the result |
| `forge status --json` / `forge audit --json` | The same facts and checks as one JSON object |
| `sudo forge machine enable [user]` | Lets the deploy user run the four commands above without a password (`/etc/sudoers.d/forge-machine`, checked with `visudo`); refuses unless the forge binary and its folder are root's alone. `disable` removes it |

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

## Build & run from your machine

Only **Docker** is required — without a local Go toolchain, every `make`
target builds inside `golang:1.27` (output owned by you, caches in `.cache/`).
Run `make` to list all targets.

```bash
make try                                   # click through the wizard in a throwaway Ubuntu container — changes nothing
make try DISTRO=debian:13                  # …or on another release

make deploy HOST=root@203.0.113.10         # build for the server's CPU, copy over SSH, verify sha256, run the wizard
make deploy HOST=ubuntu@srv ARGS=--dry-run # any forge arguments via ARGS (audit, status, --config …)
make deploy HOST=deploy@srv SSH_PORT=2222 SSH_OPTS="-i ~/.ssh/id_vps -o IdentitiesOnly=yes"

make dist                                  # dist/forge-linux-{amd64,arm64} + checksums.txt
make build                                 # ./forge for this machine
make test                                  # unit tests;  make test-distros: real steps in Ubuntu/Debian containers
```

`make deploy` uses one multiplexed SSH connection (one password/passphrase
prompt), installs the binary as `/usr/local/bin/forge` (via `sudo` when you
log in as a regular user) and hands the wizard your terminal. Keep that
session open until you've checked the new SSH login, as usual.

The wizard walks you through the deploy user, your SSH key, GitHub repos,
features and hardening; submitting the last page starts the setup, with a live
progress view. At the end it prints a summary with what to do next (e.g.
`sudo forge tailscale`). Your answers (no secrets) are kept in
`/etc/forge/config.yaml` for those follow-up commands.

### Flags

| Flag | Description |
|------|-------------|
| `audit` | **Subcommand**: read-only compromise & exposure check (rootkit IOCs, cron/systemd persistence, public container ports, floating tags, docker.sock holders, firewall bypass). Exit code 2 = critical findings |
| `--dry-run` | Walk the wizard and print every action without changing anything (works without root) |
| `--config <file>` | Replay answers from a YAML file (only the password is prompted) |
| `--save-config <file>` | Save your answers to YAML for reuse (the password is **never** written) |
| `--version` | Print version and exit |

### Reusable config

```bash
sudo ./forge --save-config server.yaml      # run once, save answers
sudo ./forge --config server.yaml           # replay on the next box
```

## ⚠ Safety

When root login or password auth is disabled, **open a new terminal and verify
`ssh deploy@host` works before closing your current session.** If the key
isn't right, fix it from the still-open session — `forge` validates `sshd -t`
before restarting, but it can't test *your* key for you.

## Security

Supply-chain hardening is a first-class concern — see [`SECURITY.md`](SECURITY.md)
for the full picture. In short:

- Docker's, Tailscale's and GitHub CLI's apt keys are **fingerprint-verified** (fail-closed) before they can sign packages.
- Container images are **pinned to versions** (never `:latest`) and run with `no-new-privileges`.
- The Portainer Agent is **never published to the internet by default**: it binds to the
  tailnet IP and requires an `AGENT_SECRET` to pair. An exposed agent is root-equivalent.
- **DOCKER-USER firewall rules** close the classic hole where `-p`-published ports
  silently bypass UFW: containers accept external traffic on 80/443 only.
- GitHub's SSH host key is **pinned**, not trust-on-first-use.
- Installers **verify SHA256** and fail closed on mismatch.
- Usernames are regex-validated and all downloads run **without a shell** (no injection).
- Preview everything first: `forge --dry-run` prints every command and changes nothing.
- Check a running box any time: `sudo forge audit` scans for rootkit/proxyjacking
  IOCs and risky Docker exposure without changing anything.
- Releases are **minisign-signed**; `forge update` verifies the signature in-process
  (not just a checksum from the same host that could be swapped alongside it).

## Layout

```
scripts/deploy.sh       `make deploy`: build for the server's arch, scp, verify, run
main.go                 entrypoint: flags, checks, banner, wizard → runner
internal/config         Config struct + YAML load/save (password excluded)
internal/system         shell exec wrappers (dry-run aware) + host facts
internal/steps          ordered, idempotent provisioning steps
internal/ui             banner, huh wizard, bubbletea runner, summary
deploy/                 self-hosted Caddy installer (cli.sh + site block)
```
```bash
make test               # full step engine in dry-run mode, simulated per distro
make test-distros       # real apt/sshd/fail2ban steps in Ubuntu/Debian containers (docker)
```
