# Security & supply-chain notes

ServerForge provisions servers, so its own trustworthiness matters. This
document records what it installs, where each artifact comes from, and how that
provenance is verified. The goal: **no unpinned images, no blindly-trusted
keys, no unverified downloads, no command injection.**

## Trust anchors (single source of truth)

All pinned versions and fingerprints live in
[`internal/steps/pins.go`](internal/steps/pins.go). Changing any of them is a
deliberate, reviewable act.

| Anchor | Value | Source |
|--------|-------|--------|
| Docker apt key fingerprint | `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` | docs.docker.com |
| Tailscale apt key fingerprint | `2596A99EAAB33821893C0A79458CA832957F5868` | pkgs.tailscale.com |
| GitHub CLI apt key fingerprint | `7F38BBB59D064DBCB3D84D725612B36462313325` | cli.github.com/packages |
| GitHub host key (ed25519) | `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` | docs.github.com |
| forge release minisign key | `RWSk3LOux6EkxZOpVER2fnvn2WKOHPBPG128iEhEy3JGztPOte98a+3C` | this repo (`pins.go`) |
| Portainer Agent image | `portainer/agent:2.39.1` (keep in lockstep with your Portainer Server) | Docker Hub |
| Watchtower image | `nickfedor/watchtower:1.23.2` (maintained fork — upstream `containrrr` was archived Dec 2025 and fails on Docker 29+) | Docker Hub |

## What is verified, and how

- **Docker Engine / Compose / Buildx** — installed from Docker's official apt
  repository. After downloading the signing key we verify its fingerprint
  against the pinned value (`verifyDockerKey`) and **delete it + abort on
  mismatch**, so a MITM'd keyring can't authorise malicious packages. Packages
  are then `signed-by` that verified key.
- **Container images** — pinned to specific version tags, never `:latest`, so a
  repushed tag can't swap the image out. Both agent containers run with
  `--security-opt no-new-privileges` to block setuid-based escalation, and
  `daemon.json` applies `no-new-privileges` daemon-wide plus `live-restore`.
- **Portainer Agent** — treated as **root-equivalent** (it holds the docker
  socket). It is therefore never published on `0.0.0.0` by default: it binds to
  the Tailscale IP, so the port does not exist on the public interface, and it
  requires an `AGENT_SECRET` to pair (without one, *any* Portainer server that
  reaches the port gains full control — this exact misconfiguration has caused
  real-world root compromises with rootkit + proxyjacking payloads). It also
  does **not** mount `/:/host`; only the docker socket and volume dir it needs.
  Re-running forge on a box with an insecurely-bound agent replaces it.
- **Tailscale** — installed from Tailscale's apt repo with the signing key
  fingerprint-verified fail-closed, same as Docker's. Setup only installs it;
  the operator logs in later with `forge tailscale` (browser/QR). Until then a
  tailnet-mode Portainer Agent is simply not started — it is never bound to
  `0.0.0.0` as a stopgap. An optional `TS_AUTHKEY` (unattended runs) is read
  from the environment and never written to disk or logs.
- **GitHub deploy keys** — one ed25519 key per repo, registered as a
  **read-only deploy key**: a compromised server can read those repos and
  nothing else (an account SSH key would read and push everything). The keys
  are added through the GitHub API by the official GitHub CLI (apt repo,
  fingerprint-pinned) after a one-time device-code approval. Its token lives
  only in `/run/forge-gh` (tmpfs, root-only) and is deleted right after —
  also when forge is aborted, which kills a login still waiting for approval.
- **Tripwire** — `forge tripwire` (systemd timer, every minute, low
  priority) snapshots the usual persistence points and sends every
  difference from the last run to Telegram once; an alert that couldn't be
  sent is retried. forge re-records the baseline after its own changes.
  Root can of course disable it — it is there to catch the minutes between
  the break-in and that.
- **SSH over Tailscale only (optional)** — `forge ssh tailnet-only` removes
  sshd's ports from UFW (`tailscale0` stays trusted) only when the operator's
  current session comes from a tailnet address and the node key does not
  expire — the two ways this would lock you out. The provider's web console
  is the last resort; the setup remembers the choice and doesn't reopen it.
- **DOCKER-USER firewall** — Docker inserts its own iptables chains ahead of
  UFW's INPUT rules, so `ufw default deny incoming` does **not** protect
  `-p`-published container ports. forge installs a persistent DOCKER-USER
  policy (systemd oneshot, reapplied after docker starts): external traffic
  reaches containers only on 80/443 (plus 9001 in the discouraged public agent
  mode); the tailnet interface is trusted. Note the port matched is the
  *container* port (DNAT runs first) — publish services on matching ports.
- **Watchtower** — runs `--monitor-only`. An auto-updater holding the docker
  socket is a supply-chain risk: it would replace your containers with whatever
  a registry serves next. It reports; you update deliberately. forge uses the
  maintained `nickfedor/watchtower` fork: the archived `containrrr/watchtower`
  speaks Docker API 1.25, which Engine 29+ rejects, so it crash-loops.
- **sshd policy** — written to `/etc/ssh/sshd_config.d/00-forge.conf`, not the
  main file. sshd keeps the *first* value it reads and the stock config
  includes `sshd_config.d/*.conf` at the top, so on cloud images
  `50-cloud-init.conf` (`PasswordAuthentication yes`) would otherwise silently
  win. After `sshd -t`, forge reads back the effective config with `sshd -T`
  and reverts if anything (password auth, root login, port, `AllowUsers`)
  differs. A port change keeps the old port open in UFW until sshd answers on
  the new one (a real TCP connection returning an `SSH-` banner); Ubuntu's
  socket-activated `ssh.socket` is rebound too. Any failure restores the
  previous config and restarts sshd onto it.
- **GitHub host key** — added to `known_hosts` only after `ssh-keyscan` output
  is fingerprinted and matched against the pinned value
  (`verifiedGitHubHostKey`) — no trust-on-first-use.
- **Released binaries** — the `install.sh` / self-hosted `deploy/cli.sh`
  installers download `checksums.txt` (or `.sha256`) and **fail closed** unless
  the SHA256 matches. Override only with `FORGE_ALLOW_UNVERIFIED=1`.
- **Release signatures (minisign)** — the release workflow signs `checksums.txt`
  with a passwordless minisign key (private key in the `MINISIGN_KEY` repo
  secret, never in the tree). `forge update` verifies that signature **in
  process** against the pinned public key before trusting the checksums or
  installing the binary — so an attacker who swaps the binary *and* its checksum
  in a compromised release still can't forge the signature. `install.sh` also
  verifies opportunistically when `minisign` is present. The verifier
  (`internal/update/minisign.go`) supports minisign's prehashed (BLAKE2b-512)
  format and depends only on the Go standard library plus `x/crypto/blake2b`.
- **Telegram alerts** — push-only over HTTPS to `api.telegram.org`; nothing
  listens. The bot token lives in `/etc/forge/alerts.env` (mode 0600) and is
  never serialised to the reusable YAML config or written to the command log.
  The token reaches curl through a config on stdin, never argv, so other local
  users can't read it from `/proc`. Token and chat ID are format-checked before
  they are written, because `alerts.env` is sourced by root-run scripts. The
  SSH-login notice runs from `/etc/pam.d/sshd` as
  `session optional pam_exec.so` — as root, so it can read the 0600 env file
  (the former `/etc/ssh/sshrc` hook ran as the logging-in user and never fired
  for non-root logins). `optional` plus a script that backgrounds the push and
  exits immediately means it can never block or delay a login. The name and the
  quiet-address list are single-quoted in `alerts.env` and can't hold a quote,
  `$` or a backtick. What is worth a message is decided by `forge alert` (Go,
  under a file lock): the hourly limit never holds back the tripwire or the
  audit, so a flood of logins from new addresses can't push the one alert that
  matters into the next day's summary.
- **No command injection** — the deploy username is validated against a strict
  regex (`ValidUsername`) before it flows into any command, the GitHub username
  for key fetching is regex-validated, and both use `exec` (no shell). Secrets
  (the deploy password) are fed via stdin and never logged or serialised.

## Auditing a run before applying it

```bash
forge --dry-run        # prints every command; changes nothing (no root needed)
```

Nothing runs until you confirm. Review the printed command list — it shows the
exact images, packages, and files that will be touched.

## Auditing a running host

```bash
sudo forge audit       # read-only; exit code 2 = critical findings
```

Checks, in order: LD_PRELOAD rootkit indicators (`/etc/ld.so.preload`), known
malware artifacts and cron/systemd persistence names from a real proxyjacking
incident (`perfcc`, `libgcwrap`, EarnFM/Repocket/TraffMonetizer), container
ports published to the internet (9001 is flagged critical), floating image
tags, `--privileged`/`--pid=host`/`/` mounts, docker.sock holders, Watchtower
without `--monitor-only`, UFW state, whether DOCKER-USER actually filters
container traffic, and every `authorized_keys` entry for manual review.

Known deliberate trade-offs (documented, not bugs): the `deploy` user is in the
`docker` group, which is root-equivalent on the host — acceptable for a
single-admin box, unacceptable for shared ones. Rootless Docker would remove
that but breaks low ports and common volume patterns, so forge doesn't use it.

## Reporting

Found a weakness? Open a private security advisory on the repository rather than
a public issue.
