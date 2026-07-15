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
| GitHub host key (ed25519) | `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` | docs.github.com |
| forge release minisign key | `RWSk3LOux6EkxZOpVER2fnvn2WKOHPBPG128iEhEy3JGztPOte98a+3C` | this repo (`pins.go`) |
| Portainer Agent image | `portainer/agent:2.39.1` (keep in lockstep with your Portainer Server) | Docker Hub |
| Watchtower image | `containrrr/watchtower:1.7.1` | Docker Hub |

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
  fingerprint-verified fail-closed, same as Docker's. The auth key is prompted
  at runtime and never written to disk or logs.
- **DOCKER-USER firewall** — Docker inserts its own iptables chains ahead of
  UFW's INPUT rules, so `ufw default deny incoming` does **not** protect
  `-p`-published container ports. forge installs a persistent DOCKER-USER
  policy (systemd oneshot, reapplied after docker starts): external traffic
  reaches containers only on 80/443 (plus 9001 in the discouraged public agent
  mode); the tailnet interface is trusted. Note the port matched is the
  *container* port (DNAT runs first) — publish services on matching ports.
- **Watchtower** — runs `--monitor-only`. An auto-updater holding the docker
  socket is a supply-chain risk: it would replace your containers with whatever
  a registry serves next. It reports; you update deliberately.
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
  The SSH-login notice is wired through `/etc/ssh/sshrc` (backgrounded,
  best-effort) rather than PAM, so a failure there can never block a login.
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
