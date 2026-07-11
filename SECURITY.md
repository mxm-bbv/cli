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
| GitHub host key (ed25519) | `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` | docs.github.com |
| Portainer Agent image | `portainer/agent:2.21.5` | Docker Hub |
| Watchtower image | `containrrr/watchtower:1.7.1` | Docker Hub |

## What is verified, and how

- **Docker Engine / Compose / Buildx** — installed from Docker's official apt
  repository. After downloading the signing key we verify its fingerprint
  against the pinned value (`verifyDockerKey`) and **delete it + abort on
  mismatch**, so a MITM'd keyring can't authorise malicious packages. Packages
  are then `signed-by` that verified key.
- **Container images** — pinned to specific version tags, never `:latest`, so a
  repushed tag can't swap the image out. Both agent containers run with
  `--security-opt no-new-privileges` to block setuid-based escalation.
- **Portainer Agent** — does **not** mount `/:/host` (that would expose the
  whole host filesystem); only the docker socket and volume dir it needs.
- **GitHub host key** — added to `known_hosts` only after `ssh-keyscan` output
  is fingerprinted and matched against the pinned value
  (`verifiedGitHubHostKey`) — no trust-on-first-use.
- **Released binaries** — the `install.sh` / self-hosted `deploy/cli.sh`
  installers download `checksums.txt` (or `.sha256`) and **fail closed** unless
  the SHA256 matches. Override only with `FORGE_ALLOW_UNVERIFIED=1`.
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

## Reporting

Found a weakness? Open a private security advisory on the repository rather than
a public issue.
