---
title: 'Story 1.11: Route traffic through Caddy and default-deny networks'
type: 'feature'
created: '2026-11-02'
status: 'in-progress'
baseline_revision: '5984088ad227d720bbdcface517e779460708704'
review_loop_iteration: 0
followup_review_recommended: false
context:
  - '{project-root}/_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-02-public-admin.md'
  - '{project-root}/_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-02-docker-only.md'
  - '{project-root}/docs/threat-model.md'
  - '{project-root}/docs/install.md'
warnings: [oversized]
deferred: []
---

<intent-contract>

## Intent

**Problem:** No traffic reaches the hosts. AD-2 and AD-26 need one entry point per surface and Compose networks that keep `Host.Hosted` from reaching `Host.Admin`. Esm decided on 2026-11-02 that the Admin site is public on its own hostname, with no VPN and no IP allowlist, and that the Admin panel is reached through a Cloudflare Tunnel, which provides its TLS and DNS (`sprint-change-proposal-2026-11-02-public-admin.md`).

**Approach:** Add a pinned Caddy service as the only service that publishes ports, serving the Tenant zone wildcard to `Host.Hosted`, refusing every other host, and keeping plain HTTP empty. Add a pinned `cloudflared` service that connects outbound to Cloudflare and forwards the Admin hostname to `Host.Admin` over an internal network, with its tunnel token as a Compose secret. Extend the Compose config test and the stack check, and update the threat model for the public Admin surface and Cloudflare.

## Boundaries & Constraints

**Always:**
- Caddy runs from an image pinned by digest, built or configured in `deploy/`, non-root, read-only root filesystem, `cap_drop: [ALL]` (add only `NET_BIND_SERVICE` if it binds 80 and 443), `no-new-privileges`, `pids_limit` and log rotation, like the other services. It is the only service with published ports: 80 and 443.
- Hostnames come from configuration, not code: the Tenant zone (for example `gatekeep.localhost` locally) and the Admin hostname (set in the Cloudflare dashboard and in Gatekeep's configuration). Caddy has no route to `Host.Admin` at all, so a Tenant host never reaches it.
- Caddy site rules: `*.{zone}` proxies to `Host.Hosted`'s public port; any other host name, including the Admin hostname, is refused with no content (TLS handshake failure or an empty fixed response, no proxying, no cookie). Plain HTTP on port 80 returns only a redirect to HTTPS with an empty body and no `Set-Cookie` for the zone, and nothing for other hosts.
- Admin path: a `cloudflared` service, image pinned by digest and hardened like the rest (non-root, read-only, no capabilities, `no-new-privileges`, `pids_limit`, log rotation), runs a remotely managed tunnel from its token, delivered only as a Compose secret (`cloudflare_tunnel_token`) and read from that file, never from an environment variable or command line. It joins `admin-edge` (internal, with `admin` only) and `cloudflare-egress` (its outbound network, joined by nothing else). It publishes no port. The ingress to `http://admin:<public port>` is configured in the Cloudflare dashboard and documented in `docs/install.md`. The stack runs without the tunnel when no token is set (the Admin panel is then unreachable from outside), and CI runs without it.
- TLS mode is configuration for the Tenant zone: `internal` (Caddy's local CA) for local and CI, and `cloudflare` for production. In `cloudflare` mode Caddy gets the `*.{zone}` wildcard certificate by ACME DNS-01 through Cloudflare DNS (Esm, 2026-11-02). Caddy is built with the `caddy-dns/cloudflare` module, pinned to an exact version, in a multi-stage Dockerfile from digest-pinned bases.
- NFR-21 still holds: `_acme-challenge.{zone}` is a CNAME to a separate validation-only Cloudflare zone, and Caddy writes challenge records there through its challenge-domain override. The Cloudflare API token is scoped to `Zone:DNS:Edit` on that validation zone only. It's delivered only as the Compose secret `cloudflare_dns_token`, read from the file, never from an environment variable or command line. In `internal` mode the secret isn't needed, so CI and local runs use no token. Admin TLS and DNS belong to Cloudflare through the tunnel.
- Certificate private keys live only in Caddy's data volume, mounted by Caddy alone, with the directory and key files readable only by Caddy's user.
- Networks: Caddy joins `edge` (non-internal, for published ports and later ACME) and `hosted-edge` (Caddy and `hosted`, internal). `cloudflared` joins `cloudflare-egress` (non-internal) and `admin-edge` (`cloudflared` and `admin`, internal). Caddy never joins `admin-edge`; `cloudflared` never joins `hosted-edge`. `hosted` and `admin` share no network except through PostgreSQL's per-host networks, which hold no other host. `worker`, `postgres` and `openbao` never join an edge network.
- Each host's health port stays unpublished and unreachable from Caddy's networks.
- `docs/threat-model.md`: Z-2, Z-9 and TB-2 drop the VPN and add Cloudflare; G-13 closes; a new threat records the internet-facing Admin surface and its controls (WebAuthn-only sign-in, fresh assertions, Story 1.20 rate limits and CSP, CSRF and Origin checks, separate hostname and cookies), with the residual risk that a `Host.Admin` flaw is one request away. Another records that Cloudflare terminates Admin TLS and sees Admin traffic in plaintext, and that the tunnel token lets its holder receive Admin traffic (with a credential row for it). It also notes that Admin access depends on Cloudflare, a cloud service outside FR-1's core runtime. `docs/install.md` gains the zone, ports, Caddy TLS settings, the tunnel setup, and the Cloudflare DNS setup: the validation-only zone, the `_acme-challenge` CNAME, CAA records, and creating the scoped API token. The threat model gets a credential row for the DNS token, which can issue certificates for the zone while it lives.

**Never:**
- No VPN, no IP allowlist, no Caddy admin API exposed (`admin off` or bound to localhost inside the container), no `cloudflared` metrics port published.
- No route from Caddy to `admin`, `worker`, `postgres`, `openbao` or any health port, and none from `cloudflared` to anything but `admin`'s public port.
- No Cloudflare account, token, zone ID or tunnel ID in the repository, CI or tests, and no CI step that calls Cloudflare.
- No DNS provider plugin or credential in this story.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Tenant host | HTTPS to `acme.{zone}` through Caddy | Reaches `Host.Hosted` (its response comes back) | No error expected |
| Admin host via Caddy | HTTPS to the Admin hostname at Caddy | Not routed to `Host.Admin` | Refused like outside the zone |
| Tunnel path | From `cloudflared`'s network namespace, connect to `admin`'s public port | Reaches `Host.Admin` | No error expected |
| Tunnel limits | From `cloudflared`'s namespace, connect to `hosted`, `worker`, `postgres`, `openbao` and health ports | Unreachable | Connection fails |
| No token | Stack up with no tunnel token set | Everything else healthy; `cloudflared` not started or idle | No secret value in any log |
| Outside the zone | HTTPS with SNI and `Host` `evil.example` | No content, no cookie; not proxied | Handshake failure or empty fixed response |
| Zone apex or nested | `{zone}` itself, `a.b.{zone}` | Refused like outside the zone | — |
| Host header mismatch | SNI `acme.{zone}`, `Host` = Admin hostname | Not routed to `Host.Admin` | Refused (misdirected request) |
| Plain HTTP | `http://acme.{zone}/` | Redirect to HTTPS, empty body, no `Set-Cookie` | — |
| Plain HTTP, other host | `http://evil.example/` | No content, no cookie | — |
| Hosted to Admin | Connect from inside the `hosted` container's network to `admin` on its public and health ports | Unreachable | Connection fails |
| Caddy to internals | Connect from Caddy's network namespace to `worker`, `postgres`, `openbao`, health ports | Unreachable | Connection fails |
| Published ports | Compose config | Only Caddy publishes, and only 80 and 443; `cloudflared` publishes nothing | Config test fails otherwise |
| DNS token | Compose config and running Caddy in `internal` mode | `cloudflare_dns_token` mounted only into Caddy, as a secret; Caddy starts healthy without it in `internal` mode | Config test fails otherwise |
| Key files | Inside Caddy's data volume | Directory and private keys owned by Caddy's user, mode no wider than `0600`/`0700`; volume mounted only by Caddy | Config and stack checks fail otherwise |

</intent-contract>

## Code Map

- `deploy/compose.yaml` -- services `postgres`, `postgres-passwords`, `openbao`, `hosted`, `admin`, `worker`, `cli`, one-shot setup tools; `x-hardened` anchor with `pids_limit` and logging; networks `hosted`, `admin`, `worker`, `tools`, all internal; no published ports today.
- `src/Adapters/Hosting/HostSettings.cs:12-83`, `GatekeepHosting.cs:60-62` -- `HostProfile.HasPublicEndpoint`; Hosted and Admin listen on `Gatekeep:PublicPort` (default 8080) besides health (8081).
- `deploy/ci/stack-check.sh`, `deploy/compose.test.yaml` (`stack` service) -- the end-to-end check run in a container; extend it. Run it from PowerShell locally with `GATEKEEP_HOST_REPO=/run/desktop/mnt/host/d/Projects/Personal/gatekeep`.
- `tests/Isolation/Stack/ComposeConfigTests.cs` -- parses `docker compose config`; extend for Caddy, ports and network membership.
- `tests/Architecture/DockerOnlyRuleTests.cs` -- docs and `deploy/` must hold only Docker commands.
- `docs/threat-model.md` -- Z-2, Z-9, TB-2, G-13, the credential rows for TLS keys and the Caddy internal CA.
- Verification runs only in Docker: `docker compose -f deploy/compose.test.yaml run --rm --build tests` and the `stack` service.

## Tasks & Acceptance

**Execution:**
- [ ] `deploy/caddy/Caddyfile`, `deploy/docker/caddy.Dockerfile` -- Tenant zone site, refusals, HTTP behaviour, TLS mode (`internal` or `cloudflare`, with the challenge-domain override), `admin off`; Caddy built with the pinned `caddy-dns/cloudflare` module.
- [ ] `deploy/compose.yaml` -- `caddy` and `cloudflared` services, `edge`, `hosted-edge`, `admin-edge`, `cloudflare-egress` networks, `caddy-data` and `caddy-config` volumes, the `cloudflare_tunnel_token` secret.
- [ ] `tests/Isolation/Stack/ComposeConfigTests.cs` -- Caddy and `cloudflared` hardening, only Caddy publishes 80 and 443, edge network membership, Caddy volumes mounted by Caddy alone, the token only as a secret to `cloudflared`.
- [ ] `deploy/ci/stack-check.sh` -- every matrix row against the running stack using a client container with `--resolve` and Caddy's internal CA.
- [ ] `docs/install.md`, `docs/threat-model.md` -- hostnames, ports, TLS settings; public Admin threat and closed G-13.

**Acceptance Criteria:**
- Given a host with only Docker, when the stack comes up, then the Tenant zone is served over HTTPS by Caddy, nothing else is published, and `Host.Admin` is reachable only from `cloudflared`'s network.

## Spec Change Log

- **2026-11-02, before review (Esm):** Tenant zone certificates use ACME DNS-01 through Cloudflare DNS, with a token scoped to a validation-only zone. This replaces "does not pick a DNS provider".
- **2026-11-02, before review (Esm):** the Admin panel is reached through a Cloudflare Tunnel, which provides its TLS and DNS. Caddy no longer serves the Admin hostname; a `cloudflared` service forwards it to `Host.Admin`. Superseded: the Caddy Admin site, and `admin-edge` shared with Caddy.

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (PowerShell, `GATEKEEP_HOST_REPO` set) -- expected: `stack-check: passed.`
