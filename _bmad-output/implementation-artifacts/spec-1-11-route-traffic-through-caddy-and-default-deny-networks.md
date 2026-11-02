---
title: 'Story 1.11: Route traffic through Caddy and default-deny networks'
type: 'feature'
created: '2026-11-02'
status: 'ready-for-dev'
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

**Problem:** No traffic reaches the hosts. AD-2 and AD-26 need Caddy as the only entry point, with one site for the Tenant zone wildcard and one for the Admin hostname, and Compose networks that keep `Host.Hosted` from reaching `Host.Admin`. Esm decided on 2026-11-02 that the Admin site is public on its own hostname, with no VPN and no IP allowlist (`sprint-change-proposal-2026-11-02-public-admin.md`).

**Approach:** Add a pinned Caddy service to `deploy/compose.yaml` as the only service that publishes ports, with a Caddyfile serving the Tenant zone wildcard to `Host.Hosted` and the Admin hostname to `Host.Admin`, refusing every other host, and keeping plain HTTP empty. Give Caddy its own edge networks, extend the Compose config test and the stack check, and update the threat model for the public Admin surface.

## Boundaries & Constraints

**Always:**
- Caddy runs from an image pinned by digest, built or configured in `deploy/`, non-root, read-only root filesystem, `cap_drop: [ALL]` (add only `NET_BIND_SERVICE` if it binds 80 and 443), `no-new-privileges`, `pids_limit` and log rotation, like the other services. It is the only service with published ports: 80 and 443.
- Hostnames come from configuration, not code: the Tenant zone (for example `gatekeep.localhost` locally) and the Admin hostname (for example `admin.gatekeep.localhost`). The Admin hostname is outside the Tenant zone wildcard's reach in Caddy's matching, so a Tenant host never routes to `Host.Admin`.
- Site rules: `*.{zone}` proxies to `Host.Hosted`'s public port; the Admin hostname proxies to `Host.Admin`'s public port; any other host name is refused with no content (TLS handshake failure or an empty fixed response, no proxying, no cookie). Plain HTTP on port 80 returns only a redirect to HTTPS with an empty body and no `Set-Cookie`, for the two sites, and nothing for other hosts.
- TLS mode is configuration: `internal` (Caddy's local CA) for local and CI; a documented production mode using a publicly trusted certificate. The wildcard certificate's DNS-01 provider and its validation-only credential are Story 1.12's install docs; this story leaves a clear configuration seam and does not pick a DNS provider.
- Certificate private keys live only in Caddy's data volume, mounted by Caddy alone, with the directory and key files readable only by Caddy's user.
- Networks: Caddy joins an `edge` network (the only non-internal one, for published ports and later ACME), plus `hosted-edge` (Caddy and `hosted`) and `admin-edge` (Caddy and `admin`), both `internal: true`. `hosted` and `admin` share no network except through PostgreSQL's per-host networks, which hold no other host. `worker`, `postgres` and `openbao` never join an edge network.
- Each host's health port stays unpublished and unreachable from Caddy's networks.
- `docs/threat-model.md`: Z-2, Z-9 and TB-2 drop the VPN; G-13 closes; a new threat records the internet-facing Admin surface and its controls (WebAuthn-only sign-in, fresh assertions, Story 1.20 rate limits and CSP, CSRF and Origin checks, separate hostname and cookies), with the residual risk that a `Host.Admin` flaw is one request away. `docs/install.md` gains the hostnames, ports and TLS settings.

**Never:**
- No VPN, no IP allowlist, no Caddy admin API exposed (`admin off` or bound to localhost inside the container).
- No route from Caddy to `worker`, `postgres`, `openbao` or any health port.
- No DNS provider plugin or credential in this story.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Tenant host | HTTPS to `acme.{zone}` through Caddy | Reaches `Host.Hosted` (its response comes back) | No error expected |
| Admin host | HTTPS to the Admin hostname | Reaches `Host.Admin` | No error expected |
| Outside the zone | HTTPS with SNI and `Host` `evil.example` | No content, no cookie; not proxied | Handshake failure or empty fixed response |
| Zone apex or nested | `{zone}` itself, `a.b.{zone}` | Refused like outside the zone | — |
| Host header mismatch | SNI `acme.{zone}`, `Host` = Admin hostname | Not routed to `Host.Admin` | Refused (misdirected request) |
| Plain HTTP | `http://acme.{zone}/` and `http://{admin}/` | Redirect to HTTPS, empty body, no `Set-Cookie` | — |
| Plain HTTP, other host | `http://evil.example/` | No content, no cookie | — |
| Hosted to Admin | Connect from inside the `hosted` container's network to `admin` on its public and health ports | Unreachable | Connection fails |
| Caddy to internals | Connect from Caddy's network namespace to `worker`, `postgres`, `openbao`, health ports | Unreachable | Connection fails |
| Published ports | Compose config | Only Caddy publishes, and only 80 and 443 | Config test fails otherwise |
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
- [ ] `deploy/caddy/Caddyfile`, Caddy image or service definition -- sites, refusals, HTTP behaviour, TLS mode setting, `admin off`.
- [ ] `deploy/compose.yaml` -- `caddy` service, `edge`, `hosted-edge`, `admin-edge` networks, `caddy-data` and `caddy-config` volumes.
- [ ] `tests/Isolation/Stack/ComposeConfigTests.cs` -- Caddy hardening, only Caddy publishes 80 and 443, edge network membership, Caddy volumes mounted by Caddy alone.
- [ ] `deploy/ci/stack-check.sh` -- every matrix row against the running stack using a client container with `--resolve` and Caddy's internal CA.
- [ ] `docs/install.md`, `docs/threat-model.md` -- hostnames, ports, TLS settings; public Admin threat and closed G-13.

**Acceptance Criteria:**
- Given a host with only Docker, when the stack comes up, then the Tenant zone and the Admin hostname are served over HTTPS by Caddy and nothing else is published.

## Spec Change Log

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (PowerShell, `GATEKEEP_HOST_REPO` set) -- expected: `stack-check: passed.`
