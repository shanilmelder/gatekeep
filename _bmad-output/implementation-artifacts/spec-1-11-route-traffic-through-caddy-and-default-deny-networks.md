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

**Problem:** No traffic reaches the hosts. AD-2 and AD-26 need Caddy as the only entry point and Compose networks that keep `Host.Hosted` from reaching `Host.Admin`. Esm decided on 2026-11-02 that the Admin site is public on its own hostname, with no VPN and no IP allowlist, served by Caddy like the Tenant sites, with certificates for both by ACME DNS-01 through Cloudflare DNS (`sprint-change-proposal-2026-11-02-public-admin.md`).

**Approach:** Add a pinned Caddy service as the only service that publishes ports, serving the Tenant zone wildcard to `Host.Hosted` and the Admin hostname to `Host.Admin`, refusing every other host, and keeping plain HTTP empty. Give Caddy separate internal networks to each host, extend the Compose config test and the stack check, and update the threat model for the public Admin surface.

## Boundaries & Constraints

**Always:**
- Caddy runs from an image pinned by digest, built or configured in `deploy/`, non-root, read-only root filesystem, `cap_drop: [ALL]` (add only `NET_BIND_SERVICE` if it binds 80 and 443), `no-new-privileges`, `pids_limit` and log rotation, like the other services. It is the only service with published ports: 80 and 443.
- Hostnames come from configuration, not code: the Tenant zone (for example `gatekeep.localhost` locally) and the Admin hostname (for example `admin.gatekeep-admin.localhost` locally). The Admin hostname must not fall under `*.{zone}`; Caddy refuses to start (config validation) if it does, so a Tenant host can never route to `Host.Admin`.
- Caddy site rules: `*.{zone}` proxies to `Host.Hosted`'s public port; the Admin hostname proxies to `Host.Admin`'s public port; any other host name is refused with no content (TLS handshake failure or an empty fixed response, no proxying, no cookie). Plain HTTP on port 80 returns only a redirect to HTTPS with an empty body and no `Set-Cookie` for the two sites, and nothing for other hosts. A request whose `Host` header names one site over a TLS connection for the other is refused.
- TLS mode is configuration for both sites: `internal` (Caddy's local CA) for local and CI, and `cloudflare` for production. In `cloudflare` mode Caddy gets the `*.{zone}` wildcard certificate and the Admin hostname's certificate by ACME DNS-01 through Cloudflare DNS (Esm, 2026-11-02). Caddy is built with the `caddy-dns/cloudflare` module, pinned to an exact version, in a multi-stage Dockerfile from digest-pinned bases.
- NFR-21 still holds: `_acme-challenge.{zone}` and `_acme-challenge.{admin hostname}` are CNAMEs to a separate validation-only Cloudflare zone, and Caddy writes challenge records there through its challenge-domain override. The Cloudflare API token is scoped to `Zone:DNS:Edit` on that validation zone only. It's delivered only as the Compose secret `cloudflare_dns_token`, read from the file, never from an environment variable or command line. In `internal` mode the secret isn't needed, so CI and local runs use no token. Docs tell the Operator to keep both sites' DNS records "DNS only" (not proxied), so Cloudflare never sees Gatekeep traffic.
- Certificate private keys live only in Caddy's data volume, mounted by Caddy alone, with the directory and key files readable only by Caddy's user.
- Networks: Caddy joins `edge` (non-internal, for published ports and ACME), `hosted-edge` (Caddy and `hosted`, internal) and `admin-edge` (Caddy and `admin`, internal). `hosted` and `admin` share no network except through PostgreSQL's per-host networks, which hold no other host. `worker`, `postgres` and `openbao` never join an edge network.
- Each host's health port stays unpublished and unreachable from Caddy's networks.
- `docs/threat-model.md`: Z-2, Z-9 and TB-2 drop the VPN; G-13 closes; a new threat records the internet-facing Admin surface and its controls (WebAuthn-only sign-in, fresh assertions, Story 1.20 rate limits and CSP, CSRF and Origin checks, separate hostname and cookies), with the residual risk that a `Host.Admin` flaw is one request away. `docs/install.md` gains the zone, the Admin hostname, ports, Caddy TLS settings and the Cloudflare DNS setup: the validation-only zone, both `_acme-challenge` CNAMEs, "DNS only" records, CAA records, and creating the scoped API token. The threat model gets a credential row for the DNS token, which can issue certificates for both sites while it lives.

**Never:**
- No VPN, no IP allowlist, no Cloudflare Tunnel, no Caddy admin API exposed (`admin off` or bound to localhost inside the container).
- No route from Caddy to `worker`, `postgres`, `openbao` or any health port.
- No Cloudflare account, token or zone ID in the repository, CI or tests, and no CI step that calls Cloudflare.
- No DNS provider plugin or credential in this story.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Tenant host | HTTPS to `acme.{zone}` through Caddy | Reaches `Host.Hosted` (its response comes back) | No error expected |
| Admin host | HTTPS to the Admin hostname | Reaches `Host.Admin` | No error expected |
| Admin under the zone | Admin hostname configured under `*.{zone}` | Caddy refuses to start | Config error names the setting |
| Outside the zone | HTTPS with SNI and `Host` `evil.example` | No content, no cookie; not proxied | Handshake failure or empty fixed response |
| Zone apex or nested | `{zone}` itself, `a.b.{zone}` | Refused like outside the zone | — |
| Host header mismatch | SNI `acme.{zone}`, `Host` = Admin hostname | Not routed to `Host.Admin` | Refused (misdirected request) |
| Plain HTTP | `http://acme.{zone}/` and `http://{admin}/` | Redirect to HTTPS, empty body, no `Set-Cookie` | — |
| Plain HTTP, other host | `http://evil.example/` | No content, no cookie | — |
| Hosted to Admin | Connect from inside the `hosted` container's network to `admin` on its public and health ports | Unreachable | Connection fails |
| Caddy to internals | Connect from Caddy's network namespace to `worker`, `postgres`, `openbao`, health ports | Unreachable | Connection fails |
| Published ports | Compose config | Only Caddy publishes, and only 80 and 443 | Config test fails otherwise |
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
- [ ] `deploy/caddy/Caddyfile`, `deploy/docker/caddy.Dockerfile` -- Tenant zone and Admin sites, refusals, HTTP behaviour, TLS mode (`internal` or `cloudflare`, with the challenge-domain override), `admin off`; Caddy built with the pinned `caddy-dns/cloudflare` module.
- [ ] `deploy/compose.yaml` -- `caddy` service, `edge`, `hosted-edge`, `admin-edge` networks, `caddy-data` and `caddy-config` volumes, the `cloudflare_dns_token` secret.
- [ ] `tests/Isolation/Stack/ComposeConfigTests.cs` -- Caddy hardening, only Caddy publishes 80 and 443, edge network membership, Caddy volumes and the DNS token mounted by Caddy alone.
- [ ] `deploy/ci/stack-check.sh` -- every matrix row against the running stack using a client container with `--resolve` and Caddy's internal CA.
- [ ] `docs/install.md`, `docs/threat-model.md` -- hostnames, ports, TLS settings; public Admin threat and closed G-13.

**Acceptance Criteria:**
- Given a host with only Docker, when the stack comes up, then the Tenant zone and the Admin hostname are served over HTTPS by Caddy and nothing else is published.

## Spec Change Log

- **2026-11-02, before review (Esm):** Caddy serves the Admin panel too, with its certificate by DNS-01 through Cloudflare. The Cloudflare Tunnel is dropped. Superseded: `cloudflared`, `cloudflare-egress`, `cloudflare_tunnel_token`.

- **2026-11-02, before review (Esm):** Tenant zone certificates use ACME DNS-01 through Cloudflare DNS, with a token scoped to a validation-only zone. This replaces "does not pick a DNS provider".
- **2026-11-02, before review (Esm):** the Admin panel is reached through a Cloudflare Tunnel, which provides its TLS and DNS. Caddy no longer serves the Admin hostname; a `cloudflared` service forwards it to `Host.Admin`. Superseded: the Caddy Admin site, and `admin-edge` shared with Caddy.

## Review Triage Log

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (PowerShell, `GATEKEEP_HOST_REPO` set) -- expected: `stack-check: passed.`
