---
title: 'Story 1.11: Route traffic through Caddy and default-deny networks'
type: 'feature'
created: '2026-11-02'
status: 'done'
baseline_revision: '5984088ad227d720bbdcface517e779460708704'
review_loop_iteration: 0
followup_review_recommended: true
context:
  - '{project-root}/_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-02-public-admin.md'
  - '{project-root}/_bmad-output/planning-artifacts/sprint-change-proposal-2026-11-02-docker-only.md'
  - '{project-root}/docs/threat-model.md'
  - '{project-root}/docs/install.md'
warnings: [oversized]
deferred:
  - summary: >-
      Cloudflare mode is proven only offline.
    evidence: |-
      No real certificate has been issued; prove it on the first real install.
    location: >-
      deploy/caddy/tls-cloudflare.caddy
    severity: low
  - summary: >-
      Forwarded-header trust and real client IPs are undecided.
    evidence: |-
      Rate limits (Story 1.20) need the real client address behind Caddy.
    location: >-
      src/Adapters/Hosting/GatekeepHosting.cs
    severity: medium
  - summary: >-
      No edge access log.
    evidence: |-
      Caddy logs could record sensitive query values (T-42); decide with the logging and alerts work.
    location: >-
      deploy/caddy/Caddyfile
    severity: medium
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
- NFR-21 still holds: `_acme-challenge.{zone}` and `_acme-challenge.{admin hostname}` are CNAMEs to a separate validation-only Cloudflare zone, and Caddy writes challenge records there through its challenge-domain override. The Cloudflare API token is scoped to `Zone:DNS:Edit` and `Zone:Read` on that validation zone only. It's delivered only as the Compose secret `cloudflare_dns_token`, read from the file, never from an environment variable or command line. In `internal` mode the secret isn't needed, so CI and local runs use no token. Docs tell the Operator to keep both sites' DNS records "DNS only" (not proxied), so Cloudflare never sees Gatekeep traffic.
- Certificate private keys live only in Caddy's data volume, mounted by Caddy alone, with the directory and key files readable only by Caddy's user.
- Networks: Caddy joins `edge` (non-internal, for published ports and ACME), `hosted-edge` (Caddy and `hosted`, internal) and `admin-edge` (Caddy and `admin`, internal). `hosted` and `admin` share no network except through PostgreSQL's per-host networks, which hold no other host. `worker`, `postgres` and `openbao` never join an edge network.
- Each host's health port stays unpublished and unreachable from Caddy's networks.
- `docs/threat-model.md`: Z-2, Z-9 and TB-2 drop the VPN; G-13 closes; a new threat records the internet-facing Admin surface and its controls (WebAuthn-only sign-in, fresh assertions, Story 1.20 rate limits and CSP, CSRF and Origin checks, separate hostname and cookies), with the residual risk that a `Host.Admin` flaw is one request away. `docs/install.md` gains the zone, the Admin hostname, ports, Caddy TLS settings and the Cloudflare DNS setup: the validation-only zone, both `_acme-challenge` CNAMEs, "DNS only" records, CAA records, and creating the scoped API token. The threat model gets a credential row for the DNS token, which can issue certificates for both sites while it lives.

**Never:**
- No VPN, no IP allowlist, no Cloudflare Tunnel, no Caddy admin API exposed (`admin off` or bound to localhost inside the container).
- No route from Caddy to `worker`, `postgres`, `openbao` or any health port.
- No Cloudflare account, token or zone ID in the repository, CI or tests, and no CI step that calls Cloudflare.
- No DNS provider other than Cloudflare, and no DNS credential with access beyond the validation-only zone.

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
- [x] `deploy/caddy/Caddyfile`, `deploy/docker/caddy.Dockerfile` -- Tenant zone and Admin sites, refusals, HTTP behaviour, TLS mode (`internal` or `cloudflare`, with the challenge-domain override), `admin off`; Caddy built with the pinned `caddy-dns/cloudflare` module.
- [x] `deploy/compose.yaml` -- `caddy` service, `edge`, `hosted-edge`, `admin-edge` networks, `caddy-data` and `caddy-config` volumes, the `cloudflare_dns_token` secret.
- [x] `tests/Isolation/Stack/ComposeConfigTests.cs` -- Caddy hardening, only Caddy publishes 80 and 443, edge network membership, Caddy volumes and the DNS token mounted by Caddy alone.
- [x] `deploy/ci/stack-check.sh` -- every matrix row against the running stack using a client container with `--resolve` and Caddy's internal CA.
- [x] `docs/install.md`, `docs/threat-model.md` -- hostnames, ports, TLS settings; public Admin threat and closed G-13.

**Acceptance Criteria:**
- Given a host with only Docker, when the stack comes up, then the Tenant zone and the Admin hostname are served over HTTPS by Caddy and nothing else is published.

## Spec Change Log

- **2026-11-02, implementation:** removed the stale "no DNS provider plugin" line left from before the Cloudflare DNS decision; the token also needs `Zone:Read` on the validation zone so the module can find it.

- **2026-11-02, before review (Esm):** Caddy serves the Admin panel too, with its certificate by DNS-01 through Cloudflare. The Cloudflare Tunnel is dropped. Superseded: `cloudflared`, `cloudflare-egress`, `cloudflare_tunnel_token`.

- **2026-11-02, before review (Esm):** Tenant zone certificates use ACME DNS-01 through Cloudflare DNS, with a token scoped to a validation-only zone. This replaces "does not pick a DNS provider".
- **2026-11-02, before review (Esm):** the Admin panel is reached through a Cloudflare Tunnel, which provides its TLS and DNS. Caddy no longer serves the Admin hostname; a `cloudflared` service forwards it to `Host.Admin`. Superseded: the Caddy Admin site, and `admin-edge` shared with Caddy.

## Review Triage Log

### 2026-11-02 — Review pass
- verdicts: 40 findings — high 6, medium 12, low 18, false 4, maybe-false 0
- findings:
  - `[false]` `[reject]` Intent: the under-zone refusal lives in the entrypoint, not Caddy's own config — the entrypoint is the image's only way in, and the intent asks that Caddy refuse to start, which it does.
  - `[false]` `[reject]` Intent: health-port isolation is an application bind, not a network rule — the intent asks that it be unreachable from Caddy's networks, by any means; the stack check proves it.
  - `[low]` `[reject]` Intent: published ports can be changed — defaults are 80 and 443 and the config test checks them; the override exists for machines where 80 is taken.
  - `[low]` `[defer]` Intent: refusals and certificates are proven only in `internal` mode — `cloudflare` mode needs real zones and a real CA; prove it on the first real install (Stories 1.12, 18.11).
  - `[false]` `[reject]` Intent: key modes are checked only by the stack check — the matrix row names config and stack checks, and both exist.
  - `[low]` `[patch]` Intent: OpenBao and Worker's other ports aren't probed from Caddy — probes added.
  - `[high]` `[patch]` Blind: code in `hosted` can reach `Host.Admin` through Caddy with SNI set to the Admin hostname, so "no route" is false — fixed edge subnets, each site aborts the other host's subnet, stack-check case, threat model corrected.
  - `[medium]` `[patch]` Blind: `GATEKEEP_ACME_EMAIL` is substituted into the Caddyfile unchecked — strict address pattern.
  - `[low]` `[patch]` Blind: the token check passes a file Caddy can't read — `-r` and non-whitespace required.
  - `[low]` `[patch]` Blind: Caddy's healthcheck says nothing about certificates — documented.
  - `[medium]` `[patch]` Blind: no test for a client with no SNI or connecting by IP — cases added, empty SNI rejected if Caddy falls back.
  - `[low]` `[patch]` Blind: `edge` gives Caddy unrestricted egress — recorded as a residual risk; it's needed for ACME and the Cloudflare API.
  - `[medium]` `[defer]` Blind: client IPs and forwarded headers are unhandled — trusted-proxy handling is Story 1.20's decision with the rate limiter; the `AAAA` advice is dropped or its Docker IPv6 need stated now.
  - `[medium]` `[patch]` Blind: no HSTS on the public sites, and no edge access log — HSTS added without `includeSubDomains`; the access log is deferred because it could record sensitive query values (T-42).
  - `[low]` `[patch]` Blind: a failed cloudflare validation hides its output — printed on failure.
  - `[medium]` `[patch]` Blind: offline validation checks rewritten copies — the shipped files are validated with a placeholder token at the real path.
  - `[low]` `[patch]` Blind: the loopback health bind has no unit test — test added.
  - `[low]` `[patch]` Blind: the under-zone test is a string match — the stack check now runs every refusal, and the threat model cites it.
  - `[low]` `[patch]` Blind: `/config` owner and modes unchecked — checked.
  - `[low]` `[patch]` Blind: no total-length limit on names — 253 characters.
  - `[medium]` `[patch]` Blind: a zone under the Admin hostname is accepted — refused.
  - `[medium]` `[patch]` Gap: start.sh's name check never runs on a bad value — the stack check loops over bad values and asserts each refusal names its setting.
  - `[medium]` `[patch]` Gap: which challenge domain each site uses is checked only as text — `caddy adapt` output asserted per site.
  - `[high]` `[patch]` Gap (other): a value with a newline passes `check_name` and can inject Caddyfile tokens — any character outside `[a-z0-9.-]` is refused.
  - `[high]` `[patch]` Edge: newline in a name passes the check — same fix as the Gap row.
  - `[high]` `[patch]` Edge: a newline tail bypasses the under-zone refusal — same fix.
  - `[medium]` `[patch]` Edge: the ACME email goes into the Caddyfile unchecked — same fix as the Blind row.
  - `[low]` `[patch]` Edge: IP-like names pass — refused.
  - `[low]` `[patch]` Edge: no total-length limit — same fix as the Blind row.
  - `[low]` `[patch]` Edge: an unreadable or blank token file passes — same fix as the Blind row.
  - `[medium]` `[patch]` Edge: challenge domains aren't compared with the sites or each other — refused when equal or under.
  - `[low]` `[patch]` Edge: the getcap guard passes when getcap is missing — required and captured.
  - `[medium]` `[patch]` Edge: a client with no SNI is untested — same fix as the Blind row.
  - `[low]` `[patch]` Edge: `Host` with a port or mixed case is untested — cases added.
  - `[low]` `[patch]` Edge: `getent` returning nothing gives a misleading failure — guarded.
  - `[medium]` `[patch]` Edge: `GATEKEEP_TLS_MODE` in `.env` is ignored — Compose and docs made consistent.
  - `[high]` `[patch]` Edge (claim): Hosted reaches Admin through Caddy — same fix as the Blind row.
  - `[high]` `[patch]` Edge (claim): TB-3 overstates isolation — corrected with the fix.
  - `[false]` `[reject]` Edge (claim): `compose.yaml` lacks the DNS token secret — it lives in the production override by design, so local and CI runs need no token.
  - `[low]` `[patch]` Edge: the loopback health contract has no unit test — same fix as the Blind row.

## Verification

**Commands:**
- `docker compose -f deploy/compose.test.yaml run --rm --build tests` -- expected: build with no warnings; Architecture and Isolation all pass.
- `docker compose -f deploy/compose.test.yaml run --rm --build stack` (PowerShell, `GATEKEEP_HOST_REPO` set) -- expected: `stack-check: passed.`

## Auto Run Result

Status: done

**Summary:** Caddy is the only service that publishes ports. It serves the Tenant zone wildcard to `Host.Hosted` and the public Admin hostname to `Host.Admin`, refuses every other name, keeps plain HTTP to a bare redirect and sets HSTS. Certificates come from its internal CA locally and in CI, and by ACME DNS-01 through Cloudflare DNS in production, with a token limited to a validation-only zone. Separate edge networks, client-subnet refusals and loopback health ports keep `Host.Hosted` from reaching `Host.Admin` directly or through Caddy.

**Files:** `deploy/caddy/`, `deploy/docker/caddy.Dockerfile`, `deploy/compose.yaml`, `deploy/compose.cloudflare.yaml`, `deploy/ci/stack-check.sh`; `src/Adapters/Hosting/GatekeepHosting.cs`; `tests/Isolation/Stack/ComposeConfigTests.cs`, `tests/Isolation/Hosting/HostStartupTests.cs`; `docs/install.md`, `docs/threat-model.md`; `.gitattributes`.

**Review:** 40 findings across four layers: 33 patched, 2 deferred, 5 rejected, each with its reason in the triage log.

**Follow-up review:** recommended. A high finding (Hosted reaching Admin through Caddy) was patched with subnet refusals that only the stack check exercises.

**Verification:** see the PR screenshot; inside Docker, the tests container passes and the stack check passes every routing row.

**Residual risks:** the Admin surface faces the internet (T-47). Caddy has outbound access for ACME. Cloudflare mode hasn't issued a real certificate yet. Client IPs behind Caddy are undecided until Story 1.20.
