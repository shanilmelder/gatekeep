# Sprint Change Proposal: public Admin site

Date: 2026-11-02. Raised by Esm during Story 1.11. Mode: batch. Approved by Esm ("yes, no allowlist").

## 1. Issue summary

**Trigger:** Story 1.11. Its first criterion served Admin traffic only on a VPN interface. The VPN was never designed (threat model G-13), and since the Docker-only decision it could not be a host service.

**Decision (Esm, 2026-11-02):** the Admin site, which serves both the Admin Dashboard and the Management API, is public. It has its own public hostname and a publicly trusted certificate, separate from every Tenant host. There is no IP allowlist.

**Kind:** a deployment decision by the owner. Esm confirmed it after the risk was explained.

## 2. Impact analysis

- **Security:** an internet-facing flaw in `Host.Admin` is no longer stopped by network position. AD-2 named that as the risk it prevents. The remaining controls are:
  - WebAuthn-only Admin sign-in (FR-46);
  - fresh assertions for sensitive actions;
  - rate limits and the Admin CSP (Story 1.20);
  - CSRF and Origin checks (NFR-4);
  - the separate hostname and cookies;
  - `Host.Hosted` still having no route to `Host.Admin` inside Docker.
- **Threat model (updated in Story 1.11):**
  - Z-2, TB-2 and Z-9 lose the VPN.
  - G-13 closes, because there is no VPN.
  - A new threat records the internet-facing Admin surface. Code execution through a `Host.Admin` flaw gives the attacker Z-2.
  - Story 18.9's security gate must review it.
- **Stories:**
  - Story 1.11: criterion 1 and the "so that" line change.
  - Story 1.20 (rate limiter and Admin CSP): unchanged, but now carries more weight.
  - No other story's criteria name the VPN.
- **PRD:** FR-46's hostname line, §10's dependency list and A-13 change.
- **Architecture:** AD-2's `Host.Admin` line, AD-26's Caddy line, the deployment diagram and AR-13 change.
- **UX:** two lines in `EXPERIENCE.md` drop "VPN only" and "over VPN".

## 3. Recommended approach

**Direct adjustment.** The text edits below have been applied. Story 1.11 builds the public Admin site in Caddy.

## 4. Changes applied

| Artifact | Old | New |
|---|---|---|
| PRD FR-46 | "...reachable only by VPN or private network." | "...on its own public hostname, outside every Tenant's origin." |
| PRD §10 | "VPN or private network access to the Admin Dashboard." | "A public DNS name and TLS certificate for the Admin Dashboard." |
| PRD A-13 | "The Management API is reachable only by VPN or private network." | "...reachable on the Admin hostname, which is public." |
| AD-2 | "`Host.Admin` ... listens only on the private network." | "...reachable only through Caddy's Admin site on its own public hostname," with the amendment note. |
| AD-26 | "the Admin hostname on the VPN interface, with a certificate from Caddy's internal CA" | "the public Admin hostname, with its own publicly trusted certificate" |
| Deployment diagram | `-->|VPN|` | `-->|HTTPS|` |
| AR-13, epics FR-46 | private network, VPN | public Admin hostname |
| Story 1.11 | "...never exposed publicly", "served only on the VPN interface" | "...reached only through its own hostname, never through a Tenant host", "served only on the Admin hostname" |
| UX `EXPERIENCE.md` | "VPN only", "over VPN" | removed |

## 5. Implementation handoff

**Scope: minor to moderate.** The work is done within Story 1.11, with the threat model updated in the same pull request.
