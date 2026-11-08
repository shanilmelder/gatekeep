# Gatekeep

A self-hosted identity and access management platform: sign-in, multi-factor authentication, access control and audit logs over standard protocols, with every project or environment kept apart as its own Tenant.

Gatekeep is a personal project, built and run for its author's own applications, and pre-v1. It is public so the code, the design and the threat model can be read and reviewed. It is not offered as a service, and there are no stability promises yet.

## What's in it

- **Services:** the hosted sign-in pages (`hosted`), the admin API and dashboard (`admin`), background jobs (`worker`), the `cli`, Caddy in front, PostgreSQL for data and OpenBao for keys and secrets.
- **Stack:** .NET 10 (`src/`), React with Vite in a pnpm workspace (`apps/`, `packages/`), Docker Compose (`deploy/`).
- **Tests:** architecture, isolation and browser tests in `tests/`, run inside Docker by CI.

## Running it

Everything runs in Docker. The machine needs Docker with Compose and Git, nothing else.

- **Install a Deployment:** `docs/install.md`.
- **Develop and test:** `deploy/compose.dev.yaml` runs the production stack plus the test services. CI (`.github/workflows/ci.yml`) shows the exact commands.
- **Releases** are signed with cosign and deployed by digest: `docs/release-signing.md`.

## Design and security

- `docs/threat-model.md`: trust boundaries, credential-equivalent values, threats and open gaps.
- `docs/key-custody.md` and `docs/runbooks/`: how keys are held, escrowed and rotated.
- `_bmad-output/`: the brief, PRD, architecture and story specs Gatekeep was built from.

**Found a vulnerability?** Please report it privately through GitHub's [security advisories](../../security/advisories/new), not in a public issue.

## Licence

Apache License 2.0: see `LICENSE`. Third-party material in this repository is listed in `THIRD-PARTY-NOTICES.md`.
