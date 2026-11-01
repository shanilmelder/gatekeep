# IAM market digest

Web research from 2026-11-01. Buyer targeting is inferred unless a source is linked. Vendor trust centres weren't checked, and Reddit was inaccessible.

## Vendors

| Vendor | Model | Pricing shape | Likely buyer |
|---|---|---|---|
| [Auth0](https://auth0.com/pricing) | Hosted | Free to 25K MAU; B2B Professional $800 at 500 MAU | Developers, enterprise |
| [Clerk](https://clerk.com/changelog/2026-02-05-new-plans-more-value) | Hosted | 50K retained users free; [Pro about $25](https://clerk.com/pricing.md) | Startups |
| [WorkOS](https://workos.com/pricing.md) | Hosted | 1M MAU free; SSO $125 per connection | B2B SaaS |
| [Stytch](https://stytch.com/pricing) ([Twilio](https://stytch.com/docs/resources/changelog)) | Hosted | 10K MAU/agents free; 5 SSO connections | Developers |
| [Descope](https://www.descope.com/pricing) | Hosted | 7.5K MAU free; Pro from $249 | Developers |
| [Cognito](https://aws.amazon.com/cognito/pricing/) | Hosted | 10K MAU free; [rates third-party](https://blog.logto.io/amazon-cognito-pricing) | AWS shops |
| [Keycloak](https://www.cncf.io/blog/2023/04/11/keycloak-joins-cncf-as-an-incubating-project/) | Self-hosted, CNCF | Free; licence unconfirmed | Workforce, platform teams |
| [Ory](https://www.ory.com/pricing) | Both | From $770/yr; per aDAU; licence unconfirmed | Platform engineers |
| [Zitadel](https://zitadel.com/pricing) | Both, [AGPL](https://zitadel.com/blog/apache-to-agpl) | 100 DAU free; Pro $100 | Multi-tenant builders |
| [Authentik](https://goauthentik.io/pricing) | Self-hosted only | $5/user, $0.02/external | Workforce |
| [Logto](https://logto.io/pricing) | Both; [MPL per third party](https://guptadeepak.com/ciam-compass/vendors/logto/) | 50K MAU free; Pro $24 plus add-ons | Small teams |

## Complaints

- **Auth0:** the [15.5x bill jump](https://stytch.com/blog/auth0-reviews/) is one anecdote repeated by competitors. A [233% rise](https://costbench.com/changelog/auth0-price-increase-2026-04/) is unverified.
- **Keycloak:** [breaking upgrades](https://forum.keycloak.org/t/keycloack-upgrade/27304), [rolling-upgrade Infinispan failures](https://github.com/bitnami/charts/issues/31072) and [database-held config](https://news.ycombinator.com/item?id=41197363). The HN threads are mostly old.
- **Cognito:** [no password-hash export](https://www.repost.aws/it/questions/QUhOXGdmb1QWinQXjfVdl1mw/migrate-users-from-cognito-user-pool-to-custom-authenticator), per an ageing answer.
- **Clerk:** [repeated 2026 outages](https://clerk.com/blog/2026-03-10-service-outage-postmortem). No lock-in evidence found.

## Trust baseline

- **Compliance:** [SOC 2 is the most-requested framework](https://startwithidentity.com/articles/b2b-saas-security-tools-enterprise-procurement/), with the [Type II report shared under NDA](https://ssojet.com/blog/enterprise-authentication-buyers-checklist-15-questions). Both sources are vendors. ISO 27001 is less universal: [Clerk reportedly lacks it](https://clerk.com/articles/can-clerk-handle-enterprise-requirements).
- **OpenID Foundation certification:** [$3,500 per deployment for non-members, $700 for members](https://openid.net/certification/fees/), with [free certification for qualifying open source](https://openid.net/certification/third-party-support-certification-policy/) (attribution unconfirmed).
- **Uptime:** 99.99% on enterprise tiers ([Auth0](https://manage.panasonic.auth0.com/docs/support/services-level-descriptions), [Stytch](https://stytch.com/pricing), [Ory](https://www.ory.com/pricing), [Zitadel](https://zitadel.com/pricing)).
- **Penetration testing:** unconfirmed; no buyer-side requirement found.

## Incidents

- [Okta 2023](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/): support-system access exposed session tokens for 134 customers; [scope later widened](https://www.itnews.com.au/news/oktas-data-breach-bigger-than-first-thought-602953).
- [Storm-0558](https://cyberscoop.com/microsoft-csrb-china-hacking/): a stale signing key was used to forge tokens.
- [Entra CVE-2025-55241](https://www.itpro.com/security/microsoft-entra-id-vulnerability): cross-tenant takeover potential, [no known abuse](https://www.thestack.technology/critical-azure-vulnerability-cve-2025-55241-entraid/).
- [Salesloft Drift](https://thehackernews.com/2025/08/google-warns-salesloft-oauth-breach.html): stolen OAuth tokens.
- [2026 Okta SSO vishing](https://cybernews.com/cybercrime/shinyhunters-link-sso-vishing-attacks-okta-paywall/): social engineering, no product flaw shown.
- [Clerk CVE-2026-42349](https://advisories.gitlab.com/npm/@clerk/shared/CVE-2026-42349/): SDK authorization bypass, CVSS 8.1.

Researcher's read: a newcomer needs key rotation, tenant-isolation tests, token-free support tooling, phishing-resistant admin access and fast disclosure.

## Agent identity

- **Standards:** the [MCP draft spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) keeps authorization optional, recommends Client ID Metadata Documents and deprecates Dynamic Client Registration. The [2026-07-28 revision date](https://scalar.com/learn/mcp/mcp-oauth) is secondary-sourced.
- **Products:** agents are now priced. [Auth0's add-on is 50% of base, including CIBA](https://auth0.com/pricing), and [Descope meters MCP consents](https://www.descope.com/pricing).
- **Adoption:** [40.55% of 7,973 remote MCP servers have no authentication](https://arxiv.org/abs/2605.22333).
- **Analysts:** Gartner's [5–20% penetration](https://www.descope.com/blog/post/2026-gartner-hype-cycle-digital-identity) figure comes via a vendor and is unconfirmed.

Researcher's read: this is a real roadmap item for developer SaaS, but no independent evidence shows it decides purchases. Surveys are [vendor-sponsored](https://www.conductorone.com/news/press-release/future-of-identity-security-2026). No CIBA adoption data was found.
