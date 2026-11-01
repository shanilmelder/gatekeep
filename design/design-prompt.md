Design a complete identity and access management (IAM) platform called "Gatekeep", a developer-first authentication and authorization service comparable in scope to Auth0. Use original branding (no Auth0/Okta logos, names, colors or wordmarks). Style: modern, clean SaaS admin UI, light and dark mode, dense but readable data tables, left sidebar navigation, top bar with tenant switcher, environment badge (Dev / Staging / Prod), global search, help, and user menu. Desktop-first, responsive down to tablet. Produce two surfaces: (A) the Admin Dashboard and (B) the End-User Hosted Login experience.

=== A. ADMIN DASHBOARD ===

1. ONBOARDING & HOME
- First-run wizard: create tenant, pick app type, choose login methods, quickstart code snippet
- Home overview: active users, logins, signups, failed logins, MFA adoption, charts over time, recent activity, security alerts, quick links to quickstarts

2. APPLICATIONS
- Application list and create flow with types: Single Page App, Regular Web App, Native/Mobile, Machine-to-Machine
- App detail tabs: Settings (client ID, client secret with reveal/rotate, domain, logo), Callback URLs, Logout URLs, Allowed Web Origins, CORS, Grant Types (Authorization Code + PKCE, Implicit, Client Credentials, Refresh Token, Device Authorization, Password, CIBA, Token Exchange), Credentials (secret, private key JWT, mTLS), Connections toggle per app, Organizations behavior, Token settings (ID token expiry, refresh token rotation, absolute/inactivity lifetimes), Quickstart tab with SDK code samples, Add-ons (SAML2 Web App, WS-Fed, SSO integrations)
- Third-party apps and dynamic client registration settings

3. APIs (Resource Servers)
- API list, create API (identifier/audience, signing algorithm RS256/HS256)
- Tabs: Settings, Permissions/Scopes, Machine-to-Machine authorized apps, token expiry, RBAC toggle, "add permissions in access token", offline access, user consent policy
- Built-in Management API entry

4. AUTHENTICATION (Connections)
- Database connections: username/password, password policy strength levels, password history, dictionary check, personal data check, require username, disable signups, custom database with Login/Get User/Create/Verify/Change Password/Delete script editors, lazy (automatic) user migration toggle, import users
- Social connections gallery (Google, Apple, Microsoft, GitHub, Facebook, LinkedIn, X, etc. shown with generic icons) with client ID/secret, scopes/attributes to request, sync profile toggle
- Enterprise connections: SAML, OpenID Connect, Microsoft Entra ID / Azure AD, Google Workspace, Active Directory/LDAP with connector agent status, ADFS, Okta Workforce, PingFederate; home realm discovery by email domain; IdP-initiated SSO settings; attribute mapping editor
- Passwordless: Email (magic link and OTP), SMS OTP; template and expiry settings
- Passkeys / WebAuthn as a first-factor login method with policy settings
- Self-service SSO: generate a setup link so a customer's IT admin can configure their own SAML/OIDC connection, plus SCIM provisioning setup
- Inbound SCIM provisioning config and token management

5. ORGANIZATIONS (B2B multi-tenancy)
- Organization list, create organization (name, display name, logo, brand colors)
- Org detail: Members, Invitations (send invite, pending, expire), Member roles, Enabled connections per org with auto-membership and "show as button", Login prompt behavior, Metadata
- Org-specific login page preview

6. USER MANAGEMENT
- Users table with search (Lucene-style query bar), filters, bulk actions, export/import jobs (JSON/CSV)
- User profile: identity provider badges, email verified status, last login/IP/device, user_metadata and app_metadata JSON editors, linked accounts (account linking), roles, permissions, organizations, sessions (list and revoke), devices, authorized apps, MFA enrollments (reset), history/logs for that user
- Actions: block/unblock, delete, send verification email, change password, reset MFA, impersonate (with warning), revoke refresh tokens
- Roles: create roles, assign permissions from APIs, assign users
- Bulk user import job status screen

7. AUTHORIZATION
- Role-Based Access Control (RBAC) management
- Fine-Grained Authorization (relationship-based, Zanzibar-style): authorization model editor (types, relations), relationship tuples browser, "check" playground, query/list objects tester, model version history

8. MULTI-FACTOR AUTH & SECURITY
- MFA factors toggles: TOTP authenticator app, push notifications via own Guardian-style mobile app, SMS, voice, email, WebAuthn security keys, WebAuthn device biometrics, recovery codes, Duo-style third-party integration
- Policies: Never / Always / Adaptive (risk-based). Adaptive MFA risk signals: new device, impossible travel, untrusted IP
- Step-up authentication settings
- Attack Protection: Bot detection with CAPTCHA provider choice and sensitivity, Suspicious IP throttling, Brute-force protection (thresholds, block notifications, allowlist), Breached password detection (block/notify, admin notifications)
- Security Center: threat dashboard with credential stuffing, signup attacks, MFA bypass attempts, timelines and suggested mitigations
- Tenant security settings: session lifetimes, idle timeout, refresh token rotation and reuse detection, allowed domains, DPoP/mTLS sender-constrained tokens, PAR (pushed authorization requests), JAR, highly-regulated/FAPI mode toggles
- Signing keys: list, rotate, revoke, JWKS endpoint view

9. ACTIONS & EXTENSIBILITY
- Actions library and code editor (Node.js) with secrets, npm dependencies, version history, deploy button, test runner with sample event payload
- Triggers and drag-and-drop Flow builder for: Login (post-login), Pre-user-registration, Post-user-registration, Post-change-password, Send phone message, Machine-to-machine credentials exchange, Password reset post-challenge, Custom token exchange
- Marketplace of pre-built integrations (generic logos) with install flow
- Forms builder: no-code drag-and-drop forms for progressive profiling, custom signup steps, terms acceptance, with flows/connectors to external services
- Custom token exchange profiles
- Legacy Rules/Hooks shown as read-only "deprecated, migrate to Actions" screen

10. AI AGENT AUTHENTICATION
- Agent/AI app registration
- Token Vault: connected third-party accounts that agents can call APIs on behalf of users, with token status and revoke
- Asynchronous authorization (CIBA): pending approval requests list, user-facing push approval screen for "Agent wants to do X"
- Fine-grained authorization for RAG documents, with link into FGA
- MCP server/client registration screen

11. BRANDING & CUSTOMIZATION
- Universal Login editor: theme builder (logo, colors, fonts, border radius, widget layout, background), live preview for every screen (login, signup, MFA, reset password, consent, organization picker, passwordless, error)
- Advanced: custom HTML page templates with variables, partials/custom prompts, text and translations editor across 50+ languages, default language
- Custom domains: add domain, DNS verification steps (CNAME/TXT), certificate status (managed or self-managed)
- Email templates: verification, welcome, password reset, blocked account, MFA enrollment, passwordless, invitation, with liquid template editor and test send
- Email provider config (SMTP, SendGrid-style, SES-style, custom) and SMS/phone provider config

12. MONITORING
- Logs: real-time event stream table with event type codes, filters, detail drawer with raw JSON
- Log Streams: webhook, Datadog, Splunk, AWS EventBridge, Azure Event Grid, Sumo Logic style destinations, with health status
- Analytics/Insights: active users, retention, login methods breakdown, MFA enrollment rate, geographic map, failure reasons
- Tenant health & rate limit usage

13. TENANT & TEAM SETTINGS
- Tenant settings: name, friendly name, support email/URL, region, environment tag, default audience, default directory, error page, session settings, OIDC/OAuth feature flags, device flow settings
- Multiple tenants and environments switcher; tenant settings diff/promotion between environments
- Team members and dashboard admin roles (Owner, Admin, Editor, Viewer, Support), dashboard SSO, dashboard MFA enforcement, audit log of admin actions
- API keys / Management API tokens explorer
- Billing & subscription: plan, MAU usage meter, invoices, upgrade
- Compliance & privacy: data residency, user data export, GDPR deletion requests, consent records, certifications page
- Deploy CLI / Terraform export & config-as-code screen
- Support center and status page link

14. DEVELOPER EXPERIENCE
- Quickstart gallery by framework (React, Next.js, Angular, Vue, .NET, Node, Python, Java, Go, iOS, Android, Flutter, React Native)
- Authentication API and Management API explorer with "Try it" console
- Test tenant tokens tool, JWT decoder, OIDC discovery endpoint viewer

=== B. END-USER HOSTED LOGIN SCREENS ===
Design each in the default theme, plus one custom-branded variant:
- Login (identifier-first) with social buttons, enterprise SSO "Continue with company SSO", passkey button
- Signup with password strength meter, terms checkbox, progressive profiling step
- Passwordless email/SMS code entry and magic link sent
- Passkey create and passkey sign-in prompts
- MFA enroll (choose factor), TOTP QR code, SMS code, push "check your phone", WebAuthn, recovery code display
- Step-up MFA challenge
- Forgot password, reset password, password changed confirmation
- Email verification required / verified
- Organization picker and organization invitation acceptance
- Consent screen for third-party app scopes
- Device activation (enter code on TV/CLI)
- Agent approval (CIBA) request screen
- Account linking prompt
- Blocked account, brute force lockout, breached password warning, CAPTCHA challenge
- Logout confirmation and generic error page
- User self-service account portal: profile, security (password, passkeys, MFA devices), active sessions, connected apps, delete account

=== DELIVERABLE ===
Start with the design system (color tokens, type scale, spacing, components: buttons, inputs, tables, tabs, code blocks, JSON editor, status badges, toggles, empty states, modals, toasts). Then show the sidebar information architecture, then key screens for each section above. Prioritize: Home, Applications detail, Connections, Users list + user detail, Organizations, MFA & Attack Protection, Actions flow builder, Universal Login editor, Logs, and the full end-user login/signup/MFA flow.