# Gatekeep design screens

Index of the three design exports in this folder.

**How to find things.** The exports contain no element `id` attributes, so each locator below uses what the file does have:

- `data-screen-label="…"`: the label on a top-level admin screen or shell region.
- `is.x`, `at.x` and similar: the `<sc-if value="{{ … }}">` conditional that renders a screen or tab.
- `GEN.x`: an entry in `static GEN`, the data for pages drawn by the shared `Section` template.
- Quoted text: a heading or caption visible in the file.
- `L123`: the line number at the time of writing. Search for the locator if the export has been regenerated.

---

## Gatekeep Design System.dc.html

Token groups and components only; the file has no screens. Components are in one `<sc-for list="{{ themes }}">` block (L93), so each renders once in light and once in dark.

| Name | Section | How to find it | Purpose |
| --- | --- | --- | --- |
| Surface tokens: `--bg`, `--sf`, `--sf2`, `--sf3` | Colour tokens | `:root` / `[data-theme="dark"]` L14–15; swatches under "Colour tokens" L39 | Layer the app canvas, cards, wells and hover states. |
| Border tokens: `--bd`, `--bd2` | Colour tokens | `:root` L14; `tokens` array L200 | Separate content with dividers and outline controls. |
| Text tokens: `--tx`, `--tx2`, `--tx3` | Colour tokens | `:root` L14; `tokens` array L200–201 | Rank primary, secondary and meta text. |
| Accent tokens: `--ac`, `--ac-sf`, `--ac-tx`, `--on-ac` | Colour tokens | `:root` L14; `tokens` array L201 | Carry Gate jade, reserved for primary actions, "allowed" states and focus. |
| Status tokens: `--ok`, `--warn`, `--bad`, `--info` and their `-sf` pairs | Colour tokens | `:root` L14; `tokens` array L201–202 | Describe state only: success, caution, error and informational tags. |
| Code tokens: `--code-bg`, `--code-tx` | Colour tokens | `:root` L14; `tokens` array L202 | Colour code surfaces and the text on them. |
| Elevation token: `--sh` | Space, radius, elevation | `:root` L14; "raised · menus, modals" L83 | Lift menus and modals off the page; everything else stays flat with a border. |
| Type scale: display, page-title, section, body, small, label, code | Type scale | "Type scale" L58 | Define the Geist and Geist Mono text styles with size, line height and weight. |
| Spacing scale: 4–48px | Space, radius, elevation | "Space, radius, elevation" L70; `spaces` array L204 | Set the 4px-based spacing steps. |
| Radius scale: tag, control, card, modal | Space, radius, elevation | "4 · tag" to "14 · modal" L76–79 | Set corner radii of 4, 7, 10 and 14px by element type. |
| Layout metrics | Space, radius, elevation | "4px base grid…" L85 | Fix control heights, table row height, content gutters and page padding. |
| Buttons | Components | "Buttons" L97 | Show primary, secondary, ghost, destructive, disabled and small buttons. |
| Form fields | Components | "Domain" field L109 to "Search (focused)" L112 | Show default, error, select and focused inputs with labels and help text. |
| Selection controls | Components | "On" toggle L116 to "Never / Always / Adaptive" L120 | Show toggles, checkbox, radio and segmented control. |
| Status badges | Components | "Status badges" L123 | Show state, protocol, environment and log-code badges. |
| Tabs | Components | "Settings / Credentials / Connections / Quickstart" L136 | Show the underlined tab bar used on detail pages. |
| Data table | Components | Grid with "User / Connection / Last login / Logins" L139 | Show header, row and selected-row styles for 38px tables. |
| Code blocks | Components | "npm" block L146; JSON block L149 | Show a dark copyable command block and a line-numbered JSON viewer. |
| Empty state | Components | "No log streams yet" L158 | Show the dashed placeholder with a call to action for empty lists. |
| Toast and inline banner | Components | "Secret rotated" L162; "Signing key expires…" L163 | Show transient confirmation and persistent warning messages. |
| Modal | Components | "Impersonate maya@acme.com?" L169 | Show a confirmation dialog for a sensitive action. |
| Sidebar information architecture | Sidebar information architecture | "Sidebar information architecture" L179; `nav` array L205 | Lay out the 12 navigation groups in task order. |

---

## Gatekeep Hosted Login.dc.html

Sections use the file's own numbered group headings. All 33 screens sit in one `<sc-for list="{{ variants }}">` block (L33), so each renders twice: in the default theme and in the Halcyon Bank brand theme. Each is found by its caption.

| Screen name | Section | How to find it | Purpose |
| --- | --- | --- | --- |
| Theme variants (Default theme; Custom branded · Halcyon Bank) | Theme | `<section data-v="{{ v.id }}">` L34; `[data-v]` tokens L15–16; `all` array L467 | Show every screen in both themes, with only the tokens changing. |
| Login · identifier first | 01 Sign in | Caption "Login · identifier first" L39 | Collect the email first and offer social, passkey and company SSO options. |
| Login · password step | 01 Sign in | Caption "Login · password step" L53 | Take the password for a known email and suggest adding a passkey. |
| Passkey sign-in prompt | 01 Sign in | Caption "Passkey sign-in prompt" L64 | Show the browser's passkey sheet over the dimmed login card. |
| Signup · password strength | 02 Sign up | Caption "Signup · password strength" L80 | Create an account with live password strength and policy feedback. |
| Progressive profiling (Form) | 02 Sign up | Caption "Progressive profiling (Form)" L95 | Collect extra profile details in a skippable multi-step form. |
| Passkey create | 02 Sign up | Caption "Passkey create" L107 | Invite the user to create a passkey instead of relying on a password. |
| Email / SMS code entry | 03 Passwordless | Caption "Email / SMS code entry" L123 | Enter a six-digit one-time code, with resend and channel-switch options. |
| Magic link sent | 03 Passwordless | Caption "Magic link sent" L133 | Tell the user a single-use sign-in link is on its way. |
| Enroll · choose a factor | 04 Multi-factor | Caption "Enroll · choose a factor" L148 | Let the user pick a second factor, ranked by strength. |
| TOTP · scan QR | 04 Multi-factor | Caption "TOTP · scan QR" L159 | Enrol an authenticator app by QR code or manual key, then confirm a code. |
| Push · check your phone | 04 Multi-factor | Caption "Push · check your phone" L170 | Wait for push approval with number matching and a countdown. |
| SMS code | 04 Multi-factor | Caption "SMS code" L182 | Verify an SMS code, shown here in the incorrect-code state. |
| WebAuthn security key | 04 Multi-factor | Caption "WebAuthn security key" L194 | Prompt the user to insert and touch a hardware security key. |
| Recovery codes | 04 Multi-factor | Caption "Recovery codes" L205 | Show one-time backup codes and require confirmation that they were saved. |
| Step-up challenge | 04 Multi-factor | Caption "Step-up challenge" L216 | Require stronger verification before a sensitive transaction. |
| Forgot password | 05 Password recovery & verification | Caption "Forgot password" L232 | Request a password reset link by email. |
| Reset password | 05 Password recovery & verification | Caption "Reset password" L242 | Set and confirm a new password with a strength meter. |
| Password changed | 05 Password recovery & verification | Caption "Password changed" L252 | Confirm the change and explain that other devices were signed out. |
| Email verification required | 05 Password recovery & verification | Caption "Email verification required" L261 | Hold the user until they verify their email, with a resend option. |
| Email verified | 05 Password recovery & verification | Caption "Email verified" L271 | Confirm verification and send the user on to the app. |
| Organization picker | 06 Organizations, consent & linking | Caption "Organization picker" L284 | Let a member of several organizations choose which to sign in to. |
| Invitation acceptance | 06 Organizations, consent & linking | Caption "Invitation acceptance" L295 | Accept an organization invite through its SSO. |
| Consent · third-party app | 06 Organizations, consent & linking | Caption "Consent · third-party app" L306 | Ask the user to allow or decline the access a third-party app requests. |
| Account linking prompt | 06 Organizations, consent & linking | Caption "Account linking prompt" L317 | Offer to link a social login to an existing password account. |
| Device activation (TV / CLI) | 07 Devices & AI agents | Caption "Device activation (TV / CLI)" L332 | Enter the code shown on an input-constrained device to authorize it. |
| Agent approval (CIBA) | 07 Devices & AI agents | Caption "Agent approval (CIBA)" L342 | Approve or deny one action requested by an AI agent. |
| Blocked account | 08 Protection | Caption "Blocked account" L357 | Tell a suspended user to contact their admin or support. |
| Brute-force lockout | 08 Protection | Caption "Brute-force lockout" L366 | Explain the temporary lock and offer unlock by email or password reset. |
| Breached password warning | 08 Protection | Caption "Breached password warning" L376 | Force a new password when the current one appears in a breach. |
| CAPTCHA challenge | 08 Protection | Caption "CAPTCHA challenge" L387 | Add a human check to login when activity looks unusual. |
| Logout confirmation | 09 Exit & errors | Caption "Logout confirmation" L401 | Confirm signing out of all apps in this browser. |
| Generic error | 09 Exit & errors | Caption "Generic error" L409 | Explain a failed or expired link and show an error code with a trace ID. |
| Self-service account portal | 10 Self-service account portal | Heading "10 — SELF-SERVICE ACCOUNT PORTAL" L421 | Let users manage sign-in methods, 2FA, sessions, connected apps and account deletion. |

---

## Gatekeep Admin.dc.html

Sections match the 12 sidebar groups in `static NAV` (L1250), plus Shell for elements shared across pages. The file is one interactive app, so most screens only appear when you navigate to them. Passing a page key as the `startPage` prop opens the app on that page.

### Shell and shared components

| Screen name | Section | How to find it | Purpose |
| --- | --- | --- | --- |
| Top bar | Shell | `data-screen-label="Top bar"` L28 | Hold the brand, tenant switcher, global search, help, theme toggle, alerts and account avatar. |
| Tenant switcher menu | Shell | `tenantMenu` L41 | Switch tenants or environments and link to compare, promote and create. |
| Global search results | Shell | `hasResults` L65 | List matching pages under the search box as the user types. |
| Sidebar | Shell | `data-screen-label="Sidebar"` L83 | Provide collapsible navigation across the 12 groups, shrinking to an icon rail on narrow windows. |
| Section page template | Shell | `data-screen-label="Section"` L1143; `isGeneric` L1142 | Draw every `GEN` page from a header, optional tabs and data-driven blocks. |
| Section blocks: stats, note, table, settings, code, cards, bars | Shell | `b.isStats` L1159 to `b.isBars` L1214 | Provide the reusable content blocks that make up `GEN` pages. |
| Confirmation modal | Shell | `modal` L1233; copy in `modalInfo` L1340 | Confirm impersonating, blocking or deleting a user, with typed confirmation for delete. |
| Toast | Shell | `toast` L1243 | Show brief confirmation after an action. |

### Screens

| Screen name | Section | How to find it | Purpose |
| --- | --- | --- | --- |
| Get started | Overview | `data-screen-label="Onboarding wizard"` L201; `is.onboarding` L200 | Guide a new admin through tenant setup in four steps. |
| Get started · Tenant step | Overview | `wiz.s0` L208 | Name the tenant and choose its region for data residency. |
| Get started · App type step | Overview | `wiz.s1` L215 | Choose the kind of application being built. |
| Get started · Login methods step | Overview | `wiz.s2` L225 | Choose how users will sign in. |
| Get started · Quickstart step | Overview | `wiz.s3` L236 | Finish setup with framework code pre-filled for the new app. |
| Home | Overview | `data-screen-label="Home"` L104; `is.home` L103 | Summarize tenant health with KPIs, login trends, MFA adoption, security alerts, recent activity, quickstarts and plan usage. |
| Applications | Applications | `data-screen-label="Applications"` L266; `is.apps` L265 | List the apps registered in the tenant and link to each one. |
| Application detail | Applications | `data-screen-label="Application detail"` L293; `is.app` L292 | Frame one application, Northwind Web, with its header and seven tabs. |
| Application · Settings | Applications | `at.settings` L309 | Edit basic details, allowed URIs and grant types, or delete the app. |
| Application · Credentials | Applications | `at.credentials` L345 | Choose the authentication method and manage the client secret and public keys. |
| Application · Connections | Applications | `at.connections` L365 | Turn identity connections on or off for this app. |
| Application · Organizations | Applications | `at.orgs` L379 | Set whether the app serves individuals, business users or both. |
| Application · Tokens | Applications | `at.tokens` L388 | Configure ID token settings and refresh token rotation and lifetimes. |
| Application · Quickstart | Applications | `at.quickstart` L408 | Show framework-specific steps to integrate this app. |
| Application · Add-ons | Applications | `at.addons` L434 | Enable SAML, WS-Federation and SSO integrations for the app. |
| APIs | Applications | `GEN.apis` L1265; tabs "List", "Northwind Core API · Settings" | List resource servers and configure one API's settings, permissions and machine-to-machine access. |
| Quickstarts | Applications | `GEN.quickstarts` L1266 | Offer framework guides pre-filled with tenant credentials. |
| Database | Authentication | `data-screen-label="Database connection"` L446; `is.db` L445 | Frame the Username-Password connection and its five tabs. |
| Database · Settings | Authentication | `dt.settings` L458 | Set the identifier types and whether sign-ups are allowed. |
| Database · Password policy | Authentication | `dt.policy` L465 | Set password strength, history, dictionary and personal-data rules, with a preview. |
| Database · Custom database | Authentication | `dt.custom` L485 | Connect an external user store through scripts and migrate users lazily. |
| Database · Applications | Authentication | `dt.applications` L504 | Show which applications use this connection. |
| Database · Import users | Authentication | `dt.import` L509 | Upload a JSON or CSV file of users and link to import jobs. |
| Social | Authentication | `data-screen-label="Social connections"` L517; `is.social` L516 | List social providers and configure the selected one. |
| Enterprise | Authentication | `data-screen-label="Enterprise connections"` L544; `is.enterprise` L543 | Manage federated customer IdPs, including domain routing and attribute mapping. |
| Enterprise · LDAP variant | Authentication | `isLdap` L562 | Show connector agent status for the AD / LDAP connection. |
| Passwordless | Authentication | `GEN.passwordless` L1267; tabs "Email", "SMS" | Configure one-time code and magic link sign-in by channel. |
| Passkeys | Authentication | `GEN.passkeys` L1268 | Show passkey adoption and set enrolment and verification policy. |
| Self-service SSO | Authentication | `GEN.ssoSelf` L1269 | Generate setup links so customer IT admins can connect their own IdP. |
| SCIM provisioning | Authentication | `GEN.scim` L1270 | Monitor inbound directory sync and map its attributes. |
| Users | User management | `data-screen-label="Users"` L584; `is.users` L583 | Search, filter and act on all users in the tenant. |
| Users · Bulk action bar | User management | `hasSel` L601 | Apply role, organization, verification, block or delete actions to selected users. |
| User detail | User management | `data-screen-label="User detail"` L625; `is.user` L624 | Frame one user, Maya Okafor, with a summary and six tabs. |
| User · Actions menu | User management | `userMenu` L639 | Run account actions such as password change, MFA reset, impersonate, block and delete. |
| User · Details | User management | `ut.details` L658 | Edit the profile and review linked accounts and metadata. |
| User · Sessions & devices | User management | `ut.sessions` L684 | Review active sessions and revoke sessions or refresh tokens. |
| User · Roles & permissions | User management | `ut.roles` L694 | Show assigned roles and the permissions they grant. |
| User · Organizations & apps | User management | `ut.orgs` L703 | Show the user's organization memberships and authorized applications. |
| User · MFA | User management | `ut.mfa` L711 | Manage the user's enrolled factors and recovery codes. |
| User · History | User management | `ut.history` L718 | Show this user's recent authentication events. |
| Roles | User management | `GEN.roles` L1271 | List permission bundles and how many users hold each one. |
| Organizations | User management | `data-screen-label="Organizations"` L730; `is.orgs` L729 | Browse customer organizations and open one in a five-tab detail pane. |
| Organization · Members | User management | `ot.members` L750 | List an organization's members and their roles. |
| Organization · Invitations | User management | `ot.invitations` L762 | Send invites and track pending ones. |
| Organization · Connections | User management | `ot.connections` L775 | Set which connections an organization uses and how members join. |
| Organization · Login experience | User management | `ot.login` L787 | Set organization branding and its login prompt, with a preview. |
| Organization · Metadata | User management | `ot.metadata` L806 | Store key-value data on the organization. |
| Import / export jobs | User management | `GEN.imports` L1272 | Track bulk user jobs and inspect failed rows. |
| RBAC | Authorization | `GEN.rbac` L1273 | Show the permission matrix across roles for one API. |
| Fine-grained (FGA) | Authorization | `GEN.fga` L1274; tabs "Model", "Tuples", "Check playground" | Edit the relationship model, manage tuples and test access checks. |
| Multi-factor auth | Security | `data-screen-label="Multi-factor auth"` L818; `is.mfa` L817 | Choose factors and when MFA is required, including step-up and remembered browsers. |
| Multi-factor auth · Adaptive panel | Security | `isAdaptive` L841 | Configure the risk signals that trigger MFA under the adaptive policy. |
| Attack protection | Security | `data-screen-label="Attack protection"` L862; `is.attack` L861 | Configure bot detection, IP throttling, brute-force protection and breached password detection. |
| Security center | Security | `GEN.seccenter` L1275 | Show detected threats, a timeline and suggested mitigations. |
| Tenant security | Security | `GEN.tenantsec` L1276 | Set session lifetimes, refresh token defaults, sender-constrained tokens and allowed domains. |
| Signing keys | Security | `GEN.keys` L1277 | Rotate and revoke token signing keys and show the JWKS. |
| Flows & editor | Actions | `data-screen-label="Actions flow builder"` L905; `is.flows` L904 | Pick a trigger and drag actions into its flow, then deploy it. |
| Action editor · Code | Actions | `atab.code` L953 | Edit the selected action's code. |
| Action editor · Secrets | Actions | `atab.secrets` L959 | Manage secrets available to the action. |
| Action editor · Dependencies | Actions | `atab.deps` L967 | Manage the action's packages. |
| Action editor · Versions | Actions | `atab.versions` L974 | Review deployed versions and restore an earlier one. |
| Action editor · Test | Actions | `atab.test` L981 | Run the action against a sample event payload. |
| Library | Actions | `GEN.actionsLib` L1278 | List custom and installed actions with their trigger, version and status. |
| Forms | Actions | `GEN.forms` L1279 | Build no-code steps for the login flow and view a form's nodes. |
| Marketplace | Actions | `GEN.marketplace` L1280 | Browse and install pre-built integrations. |
| Token exchange | Actions | `GEN.tokenex` L1281 | Define profiles that swap external or legacy tokens for Gatekeep tokens. |
| Rules & Hooks (legacy) | Actions | `GEN.rules` L1282 | Show deprecated rules and hooks with their migration status. |
| Agents | AI agents | `GEN.agents` L1283 | Register AI agents and set their scoped access policy. |
| Token vault | AI agents | `GEN.vault` L1284 | Review and revoke third-party accounts that agents use for users. |
| Async authorization | AI agents | `GEN.ciba` L1285 | Track CIBA approval requests and configure how they are delivered. |
| RAG authorization | AI agents | `GEN.rag` L1286 | Filter retrieved documents through FGA so agents see only what the user can. |
| MCP servers | AI agents | `GEN.mcp` L1287 | Register MCP servers and set client registration rules. |
| Universal Login | Branding | `data-screen-label="Universal Login editor"` L999; `is.ul` L998 | Edit the hosted login theme with live controls and publish it. |
| Universal Login · Preview screens | Branding | `us.login` L1028 to `us.error` L1089 | Preview the theme on login, signup, MFA, reset, consent, org picker, passwordless and error screens. |
| Custom domains | Branding | `GEN.domains` L1288 | Add login domains and track their certificates and DNS verification. |
| Email templates | Branding | `GEN.emails` L1289; seven tabs from "Verification" to "Invitation" | Edit Liquid templates for transactional email. |
| Email & SMS providers | Branding | `GEN.providers` L1290 | Choose and configure message delivery providers. |
| Logs | Monitoring | `data-screen-label="Logs"` L1104; `is.logs` L1103 | Browse and filter tenant events by outcome. |
| Logs · Event drawer | Monitoring | `logOpen` L1131 | Show the raw JSON of the selected event. |
| Log streams | Monitoring | `GEN.streams` L1291 | Manage event streams to SIEM and observability destinations. |
| Analytics | Monitoring | `GEN.analytics` L1292 | Report active users, retention, login methods, failure reasons and top countries. |
| Health & rate limits | Monitoring | `GEN.health` L1293 | Show service status, latency and API quota usage. |
| Tenant | Settings | `GEN.tenant` L1294 | Edit general tenant details, API authorization, error page and OIDC options. |
| Environments | Settings | `GEN.envs` L1295 | Compare configuration between environments and promote changes. |
| Team & audit | Settings | `GEN.team` L1296; tabs "Members", "Audit log" | Manage dashboard admins and review what they changed. |
| API keys | Settings | `GEN.apikeys` L1297 | Manage Management API credentials and inspect tokens. |
| Billing | Settings | `GEN.billing` L1298 | Show the plan, usage against limits and invoices. |
| Compliance & privacy | Settings | `GEN.compliance` L1299 | Show data residency, subject requests, consent records and certifications. |
| Config as code | Settings | `GEN.iac` L1300; tabs "Terraform", "Deploy CLI" | Export the tenant as Terraform or Deploy CLI YAML. |
| API explorer | Developers | `GEN.explorer` L1301 | Browse API endpoints and try requests. |
| JWT & OIDC tools | Developers | `GEN.tools` L1302; tabs "JWT decoder", "OIDC discovery", "Test tokens" | Decode tokens, inspect OIDC discovery and mint test tokens. |
| Support | Developers | `GEN.support` L1303 | Link to help resources and list the tenant's support tickets. |

---

## Differences between the exports

- **Sidebar:** the design system's fallback list (`Gatekeep Design System.dc.html` L205) doesn't match `static NAV` in the admin export (L1250). It names the second group "Build" rather than "Applications", leaves out the Northwind Web and Maya Okafor entries, and shortens some labels (for example "Import jobs", "Team", "Health & limits").
- **Colour swatches:** the design system's swatch grid shows 16 of the 24 tokens defined in `:root`. It omits `--ac-tx`, `--on-ac`, `--ok-sf`, `--warn-sf`, `--bad-sf`, `--info-sf`, `--code-tx` and `--sh`.
- **Login previews:** the Universal Login editor previews 8 screens, while the hosted login export has 33.
