<!-- Generated from each module's Contracts/{Module}Events.cs. Do not edit. Regenerate: dotnet run --project tests/Architecture/Generator -->

# Audit event catalogue

Every audit type code Gatekeep writes, declared in its module's contract. Codes are `{domain}.{object}.{action}` and a public contract: removing or renaming a published code is a contract break, which the generator refuses and `AuditCatalogueTests` fails on.

| Code | Module | Summary | FR-40 class |
| --- | --- | --- | --- |
| `admin.access.denied` | Admins | An Admin was refused a capability. The target is the path's Tenant ID as sent, which may not exist. Past 30 per Admin in 15 minutes, only logged. Holds no capability name. | None |
| `admin.credential.registered` | Admins | An Admin registered a WebAuthn credential. Holds no credential ID, public key, challenge or user handle. | None |
| `admin.credential.removed` | Admins | An Admin removed one of their WebAuthn credentials. Holds no credential ID or public key. | None |
| `admin.credential.sign_count_regressed` | Admins | A sign-in with an Admin's WebAuthn credential was refused because its signature counter went backwards: it may be cloned. | None |
| `admin.fresh_assertion.failed` | Admins | A fresh assertion whose signature verified over an Admin's own WebAuthn credential was refused. Holds no credential ID, challenge or binding. | None |
| `admin.fresh_assertion.verified` | Admins | An Admin confirmed a sensitive action with a fresh WebAuthn assertion. Holds no credential ID, challenge, binding or Session ID. | None |
| `admin.recovery_code.issued` | Admins | An Admin confirmed they saved an offline Recovery Code, which can now be used once. Holds no code or HMAC. | None |
| `admin.recovery_code.used` | Admins | An Admin's offline Recovery Code was used to start a Session that reaches only credential registration. Holds no code or HMAC. | None |
| `admin.session.revoked` | Admins | A credential removal or a Recovery Code ended a live Admin Session as revoked. Holds no Session ID. | None |
| `admin.session.signed_out` | Admins | An Admin signed out, which ended their Admin Session. Holds no Session ID. | None |
| `admin.session.superseded` | Admins | A sign-in in the same browser ended a live Admin Session as superseded. Holds no Session ID. | None |
| `admin.setup.completed` | Admins | An Admin came to hold two WebAuthn credentials, or one and an offline Recovery Code, which completed setup and made their Session full. | None |
| `admin.signin.failed` | Admins | A sign-in whose signature verified over an Admin's WebAuthn credential was refused. Holds no credential ID, challenge or user handle. | None |
| `admin.signin.succeeded` | Admins | An Admin signed in with a WebAuthn credential and a full Admin Session started. Holds no credential ID, challenge, user handle or Session ID. | None |
| `audit.retention.checkpoint` | Audit | Retention deleted a chain's sealed prefix past the Log period. Names the last deleted row's epoch, seq and hash. | None |
| `authentication.signin_transaction.started` | Authentication | A sign-in transaction began for an Application. The caller is anonymous, so no person is named. | None |
| `bootstrap.admin.created` | Admins | The bootstrap token was claimed: the first Admin was created as Deployment Owner and bootstrap completed. Holds no token or hash. | None |
| `bootstrap.token.issued` | Admins | gatekeep init issued the first one-time bootstrap token. It expires 15 minutes after issue. Holds no token or hash. | None |
| `bootstrap.token.reissued` | Admins | gatekeep init reissued the bootstrap token, voiding the previous one. It expires 15 minutes after issue. Holds no token or hash. | None |
| `keys.tenant_keys.provisioned` | Keys | A Tenant's missing Signing Keys, Management keys or token protection key were created in key custody. Names no key. | None |
| `operations.job.dead` | Operations | A job used its last attempt and went dead. Only its fixed failure code is kept. | None |
| `operations.operation.retried` | Operations | An Admin retried a failed Operation's failed steps. Names the Operation's Tenant only, when it has one. | None |
| `sessions.access.revoked` | Sessions | Sessions in scope ended and their Token Families and tokens were revoked. User scope targets the User. | Session and token revocation |
| `sessions.session.started` | Sessions | A User's Session started. Names the User only: the Session ID is stored only as its hash. | None |
| `tenancy.tenant.activated` | Tenancy | A Tenant's creation Operation succeeded: its settings exist and its Tenant Subdomain now resolves. | None |
| `tenancy.tenant.created` | Tenancy | A Deployment Owner created a Tenant and became its Tenant Owner, and its creation Operation started. Names the Tenant only. | None |
| `tenancy.tenant.label_changed` | Tenancy | A Tenant Owner changed a Tenant's environment label, other than removing Prod. Names the Tenant only. | None |
| `tenancy.tenant.prod_label_removed` | Tenancy | A Tenant Owner removed a Tenant's Prod label after a fresh WebAuthn assertion. No setting changed with it. | None |

## FR-40 Tenant Log classes

Each class a Tenant's Log must cover, and the codes that prove it. A pending class names the story that adds its event; `EventClassTests` fails once that story is done and the class is still pending.

| Class | Codes | Status |
| --- | --- | --- |
| Sign-ins and failures | None yet | Pending: Story 4.9 |
| Password resets | None yet | Pending: Story 4.11 |
| Email changes | None yet | Pending: Story 16.8 |
| Factor events | None yet | Pending: Story 6.1 |
| Recovery Code events | None yet | Pending: Story 6.8 |
| Session and token revocation | `sessions.access.revoked` | Proved |
| Admin changes | None yet | Pending: Story 8.2 |
| Key operations | None yet | Pending: Story 9.2 |
| Management API grants | None yet | Pending: Story 17.2 |
| Token Family revocations | None yet | Pending: Story 2.10 |
| Rejected cross-Tenant attempts | None yet | Pending: Story 7.4 |
