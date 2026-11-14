<!-- Generated from each module's Contracts/{Module}Events.cs. Do not edit. Regenerate: dotnet run --project tests/Architecture/Generator -->

# Audit event catalogue

Every audit type code Gatekeep writes, declared in its module's contract. Codes are `{domain}.{object}.{action}` and a public contract: removing or renaming a published code is a contract break, which the generator refuses and `AuditCatalogueTests` fails on. Each code's outcome is declared with it and never stored: a Log search by outcome is a search by the codes that have it.

| Code | Module | Outcome | Summary | FR-40 class |
| --- | --- | --- | --- | --- |
| `admin.access.denied` | Admins | Failure | An Admin was refused a capability. The target is the path's Tenant ID as sent, which may not exist. Past 30 per Admin in 15 minutes, only logged. Holds no capability name. | None |
| `admin.credential.registered` | Admins | Success | An Admin registered a WebAuthn credential. Holds no credential ID, public key, challenge or user handle. | None |
| `admin.credential.removed` | Admins | Success | An Admin removed one of their WebAuthn credentials. Holds no credential ID or public key. | None |
| `admin.credential.sign_count_regressed` | Admins | Failure | A sign-in with an Admin's WebAuthn credential was refused because its signature counter went backwards: it may be cloned. | None |
| `admin.cross_tenant.rejected` | Admins | Failure | An Admin holding no Tenant Role in this Tenant was refused a request in it. Past 30 refusals per Admin in 15 minutes, only logged. Holds no capability name. | Rejected cross-Tenant attempts |
| `admin.enrolment.issued` | Admins | Success | gatekeep recover-admin issued a single-use 15-minute enrolment for an Admin, after its Security Alert and off-server record. Holds no value or hash. | None |
| `admin.enrolment.used` | Admins | Success | An Admin's recover-admin enrolment was used to end their Sessions and start one that reaches only credential registration. Holds no value or hash. | None |
| `admin.fresh_assertion.failed` | Admins | Failure | A fresh assertion whose signature verified over an Admin's own WebAuthn credential was refused. Holds no credential ID, challenge or binding. | None |
| `admin.fresh_assertion.verified` | Admins | Success | An Admin confirmed a sensitive action with a fresh WebAuthn assertion. Holds no credential ID, challenge, binding or Session ID. | None |
| `admin.recovery_code.issued` | Admins | Success | An Admin confirmed they saved an offline Recovery Code, which can now be used once. Holds no code or HMAC. | None |
| `admin.recovery_code.used` | Admins | Success | An Admin's offline Recovery Code was used to start a Session that reaches only credential registration. Holds no code or HMAC. | None |
| `admin.session.revoked` | Admins | Success | A credential removal, a Recovery Code or a recover-admin enrolment ended a live Admin Session as revoked. Holds no Session ID. | None |
| `admin.session.signed_out` | Admins | Success | An Admin signed out, which ended their Admin Session. Holds no Session ID. | None |
| `admin.session.superseded` | Admins | Success | A sign-in in the same browser ended a live Admin Session as superseded. Holds no Session ID. | None |
| `admin.setup.completed` | Admins | Success | An Admin came to hold two WebAuthn credentials, or one and an offline Recovery Code, which completed setup and made their Session full. | None |
| `admin.signin.failed` | Admins | Failure | A sign-in whose signature verified over an Admin's WebAuthn credential was refused. Holds no credential ID, challenge or user handle. | None |
| `admin.signin.succeeded` | Admins | Success | An Admin signed in with a WebAuthn credential and a full Admin Session started. Holds no credential ID, challenge, user handle or Session ID. | None |
| `audit.retention.checkpoint` | Audit | Success | Retention deleted a chain's sealed prefix past the Log period. Names the last deleted row's epoch, seq and hash. | None |
| `authentication.signin_transaction.started` | Authentication | Success | A sign-in transaction began for an Application. The caller is anonymous, so no person is named. | None |
| `bootstrap.admin.created` | Admins | Success | The bootstrap token was claimed: the first Admin was created as Deployment Owner and bootstrap completed. Holds no token or hash. | None |
| `bootstrap.token.issued` | Admins | Success | gatekeep init issued the first one-time bootstrap token. It expires 15 minutes after issue. Holds no token or hash. | None |
| `bootstrap.token.reissued` | Admins | Success | gatekeep init reissued the bootstrap token, voiding the previous one. It expires 15 minutes after issue. Holds no token or hash. | None |
| `directory.api.created` | Directory | Success | An API was created with its identifier, which can't be changed. Names the API only. | None |
| `directory.api.permission_added` | Directory | Success | A Permission was added to an API. Names the API only. | None |
| `directory.api.permission_removed` | Directory | Success | A Permission was removed from an API. Names the API only. | None |
| `directory.api.updated` | Directory | Success | An API's offline access, RBAC or token lifetimes were changed. Names the API only. A save that changes nothing writes no event. | None |
| `directory.application.created` | Directory | Success | An Application was created. Names the Application only: no client secret is created with it, and any secret is stored only as its hash. | None |
| `directory.application.deleted` | Directory | Success | An Application was deleted: hidden at once, its secrets, refresh tokens and grants revoked. Access tokens it holds stay valid until they expire. Names the Application only. | None |
| `directory.application.prod_callback_added` | Directory | Success | A callback URL was added to an Application in a Prod Tenant, after a fresh assertion. Names the Application only, never the URL. | None |
| `directory.application.updated` | Directory | Success | An Application's callback, logout or web origin URLs or its grant types were changed. Names the Application only, never a URL. A save that changes nothing writes no event. | None |
| `directory.client_secret.created` | Directory | Success | A client secret was created for an Application. Names the Application only: the secret is shown once to its creator and stored only as its hash. | None |
| `directory.client_secret.revoked` | Directory | Success | One of an Application's client secrets was revoked, or a rotated-out secret was ended early: it is refused at once. Names the Application only, never a secret. | None |
| `directory.client_secret.rotated` | Directory | Success | An Application's client secret was rotated: a new secret was created, and the old one stays valid for 24 hours unless ended sooner. Names the Application only, never a secret. | None |
| `keys.signing_key.created` | Keys | Success | A Tenant's replacement next Signing or Management key was created in key custody. Names no key. | Key operations |
| `keys.signing_key.destroyed` | Keys | Success | A Tenant's retired or revoked Signing or Management key was destroyed in key custody. Names no key. | None |
| `keys.signing_key.destruction_failed` | Keys | Failure | Key custody failed to destroy a Tenant's retired or revoked Signing or Management key; the destruction retries. Names no key. | None |
| `keys.signing_key.promoted` | Keys | Success | A Tenant's next Signing or Management key became current. Names no key. | Key operations |
| `keys.signing_key.promoted_unaged` | Keys | Success | A revoked Signing Key's next key became current before it had been published for 15 minutes; relying parties may not have it yet. Names no key. | Key operations |
| `keys.signing_key.retired` | Keys | Success | A Tenant's previous Signing or Management key retired and its destruction was queued. Names no key. | None |
| `keys.signing_key.revoked` | Keys | Success | A Tenant Owner revoked a Signing Key: it left the JWKS and its private material is queued for destruction. Names no key. | Key operations |
| `keys.signing_key.rotated` | Keys | Success | A Tenant's Signing or Management key was rotated, by the daily rotation or a Tenant Owner: current became previous. Names no key. | Key operations |
| `keys.tenant_keys.provisioned` | Keys | Success | A Tenant's missing Signing Keys, Management keys or token protection key were created in key custody. Names no key. | None |
| `keys.transit_key.swept` | Keys | Success | A Signing or Management key at least 24 hours old, named by no row when checked, was deleted from key custody. Names no key. | None |
| `operations.job.dead` | Operations | Failure | A job used its last attempt and went dead. Only its fixed failure code is kept. | None |
| `operations.operation.retried` | Operations | Success | An Admin retried a failed Operation's failed steps. Names the Operation's Tenant only, when it has one. | None |
| `protocol.client.cross_tenant_rejected` | Protocol | Failure | A client credential issued by another Tenant was refused at this Tenant's token endpoint. Names nothing of the other Tenant. | Rejected cross-Tenant attempts |
| `sessions.access.revoked` | Sessions | Success | Sessions in scope ended and their Token Families and tokens were revoked. User scope targets the User. | Session and token revocation |
| `sessions.session.started` | Sessions | Success | A User's Session started. Names the User only: the Session ID is stored only as its hash. | None |
| `tenancy.tenant.activated` | Tenancy | Success | A Tenant's creation Operation succeeded: its settings exist and its Tenant Subdomain now resolves. | None |
| `tenancy.tenant.created` | Tenancy | Success | A Deployment Owner created a Tenant and became its Tenant Owner, and its creation Operation started. Names the Tenant only. | None |
| `tenancy.tenant.deleted` | Tenancy | Success | A Tenant's deletion Operation succeeded: every module's Tenant data is purged and its keys are destroyed. Its Logs are kept until their retention ends. | None |
| `tenancy.tenant.deletion_started` | Tenancy | Success | A Deployment Owner deleted a Tenant after typing its Tenant Subdomain and a fresh WebAuthn assertion: its host stops resolving, its roles end, its deletion Operation starts. Names the Tenant only. | None |
| `tenancy.tenant.label_changed` | Tenancy | Success | A Tenant Owner changed a Tenant's environment label, other than removing Prod. Names the Tenant only. | None |
| `tenancy.tenant.prod_label_removed` | Tenancy | Success | A Tenant Owner removed a Tenant's Prod label after a fresh WebAuthn assertion. No setting changed with it. | None |

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
| Key operations | `keys.signing_key.created`, `keys.signing_key.promoted`, `keys.signing_key.promoted_unaged`, `keys.signing_key.revoked`, `keys.signing_key.rotated` | Proved |
| Management API grants | None yet | Pending: Story 17.2 |
| Token Family revocations | `sessions.access.revoked` | Proved |
| Rejected cross-Tenant attempts | `admin.cross_tenant.rejected`, `protocol.client.cross_tenant_rejected` | Proved |
