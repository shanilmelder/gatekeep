<!-- Generated from each module's Contracts/{Module}Events.cs. Do not edit. Regenerate: dotnet run --project tests/Architecture/Generator -->

# Audit event catalogue

Every audit type code Gatekeep writes, declared in its module's contract. Codes are `{domain}.{object}.{action}` and a public contract: removing or renaming a published code is a contract break, which the generator refuses and `AuditCatalogueTests` fails on.

| Code | Module | Summary | FR-40 class |
| --- | --- | --- | --- |
| `admin.credential.registered` | Admins | An Admin registered a WebAuthn credential. Holds no credential ID, public key, challenge or user handle. | None |
| `admin.setup.completed` | Admins | An Admin registered their second WebAuthn credential, which completed setup and made their Session full. | None |
| `audit.retention.checkpoint` | Audit | Retention deleted a chain's sealed prefix past the Log period. Names the last deleted row's epoch, seq and hash. | None |
| `authentication.signin_transaction.started` | Authentication | A sign-in transaction began for an Application. The caller is anonymous, so no person is named. | None |
| `bootstrap.admin.created` | Admins | The bootstrap token was claimed: the first Admin was created as Deployment Owner and bootstrap completed. Holds no token or hash. | None |
| `bootstrap.token.issued` | Admins | gatekeep init issued the first one-time bootstrap token. It expires 15 minutes after issue. Holds no token or hash. | None |
| `bootstrap.token.reissued` | Admins | gatekeep init reissued the bootstrap token, voiding the previous one. It expires 15 minutes after issue. Holds no token or hash. | None |
| `operations.job.dead` | Operations | A job used its last attempt and went dead. Only its fixed failure code is kept. | None |
| `sessions.access.revoked` | Sessions | Sessions in scope ended and their Token Families and tokens were revoked. User scope targets the User. | Session and token revocation |
| `sessions.session.started` | Sessions | A User's Session started. Names the User only: the Session ID is stored only as its hash. | None |

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
