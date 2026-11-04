<!-- Generated from tests/Architecture/module-edges.txt. Do not edit. Regenerate: dotnet run --project tests/Architecture/Generator -->

# Module dependencies

Every solid arrow is one allowed direct dependency. Every dashed arrow is a composition root wiring a module's adapter registration. Transitive reach grants nothing. Every module and host may also reference Kernel, not drawn.

```mermaid
flowchart TD
  HostHosted[Host.Hosted]
  Protocol[Protocol]
  Authentication[Authentication]
  Identity[Identity]
  Sessions[Sessions]
  Tenancy[Tenancy]
  AdaptersLogging[Adapters.Logging]
  AdaptersHosting[Adapters.Hosting]
  HostAdmin[Host.Admin]
  Management[Management]
  Admins[Admins]
  Audit[Audit]
  AdaptersFido2[Adapters.Fido2]
  HostWorker[Host.Worker]
  Operations[Operations]
  Cli[Cli]
  AdaptersOpenBao[Adapters.OpenBao]
  AdaptersPostgres[Adapters.Postgres]
  Directory[Directory]
  Keys[Keys]
  Notifications[Notifications]
  TestsIsolation[Tests.Isolation]
  HostHosted --> Protocol
  HostHosted --> Authentication
  HostHosted --> Identity
  HostHosted --> Sessions
  HostHosted --> Tenancy
  HostHosted --> AdaptersLogging
  HostHosted --> AdaptersHosting
  HostAdmin --> Management
  HostAdmin --> Admins
  HostAdmin --> Audit
  HostAdmin --> AdaptersLogging
  HostAdmin --> AdaptersHosting
  HostAdmin -.-> AdaptersFido2
  HostWorker --> Operations
  HostWorker --> AdaptersLogging
  HostWorker --> AdaptersHosting
  Cli --> Operations
  Cli --> Admins
  Cli --> Audit
  Cli --> AdaptersOpenBao
  Cli --> AdaptersPostgres
  Protocol --> Authentication
  Protocol --> Directory
  Protocol --> Identity
  Protocol --> Sessions
  Protocol --> Keys
  Protocol --> Tenancy
  Authentication --> Directory
  Authentication --> Identity
  Authentication --> Sessions
  Authentication --> Notifications
  Authentication --> Tenancy
  Management --> Operations
  Management --> Directory
  Management --> Identity
  Management --> Sessions
  Management --> Keys
  Management --> Notifications
  Management --> Admins
  Management --> Audit
  Management --> Tenancy
  Operations --> Authentication
  Operations --> Directory
  Operations --> Identity
  Operations --> Sessions
  Operations --> Keys
  Operations --> Notifications
  Operations --> Audit
  Operations --> Admins
  Operations --> Tenancy
  Identity --> Sessions
  Identity --> Notifications
  Identity --> Tenancy
  Directory --> Sessions
  Directory --> Tenancy
  Keys --> Tenancy
  Sessions --> Tenancy
  Notifications --> Tenancy
  Admins --> Notifications
  AdaptersHosting --> AdaptersOpenBao
  TestsIsolation --> AdaptersFido2
  TestsIsolation --> AdaptersHosting
  TestsIsolation --> AdaptersLogging
  TestsIsolation --> AdaptersOpenBao
  TestsIsolation --> AdaptersPostgres
  TestsIsolation --> Admins
  TestsIsolation --> Audit
  TestsIsolation --> Authentication
  TestsIsolation --> Cli
  TestsIsolation --> Keys
  TestsIsolation --> Management
  TestsIsolation --> Operations
  TestsIsolation --> Sessions
  TestsIsolation --> Tenancy
```
