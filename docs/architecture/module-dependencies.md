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
  HostAdmin[Host.Admin]
  Management[Management]
  Admins[Admins]
  HostWorker[Host.Worker]
  Operations[Operations]
  Cli[Cli]
  AdaptersPostgres[Adapters.Postgres]
  Directory[Directory]
  Keys[Keys]
  Notifications[Notifications]
  Audit[Audit]
  TestsIsolation[Tests.Isolation]
  AdaptersOpenBao[Adapters.OpenBao]
  HostHosted --> Protocol
  HostHosted --> Authentication
  HostHosted --> Identity
  HostHosted --> Sessions
  HostHosted --> Tenancy
  HostHosted --> AdaptersLogging
  HostAdmin --> Management
  HostAdmin --> Admins
  HostAdmin --> AdaptersLogging
  HostWorker --> Operations
  HostWorker --> AdaptersLogging
  Cli --> Operations
  Cli --> Admins
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
  TestsIsolation --> AdaptersLogging
  TestsIsolation --> AdaptersOpenBao
  TestsIsolation --> AdaptersPostgres
  TestsIsolation --> Audit
  TestsIsolation --> Cli
```
