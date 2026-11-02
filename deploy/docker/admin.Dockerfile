# Host.Admin: Admin Dashboard and Management API (Z-2).
# Built locally from this repository (AD-26): docker compose -f deploy/compose.yaml build.
# Base images are pinned by digest. Signing is Story 12.5.
#
# The runtime image is Ubuntu chiseled: no shell, no package manager, no HTTP client.
# The healthcheck runs this binary with --health-probe instead.

# Only the project and lock files, so restore below stays cached while source changes:
# a COPY layer is cached by its contents.
FROM mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS projects
WORKDIR /src
COPY src/ src/
RUN find src -type f ! -name '*.csproj' ! -name 'packages.lock.json' -delete

FROM mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
WORKDIR /src
ENV DOTNET_NOLOGO=true \
    DOTNET_CLI_TELEMETRY_OPTOUT=true

# Build rules, the edge list the build checks, then every project and lock file.
COPY global.json nuget.config Directory.Build.props Directory.Build.targets Directory.Packages.props ./
COPY tests/Architecture/module-edges.txt tests/Architecture/
COPY --from=projects /src/ ./
RUN dotnet restore src/Gatekeep.Host.Admin/Gatekeep.Host.Admin.csproj --locked-mode

COPY src/ src/
RUN dotnet publish src/Gatekeep.Host.Admin/Gatekeep.Host.Admin.csproj --no-restore --configuration Release --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled@sha256:c89a6a61f494f20a5ae302990e814627a8d91b332fd4a8e7c1707c2d4da9555d
WORKDIR /app
COPY --from=build /app ./

# No diagnostics IPC socket, and no default HTTP port: the host binds its own (Kestrel).
ENV DOTNET_EnableDiagnostics=0 \
    ASPNETCORE_HTTP_PORTS=

# A uid of its own, distinct per host, so a secret file can be readable by one host only.
USER 10002:10002

ENTRYPOINT ["dotnet", "/app/Gatekeep.Host.Admin.dll"]
