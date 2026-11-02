# Gatekeep.Cli, the `cli` Compose service, run on demand:
#   docker compose -f deploy/compose.yaml run --rm cli migrate
# Built locally from this repository (AD-26): docker compose -f deploy/compose.yaml build.
# Base images are pinned by digest. Signing is Story 12.5.
#
# The runtime image is Ubuntu chiseled: no shell, no package manager, no HTTP client.
# It runs one command and exits, so it has no healthcheck and listens on no port.

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
RUN dotnet restore src/Gatekeep.Cli/Gatekeep.Cli.csproj --locked-mode

COPY src/ src/
RUN dotnet publish src/Gatekeep.Cli/Gatekeep.Cli.csproj --no-restore --configuration Release --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled@sha256:c89a6a61f494f20a5ae302990e814627a8d91b332fd4a8e7c1707c2d4da9555d
WORKDIR /app
COPY --from=build /app ./

# No diagnostics IPC socket.
ENV DOTNET_EnableDiagnostics=0

# A uid of its own, distinct from every host, so its secret files are readable by it only.
USER 10004:10004

ENTRYPOINT ["dotnet", "/app/gatekeep.dll"]
