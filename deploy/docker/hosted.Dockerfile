# Host.Hosted: OIDC, Hosted Login and Account Portal (Z-1).
# Built locally from this repository (AD-26): docker compose -f deploy/compose.yaml build.
# Base images are pinned by digest. Releases are built, signed and shipped with an SBOM
# by .github/workflows/release.yml: docs/release-signing.md.
#
# The runtime image is Ubuntu chiseled: no shell, no package manager, no HTTP client.
# The healthcheck runs this binary with --health-probe instead.
#
# The build context is filtered by the shared .dockerignore, which lets in the pnpm
# workspace (apps/, packages/) the Hosted Login bundle is built from.

# The Hosted Login bundle (AD-21, Story 4.1): apps/hosted-login built by Vite, served by
# Host.Hosted from its web root under /login/, each step page its index.html with the step and
# the Tenant's theme injected. Node builds it here and never reaches the runtime image. Node is
# the image tests.Dockerfile pins, and pnpm the version package.json pins. pnpm's own install
# script runs, as in tests.Dockerfile, to put its native binary in place; the workspace install
# runs with scripts disabled (AD-25).
FROM node:26.13.0-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9 AS bundle
ENV PNPM_HOME=/usr/local/pnpm \
    PATH=/usr/local/pnpm:$PATH
RUN npm install --global pnpm@12.16.1 \
    && pnpm --version \
    && head -c 4 "$(readlink -f "$(command -v pnpm)")" | grep -q ELF
WORKDIR /src
# Every workspace manifest, so the frozen lockfile matches the workspace it describes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY apps/admin-dashboard/package.json apps/admin-dashboard/
COPY tests/browser/package.json tests/browser/
COPY packages/ packages/
COPY apps/hosted-login/ apps/hosted-login/
RUN pnpm install --frozen-lockfile --ignore-scripts --filter "@gatekeep/hosted-login..."
RUN pnpm --filter "@gatekeep/hosted-login..." run build \
    && test -f apps/hosted-login/dist/index.html \
    && pnpm --filter @gatekeep/hosted-login run budget

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
RUN dotnet restore src/Gatekeep.Host.Hosted/Gatekeep.Host.Hosted.csproj --locked-mode

COPY src/ src/
RUN dotnet publish src/Gatekeep.Host.Hosted/Gatekeep.Host.Hosted.csproj --no-restore --configuration Release --output /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0.14-noble-chiseled@sha256:c89a6a61f494f20a5ae302990e814627a8d91b332fd4a8e7c1707c2d4da9555d
WORKDIR /app
COPY --from=build /app ./
# The web root: Host.Hosted serves the bundle's assets from here, and every step page from its index.html.
COPY --from=bundle /src/apps/hosted-login/dist/ ./wwwroot/

# No diagnostics IPC socket, and no default HTTP port: the host binds its own (Kestrel).
ENV DOTNET_EnableDiagnostics=0 \
    ASPNETCORE_HTTP_PORTS=

# A uid of its own, distinct per host, so a secret file can be readable by one host only.
USER 10001:10001

ENTRYPOINT ["dotnet", "/app/Gatekeep.Host.Hosted.dll"]
