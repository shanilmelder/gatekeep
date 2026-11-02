# Host.Admin: Admin Dashboard and Management API (Z-2).
# Built locally from this repository (AD-26): docker compose -f deploy/compose.yaml build.
# Base images are pinned by digest. Releases are built, signed and shipped with an SBOM
# by .github/workflows/release.yml: docs/release-signing.md.
#
# The runtime image is Ubuntu chiseled: no shell, no package manager, no HTTP client.
# The healthcheck runs this binary with --health-probe instead.
#
# The build context is filtered by admin.Dockerfile.dockerignore, which lets in the
# workspace the Admin Dashboard bundle needs (apps/, packages/) that .dockerignore keeps out
# of the other images.

# The Admin Dashboard bundle (AD-21): apps/admin-dashboard built by Vite, served by Host.Admin
# from its web root under the Admin CSP. Node is the image tests.Dockerfile pins, and pnpm the
# version package.json pins. pnpm's own install script runs, as in tests.Dockerfile, to put
# its native binary in place; the workspace install runs with scripts disabled (AD-25).
FROM node:26.13.0-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9 AS bundle
ENV PNPM_HOME=/usr/local/pnpm \
    PATH=/usr/local/pnpm:$PATH
RUN npm install --global pnpm@12.16.1 \
    && pnpm --version \
    && head -c 4 "$(readlink -f "$(command -v pnpm)")" | grep -q ELF
WORKDIR /src
# Every workspace manifest, so the frozen lockfile matches the workspace it describes.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.base.json ./
COPY apps/hosted-login/package.json apps/hosted-login/
COPY tests/browser/package.json tests/browser/
COPY packages/ packages/
COPY apps/admin-dashboard/ apps/admin-dashboard/
RUN pnpm install --frozen-lockfile --ignore-scripts --filter "@gatekeep/admin-dashboard..."
RUN pnpm --filter "@gatekeep/admin-dashboard..." run build \
    && test -f apps/admin-dashboard/dist/index.html

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
# The web root: Host.Admin serves the bundle from here, with the Admin CSP on every response.
COPY --from=bundle /src/apps/admin-dashboard/dist/ ./wwwroot/

# No diagnostics IPC socket, and no default HTTP port: the host binds its own (Kestrel).
ENV DOTNET_EnableDiagnostics=0 \
    ASPNETCORE_HTTP_PORTS=

# A uid of its own, distinct per host, so a secret file can be readable by one host only.
USER 10002:10002

ENTRYPOINT ["dotnet", "/app/Gatekeep.Host.Admin.dll"]
