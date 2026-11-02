# The build and test container (deploy/compose.test.yaml): the exact .NET SDK in
# global.json, Node and pnpm at the versions package.json pins, and the Docker CLI with
# Compose, so a machine needs only Docker and Git. Base images pinned by digest.
#
# Test only. It's the one container that gets the Docker socket, so Testcontainers can
# start PostgreSQL and OpenBao and the config tests can read the Compose files. No runtime
# service is built from it.

FROM node:26.13.0-bookworm-slim@sha256:bc0a2afd3b74ce12222fc8bab99271e66257f021078f5f4a5d687a77d280c1d9 AS node
FROM docker:29.8.1-cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca AS docker

# Only the project and lock files of src/ and tests/, for the cached restore below.
FROM mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS projects
WORKDIR /src
COPY src/ src/
COPY tests/ tests/
RUN find src tests -type f ! -name '*.csproj' ! -name 'packages.lock.json' -delete

FROM mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b

ENV DOTNET_NOLOGO=true \
    DOTNET_CLI_TELEMETRY_OPTOUT=true \
    PNPM_HOME=/usr/local/pnpm \
    PATH=/usr/local/pnpm:$PATH

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

# pnpm at the version package.json pins. Its own install script runs, because it puts
# pnpm's native binary in place of a shebang-less shim that tests can't spawn. That's the
# pinned tool only: the workspace install below still runs with scripts disabled (AD-25).
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && npm install --global pnpm@12.16.1 \
    && pnpm --version \
    && head -c 4 "$(readlink -f /usr/local/bin/pnpm)" | grep -q ELF

WORKDIR /src

# Restore first, from project and lock files only, so a source change keeps the cached
# restore: the COPY from the projects stage is cached by its contents.
COPY global.json nuget.config Directory.Build.props Directory.Build.targets Directory.Packages.props Gatekeep.slnx ./
COPY tests/Architecture/module-edges.txt tests/Architecture/
COPY --from=projects /src/ ./
RUN dotnet restore Gatekeep.slnx --locked-mode

COPY . .
RUN pnpm install --frozen-lockfile --ignore-scripts

CMD ["sh", "deploy/docker/run-tests.sh"]
