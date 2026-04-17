# syntax=docker/dockerfile:1.7
# gibson-tool-runner — one image hosting every CLI parser compiled into the
# Go binary. The image ships on debian:trixie-slim (not Kali) and installs
# only the tools the registered parsers exec. Adding a tool means one new
# apt/curl/go-install line here + a parser file in ./parsers/.
#
# Build:
#   docker build -t ghcr.io/zero-day-ai/gibson-tool-runner:<tag> .
#
# Run (smoke):
#   docker run --rm -e GIBSON_TOOL_INPUT_B64=... -e GIBSON_TOOL_NAME=nmap \
#     ghcr.io/zero-day-ai/gibson-tool-runner:<tag>

# Pin the runtime base by digest in production releases. :trixie-slim is
# fine for dev iteration; CI overrides via --build-arg BASE=debian@sha256:...
# for reproducibility.
ARG BASE=debian:trixie-slim

########################
# Stage 1 — build binary
########################
FROM golang:1.25-bookworm AS build

WORKDIR /src

# Dependencies first for layer caching.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Source.
COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/gibson-runner \
        ./cmd/gibson-runner

########################
# Stage 2 — runtime
########################
FROM ${BASE}

# Installed tools: curated for the currently-registered parsers. Grow this
# list as parsers land. Keep --no-install-recommends + clean to minimise
# image size and attack surface.
#
#   nmap                — parsers/nmap
#   httpx-toolkit (TBD) — parsers/httpx (ProjectDiscovery; installed via
#                          the published binary below since Debian
#                          trixie's httpx package is the wrong project)
#   ca-certificates + curl  — needed for go-installed binaries to dial TLS.
#
# Additional parsers (nuclei, subfinder, etc.) follow the same pattern:
# either apt-installable or fetch the pinned upstream binary via curl.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        curl \
        jq \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery httpx + nuclei — install from upstream releases.
# Tag-pinned so image builds are reproducible.
ARG HTTPX_VERSION=1.6.10
ARG NUCLEI_VERSION=3.3.7
ARG TARGETARCH=amd64

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) PD_ARCH="amd64" ;; \
      arm64) PD_ARCH="arm64" ;; \
      *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${PD_ARCH}.zip"; \
    curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${PD_ARCH}.zip"; \
    apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*; \
    mkdir -p /tmp/httpx /tmp/nuclei; \
    unzip -o /tmp/httpx.zip -d /tmp/httpx; \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei; \
    mv /tmp/httpx/httpx /usr/local/bin/httpx; \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    chmod +x /usr/local/bin/httpx /usr/local/bin/nuclei; \
    rm -rf /tmp/httpx.zip /tmp/nuclei.zip /tmp/httpx /tmp/nuclei; \
    apt-get purge -y unzip && apt-get autoremove -y

# Runner binary.
COPY --from=build /out/gibson-runner /usr/local/bin/gibson-runner

# Run as an unprivileged user. Setec microVMs already isolate the process,
# but defence in depth: don't exec tools as root inside the guest.
RUN useradd --system --create-home --shell /usr/sbin/nologin runner
USER runner:runner
WORKDIR /home/runner

ENTRYPOINT ["/usr/local/bin/gibson-runner"]
