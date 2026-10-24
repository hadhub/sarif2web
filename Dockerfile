FROM golang:1.25-bookworm AS go-toolchain
FROM rust:1.90-bookworm AS rust-toolchain
FROM node:24-bookworm-slim AS node-toolchain
FROM python:3.12-slim-bookworm

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget unzip nodejs npm ca-certificates \
    build-essential cmake pkg-config libssl-dev \
    default-jdk maven gradle ruby-full && \
    rm -rf /var/lib/apt/lists/*

# Toolchains needed by Go/Kotlin autobuild and Rust extraction.
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
ENV PATH="/usr/local/go/bin:/usr/local/cargo/bin:${PATH}"

# Semgrep (pip)
RUN pip install --no-cache-dir semgrep

# Gitleaks
ARG GITLEAKS_VERSION=8.24.0
RUN GITLEAKS_ARCH="x64"; \
    case "$(uname -m)" in aarch64|arm64) GITLEAKS_ARCH="arm64";; esac; \
    wget -qO /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" && \
    tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# TruffleHog
ARG TRUFFLEHOG_VERSION=3.88.26
RUN TRUFFLEHOG_ARCH="amd64"; \
    case "$(uname -m)" in aarch64|arm64) TRUFFLEHOG_ARCH="arm64";; esac; \
    wget -qO /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" && \
    tar xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Snyk (npm)
RUN npm install -g snyk

# CodeQL (binary from GitHub release)
ARG CODEQL_VERSION=2.27.2
RUN CODEQL_ARCH="linux64"; \
    case "$(uname -m)" in aarch64|arm64) CODEQL_ARCH="linux-arm64";; esac; \
    wget -qO /tmp/codeql.tar.gz \
    "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VERSION}/codeql-bundle-${CODEQL_ARCH}.tar.gz" && \
    mkdir -p /opt/codeql && \
    tar xzf /tmp/codeql.tar.gz -C /opt && \
    rm /tmp/codeql.tar.gz
ENV PATH="/opt/codeql:${PATH}"

# Keep Snyk and JavaScript projects on a supported Node.js runtime.
COPY --from=node-toolchain /usr/local/bin/node /usr/local/bin/node
COPY --from=node-toolchain /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "--timeout", "120", "app:app"]
