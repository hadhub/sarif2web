FROM python:3.12-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget unzip nodejs npm && \
    rm -rf /var/lib/apt/lists/*

# Semgrep (pip)
RUN pip install --no-cache-dir semgrep

# Gitleaks
ARG GITLEAKS_VERSION=8.24.0
RUN wget -qO /tmp/gitleaks.tar.gz \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" && \
    tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# TruffleHog
ARG TRUFFLEHOG_VERSION=3.88.26
RUN wget -qO /tmp/trufflehog.tar.gz \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" && \
    tar xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Snyk (npm)
RUN npm install -g snyk

# CodeQL (binary from GitHub release)
RUN wget -qO /tmp/codeql.tar.gz \
    "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz" && \
    mkdir -p /opt/codeql && \
    tar xzf /tmp/codeql.tar.gz -C /opt && \
    rm /tmp/codeql.tar.gz
ENV PATH="/opt/codeql:${PATH}"

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "--timeout", "120", "app:app"]
