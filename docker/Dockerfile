# =============================================================================
# Assassinate - Multi-Distro Docker Image
# =============================================================================
#
# Supported distributions:
#   - Ubuntu (default)
#   - Debian
#   - Fedora
#   - Arch Linux
#   - Kali Linux
#   - Parrot OS
#
# Usage:
#   docker build -f docker/Dockerfile -t assassinate .
#   docker build -f docker/Dockerfile --build-arg DISTRO=fedora -t assassinate:fedora .
#   docker build -f docker/Dockerfile --build-arg DISTRO=kali -t assassinate:kali .
#
# =============================================================================

ARG DISTRO=ubuntu

# -----------------------------------------------------------------------------
# Base Image Selection
# -----------------------------------------------------------------------------

FROM ubuntu:24.04 AS base-ubuntu
FROM debian:bookworm AS base-debian
FROM fedora:40 AS base-fedora
FROM archlinux:latest AS base-arch
FROM kalilinux/kali-rolling:latest AS base-kali
FROM parrotsec/security:latest AS base-parrot

FROM base-${DISTRO} AS base

# -----------------------------------------------------------------------------
# Bootstrap - Install Python (the installer handles everything else)
# -----------------------------------------------------------------------------

ARG DISTRO=ubuntu

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install Python and curl - that's all we need to bootstrap
RUN case "${DISTRO}" in \
    ubuntu|debian|kali|parrot) \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv curl ca-certificates git && \
    rm -rf /var/lib/apt/lists/* ;; \
    fedora) \
    dnf install -y python3 python3-pip curl ca-certificates git findutils && \
    dnf clean all ;; \
    arch) \
    pacman -Sy --noconfirm python python-pip curl ca-certificates git && \
    pacman -Scc --noconfirm ;; \
    esac

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mkdir -p /usr/local/bin && \
    ln -sf /root/.local/bin/uv /usr/local/bin/uv && \
    ln -sf /root/.local/bin/uvx /usr/local/bin/uvx

# -----------------------------------------------------------------------------
# Build - Run the unified installer
# -----------------------------------------------------------------------------

WORKDIR /app

COPY pyproject.toml uv.lock LICENSE README.md ./
COPY python/ ./python/
COPY rust/ ./rust/

RUN uv sync --all-extras

ARG SKIP_MSF=false

# The installer handles ALL distro-specific logic via Ansible
RUN . .venv/bin/activate && \
    if [ "${SKIP_MSF}" = "true" ]; then \
    assassinate-setup --install --force --skip-steps msf; \
    else \
    assassinate-setup --install --force; \
    fi

# Verify
RUN . .venv/bin/activate && \
    assassinate-setup --verify || true

# Create .msf4 directory for database config (mounted at runtime)
RUN mkdir -p /root/.msf4

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

RUN case "${DISTRO}" in \
    ubuntu|debian|kali|parrot) \
    apt-get clean && rm -rf /var/lib/apt/lists/* ;; \
    fedora) \
    dnf clean all ;; \
    arch) \
    pacman -Scc --noconfirm ;; \
    esac

# -----------------------------------------------------------------------------
# Runtime Configuration
# -----------------------------------------------------------------------------

ENV PATH="/app/.venv/bin:/usr/local/cargo/bin:${PATH}" \
    CARGO_HOME="/usr/local/cargo" \
    RUSTUP_HOME="/usr/local/rustup" \
    MSF_ROOT="/opt/metasploit-framework"

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from python.assassinate import *" || exit 1

CMD ["python3", "-m", "assassinate", "--help"]
