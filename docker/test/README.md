# Multi-Distro Docker Testing

This directory contains Docker-based testing infrastructure to validate Assassinate installation across multiple Linux distributions before pushing to CI/CD.

## Available Distributions

- **Kali Linux** (`kalilinux/kali-rolling`) - Primary pentesting distro
- **Ubuntu** (`ubuntu:24.04`) - Wide user base
- **Debian** (`debian:bookworm`) - Stable baseline
- **Arch Linux** (`archlinux:latest`) - Rolling release, bleeding edge
- **Fedora** (`fedora:latest`) - Red Hat ecosystem

## Prerequisites

- Docker installed and running
- Docker Compose installed
- Sufficient disk space (~5-10GB per distro)

## Quick Start

### Test All Distributions

```bash
cd docker/test
./test-distros.sh
```

### Test Specific Distribution

```bash
# Test Ubuntu only
./test-distros.sh ubuntu

# Test Kali only
./test-distros.sh kali

# Test Arch only
./test-distros.sh arch
```

### Clean Up

```bash
# Remove all test containers and images
./test-distros.sh clean
```

## What Gets Tested

Each test:
1. Builds a fresh container from the official base image
2. Installs system dependencies for that distro
3. Installs Rust toolchain
4. Clones/installs Metasploit Framework
5. Builds the Assassinate Rust bridge
6. Runs the bridge unit tests

## Manual Testing

You can also use Docker Compose directly:

```bash
# Build specific service
docker compose build ubuntu-test

# Build all services
docker compose build

# Run a specific test container interactively
docker compose run --rm ubuntu-test /bin/bash
```

## Expected Build Times

Approximate times (varies by hardware and network):

- **Kali**: 5-10 minutes (MSF pre-installed)
- **Ubuntu**: 15-20 minutes (needs MSF clone)
- **Debian**: 15-20 minutes (needs MSF clone)
- **Arch**: 10-15 minutes (package updates)
- **Fedora**: 10-15 minutes (DNF updates)

## Troubleshooting

### Build Fails

Check the Docker build output for the specific error:

```bash
docker compose build ubuntu-test --progress=plain
```

### Out of Disk Space

Clean up old images:

```bash
./test-distros.sh clean
docker system prune -a
```

### Network Issues

Some distros may have network-related issues with package managers. Try:

```bash
docker compose build --no-cache ubuntu-test
```

## CI/CD Integration

Once tests pass locally, the same Docker configurations can be used in GitHub Actions CI/CD pipeline with minimal modifications.

## Notes

- Builds are **not cached** between runs for consistency
- Each build starts from a clean base image
- Tests run as non-root user (`testuser`) to match real-world usage
- PostgreSQL is configured but not started (not needed for bridge tests)
