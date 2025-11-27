# Testing Guide

This document provides comprehensive testing instructions for the Assassinate Rust FFI Bridge.

## Table of Contents

- [Testing Environment](#testing-environment)
- [Multi-Distro Testing](#multi-distro-testing)
- [Local Integration Tests](#local-integration-tests)
- [MSF Test Suite](#msf-test-suite)
- [CI/CD Testing](#cicd-testing)
- [Troubleshooting](#troubleshooting)

---

## Testing Environment

### Supported Distributions

The bridge has been validated on the following Linux distributions:

| Distribution | Version | Status |
|--------------|---------|--------|
| Debian | 12 (Bookworm) | ✅ Passing |
| Kali Linux | Rolling | ✅ Passing |
| Parrot Security | Latest | ✅ Passing |
| Ubuntu | 24.04 LTS | ✅ Passing |
| Fedora | Latest | ✅ Passing |
| Arch Linux | Rolling | ✅ Passing |

### Prerequisites

- Docker and Docker Compose (for multi-distro testing)
- Rust 1.91+ with cargo
- Ruby 3.1+ with bundler
- Metasploit Framework 6.4+
- PostgreSQL (for full MSF functionality)

---

## Multi-Distro Testing

The project includes `docker-compose.test.yml` for testing across all supported distributions.

### Start Test Containers

```bash
# Start all distro containers
docker-compose -f docker-compose.test.yml up -d

# Start a specific distro
docker-compose -f docker-compose.test.yml up -d kali
```

### Run Tests in Containers

#### Test All Distros

```bash
# Run this script to test all distros
for distro in debian kali parrot ubuntu fedora arch; do
  echo "Testing $distro..."
  docker exec test-$distro bash -c 'cd /workspace/assassinate_bridge && cargo test --release'
done
```

#### Test Specific Distro

**Debian/Ubuntu/Kali/Parrot:**
```bash
# Install dependencies
docker exec test-debian bash -c '
  apt-get update && apt-get install -y \
    build-essential curl git libssl-dev pkg-config \
    libclang-dev libpcap-dev postgresql libpq-dev \
    ruby-full ruby-dev libyaml-dev libffi-dev
'

# Install Rust
docker exec test-debian bash -c '
  curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
'

# Clone and setup MSF
docker exec test-debian bash -c '
  cd /tmp && \
  git clone --depth=1 https://github.com/rapid7/metasploit-framework.git && \
  cd metasploit-framework && \
  gem install bundler && \
  bundle install --jobs 4
'

# Run bridge tests
docker exec test-debian bash -c '
  . $HOME/.cargo/env && \
  cd /workspace/assassinate_bridge && \
  MSF_ROOT=/tmp/metasploit-framework cargo test --release --test integration_tests
'
```

**Fedora:**
```bash
# Install dependencies
docker exec test-fedora bash -c '
  dnf install -y gcc gcc-c++ make git openssl-devel \
    clang-devel libpcap-devel postgresql postgresql-server \
    postgresql-devel ruby ruby-devel libyaml-devel libffi-devel
'

# Rest is same as Debian...
```

**Arch Linux:**
```bash
# Install dependencies
docker exec test-arch bash -c '
  pacman -Syu --needed --noconfirm base-devel git rust \
    openssl clang libpcap postgresql ruby libyaml libffi
'

# Setup MSF with PATH fix for Arch
docker exec test-arch bash -c '
  cd /tmp && \
  git clone --depth=1 https://github.com/rapid7/metasploit-framework.git && \
  cd metasploit-framework && \
  gem install bundler && \
  export PATH="$(ruby -e \"puts Gem.user_dir\")/bin:$PATH" && \
  bundle install --jobs 4
'

# Run tests
docker exec test-arch bash -c '
  cd /workspace/assassinate_bridge && \
  MSF_ROOT=/tmp/metasploit-framework cargo test --release --test integration_tests
'
```

### Clean Up Containers

```bash
# Stop and remove all containers
docker-compose -f docker-compose.test.yml down

# Remove with volumes
docker-compose -f docker-compose.test.yml down -v
```

---

## Local Integration Tests

### Environment Setup

```bash
# Set MSF path (adjust to your installation)
export MSF_ROOT=/opt/metasploit-framework

# Optional: Set custom Ruby path
export RUBY=/path/to/ruby
```

### Run Integration Tests

```bash
cd assassinate_bridge

# Run all integration tests
cargo test --release --test integration_tests

# Run with verbose output
cargo test --release --test integration_tests -- --nocapture

# Run specific test
cargo test --release --test integration_tests -- test_all_metasploit_integration
```

### Test Output

Successful test output should show:

```
running 1 test

=== Test 01: Ruby VM initialization ===
✓ Ruby VM initialized successfully

=== Test 02: Metasploit loading ===
✓ Metasploit loaded successfully

=== Test 03: Framework creation ===
✓ Framework created successfully

...

=== ALL TESTS PASSED! ===

test test_all_metasploit_integration ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

---

## MSF Test Suite

Run the complete Metasploit Framework test suite through the bridge:

### Setup

```bash
cd /opt/metasploit-framework

# Ensure MSF dependencies are installed
bundle install
```

### Run Bridge Validation Tests

```bash
# Run framework spec with bridge helper
bundle exec rspec spec/lib/msf/core/framework_spec.rb \
  --require /path/to/assassinate/assassinate_bridge/spec/bridge_spec_helper_minimal.rb

# Run all MSF specs through bridge
bundle exec rspec \
  --require /path/to/assassinate/assassinate_bridge/spec/bridge_spec_helper_minimal.rb
```

### Expected Results

- **1,200+ examples:** Framework, modules, payloads, encoders
- **99.9% pass rate:** Only expected deprecation warnings
- **All core functionality:** Exploits, auxiliary, payloads, sessions

See `assassinate_bridge/MSF_TEST_RESULTS.md` for detailed test results.

---

## CI/CD Testing

### GitHub Actions Workflows

The project uses two CI/CD workflows:

#### 1. Assassinate Rust FFI Bridge CI
- **Trigger:** Every push and PR
- **Jobs:**
  - Format check (`cargo fmt`)
  - Lint check (`cargo clippy`)
  - Build (`cargo build`)
  - Unit tests (`cargo test --lib`)

#### 2. Multi-Distro Validation
- **Trigger:** Every push and PR to feature branches
- **Jobs:**
  - Full distro validation (6 parallel jobs)
  - MSF installation and bundle install
  - Bridge compilation and integration tests
  - Full 24.04 Ubuntu test (optional)

### Viewing CI/CD Results

```bash
# List recent workflow runs
gh run list --branch feature/multi-distro-testing

# View specific run
gh run view <run-id>

# View run logs
gh run view <run-id> --log

# View specific job logs
gh run view <run-id> --log --job <job-id>
```

### CI/CD Configuration

See `.github/workflows/` for workflow definitions:
- `ci.yml` - Basic Rust CI
- `distro-matrix.yml` - Multi-distro validation

---

## Troubleshooting

### Common Issues

#### Issue: MSF Path Not Found

```
Error: No such file or directory @ dir_s_chdir - /home/aus/PycharmProjects/assassinate/metasploit-framework
```

**Solution:** Set the correct MSF path:
```bash
export MSF_ROOT=/opt/metasploit-framework
cargo test --release --test integration_tests
```

#### Issue: Ruby Not Found

```
Error: Ruby not found or version incompatible
```

**Solution:** Set Ruby path explicitly:
```bash
export RUBY=/usr/bin/ruby  # Or your Ruby path
cargo build --release
```

#### Issue: Bundle Install Fails (Kali)

```
Bundler::GemNotFound: Could not find xmlrpc-0.3.3.gem for installation
```

**Solution:** Install xmlrpc separately first:
```bash
gem install xmlrpc
bundle install --jobs 4 --retry 3
```

#### Issue: Arch Linux - Bundle Not Found

```
bash: bundle: command not found
```

**Solution:** Add gem bin directory to PATH:
```bash
export PATH="$(ruby -e 'puts Gem.user_dir')/bin:$PATH"
bundle install --jobs 4
```

#### Issue: PostgreSQL Not Running

```
Error: could not connect to server: Connection refused
```

**Solution:** Start PostgreSQL service:
```bash
# Debian/Ubuntu
sudo systemctl start postgresql

# Fedora
sudo postgresql-setup --initdb
sudo systemctl start postgresql

# Arch
sudo systemctl start postgresql
```

### Debug Mode

Enable verbose output for debugging:

```bash
# Rust test verbose output
RUST_BACKTRACE=1 cargo test --release --test integration_tests -- --nocapture

# Ruby debug output
RUBY_DEBUG=1 cargo test --release --test integration_tests
```

### Getting Help

- **GitHub Issues:** [https://github.com/ausmaster/assassinate/issues](https://github.com/ausmaster/assassinate/issues)
- **Discord:** [https://discord.com/invite/PZqkgxu5SA](https://discord.com/invite/PZqkgxu5SA)
- **Documentation:** See [README.md](README.md) and [MSF_TEST_RESULTS.md](assassinate_bridge/MSF_TEST_RESULTS.md)

---

## Test Coverage Summary

| Test Category | Tests | Status |
|---------------|-------|--------|
| Ruby VM Integration | 3 | ✅ Passing |
| Framework Operations | 15+ | ✅ Passing |
| Module Management | 50+ | ✅ Passing |
| Payload Generation | 100+ | ✅ Passing |
| DataStore Operations | 20+ | ✅ Passing |
| Session Management | 10+ | ✅ Passing |
| Multi-Distro Validation | 6 distros | ✅ Passing |
| **Total MSF Examples** | **1,214+** | **99.9%** |

---

*Last Updated: 2025-11-27*
