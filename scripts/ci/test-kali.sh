#!/bin/bash
# Test script for Kali Linux (uses package MSF)
set -e

echo '=== Testing Kali Linux - Installation and Tests ==='

# Update and install dependencies
apt-get update -qq
apt-get install -y -qq \
  build-essential curl git \
  libssl-dev pkg-config libclang-dev libpcap-dev \
  postgresql postgresql-contrib libpq-dev \
  ruby-full ruby-dev libyaml-dev libffi-dev \
  capnproto libcapnp-dev python3-dev cmake \
  metasploit-framework

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

echo "Rust installed:"
rustc --version

# Set MSF_ROOT for package MSF
export MSF_ROOT=/usr/share/metasploit-framework
echo "Using MSF at: $MSF_ROOT"

# Build all Rust components in container-local target dir (avoid GLIBC mismatch)
export CARGO_TARGET_DIR=/tmp/cargo-target
echo 'Building Rust components...'
cd /workspace/rust/ipc && cargo build --release
cd /workspace/rust/bridge && cargo build --release
cd /workspace/rust/daemon && cargo build --release

echo 'Verifying builds...'
ls -lh /tmp/cargo-target/release/libbridge.*
ls -lh /tmp/cargo-target/release/daemon

# Run Rust unit tests
echo 'Running Rust unit tests...'
cd /workspace/rust/bridge
cargo test --release --lib

echo '=== Kali validation completed ==='