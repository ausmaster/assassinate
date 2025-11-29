#!/bin/bash
# Test script for Arch Linux (uses GitHub MSF)
set -e

echo '=== Testing Arch Linux - Installation and Tests ==='

# Update and install dependencies
pacman -Sy --noconfirm \
  base-devel curl git \
  openssl pkg-config clang libpcap \
  postgresql postgresql-libs \
  ruby libyaml libffi \
  capnproto python cmake

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

echo "Rust installed:"
rustc --version

# Clone MSF from GitHub
echo 'Cloning Metasploit Framework...'
git clone --depth 1 https://github.com/rapid7/metasploit-framework.git /tmp/metasploit-framework
export MSF_ROOT=/tmp/metasploit-framework

# Install MSF dependencies
cd /tmp/metasploit-framework
gem install bundler

# Fix PATH for Arch Linux gem executables
export PATH="$(ruby -e 'puts Gem.user_dir')/bin:$PATH"

gem install xmlrpc
bundle install --jobs 1 --retry 3

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

echo '=== Arch validation completed ==='