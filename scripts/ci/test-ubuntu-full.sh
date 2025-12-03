#!/bin/bash
# Full test script for Ubuntu 24.04 - Includes Rust tests + Python integration tests
set -e

echo '=== Testing Ubuntu 24.04 - Full Test Suite ==='

# Update and install dependencies
apt-get update -qq
apt-get install -y -qq \
  build-essential curl git \
  libssl-dev pkg-config libclang-dev libpcap-dev \
  postgresql postgresql-contrib libpq-dev \
  ruby-full ruby-dev libyaml-dev libffi-dev \
  capnproto libcapnp-dev python3-dev cmake

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
gem install xmlrpc
bundle install --jobs 1 --retry 3

# Setup PostgreSQL
echo 'Setting up PostgreSQL...'
# Drop existing cluster and recreate properly
pg_dropcluster --stop 16 main || true
pg_createcluster 16 main --start

# Update pg_hba.conf to allow trust authentication for localhost
sed -i 's/host.*all.*all.*127\.0\.0\.1\/32.*scram-sha-256/host    all             all             127.0.0.1\/32            trust/' /etc/postgresql/16/main/pg_hba.conf
sed -i 's/host.*all.*all.*::1\/128.*scram-sha-256/host    all             all             ::1\/128                 trust/' /etc/postgresql/16/main/pg_hba.conf

# Reload PostgreSQL to apply config changes (must run as postgres user)
su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D /var/lib/postgresql/16/main reload"

# Create user and database (use explicit 'root' since we're running as root in container)
su - postgres -c "psql -c \"CREATE USER root SUPERUSER;\"" || echo "User may already exist"
su - postgres -c "psql -c \"CREATE DATABASE msf_test OWNER root;\"" || echo "Database may already exist"

# Create database.yml for MSF
cat > /tmp/metasploit-framework/config/database.yml <<EOF
development: &pgsql
  adapter: postgresql
  database: msf_test
  username: root
  password:
  host: localhost
  port: 5432
  pool: 200
  timeout: 5
production: &production
  <<: *pgsql
test:
  <<: *pgsql
EOF

# Run database migrations
cd /tmp/metasploit-framework
export RAILS_ENV=test
bundle exec rake db:migrate

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

# Install uv for Python
echo 'Installing uv...'
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# Install Python dependencies
echo 'Installing Python dependencies...'
cd /workspace
uv sync --all-extras

# Run Python integration tests
echo 'Running Python integration tests...'
export ASSASSINATE_LOG_LEVEL=WARNING
uv run pytest tests/ -v --tb=short

echo '=== Ubuntu 24.04 Full Test validation completed ==='
