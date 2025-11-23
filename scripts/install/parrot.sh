#!/bin/bash
# Assassinate installation script for Parrot OS
set -e

echo "========================================="
echo "Assassinate - Parrot OS Installation"
echo "========================================="

# Update package lists
echo "[1/6] Updating package lists..."
sudo apt-get update

# Install system dependencies
echo "[2/6] Installing system dependencies..."
sudo apt-get install -y \
    build-essential \
    curl \
    git \
    libssl-dev \
    pkg-config \
    libclang-dev \
    postgresql \
    postgresql-contrib \
    libpq-dev

# Install Rust
echo "[3/6] Installing Rust toolchain..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust already installed: $(rustc --version)"
fi

# Parrot OS comes with Metasploit pre-installed, verify it
echo "[4/6] Verifying Metasploit Framework..."
if ! command -v msfconsole &> /dev/null; then
    echo "ERROR: Metasploit Framework not found. Installing..."
    sudo apt-get install -y metasploit-framework
else
    echo "Metasploit Framework found: $(msfconsole --version | head -1)"
fi

# Setup PostgreSQL for MSF
echo "[5/6] Configuring PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create PostgreSQL user if needed
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$USER'" | grep -q 1; then
    sudo -u postgres createuser -s $USER || true
fi

# Build Assassinate Bridge
echo "[6/6] Building Assassinate Rust Bridge..."
cd "$(dirname "$0")/../.."
cd assassinate_bridge
cargo build --release

echo ""
echo "========================================="
echo "✅ Installation complete!"
echo "========================================="
echo ""
echo "Library location: $(pwd)/target/release/libassassinate_bridge.so"
echo ""
echo "To test the bridge:"
echo "  cd assassinate_bridge"
echo "  cargo test --release"
echo ""
