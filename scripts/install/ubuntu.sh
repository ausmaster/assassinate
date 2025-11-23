#!/bin/bash
# Assassinate installation script for Ubuntu
set -e

echo "========================================="
echo "Assassinate - Ubuntu Installation"
echo "========================================="

# Update package lists
echo "[1/7] Updating package lists..."
sudo apt-get update

# Install system dependencies
echo "[2/7] Installing system dependencies..."
sudo apt-get install -y \
    build-essential \
    curl \
    git \
    libssl-dev \
    pkg-config \
    libclang-dev \
    postgresql \
    postgresql-contrib \
    libpq-dev \
    ruby-full \
    ruby-dev

# Install Rust
echo "[3/7] Installing Rust toolchain..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust already installed: $(rustc --version)"
fi

# Clone Metasploit Framework
echo "[4/7] Cloning Metasploit Framework..."
if [ ! -d "$HOME/metasploit-framework" ]; then
    git clone https://github.com/rapid7/metasploit-framework.git "$HOME/metasploit-framework"
else
    echo "Metasploit Framework already cloned"
fi

# Install MSF dependencies
echo "[5/7] Installing Metasploit dependencies..."
cd "$HOME/metasploit-framework"
gem install bundler
bundle install

# Setup PostgreSQL
echo "[6/7] Configuring PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$USER'" | grep -q 1; then
    sudo -u postgres createuser -s $USER || true
fi

# Build Assassinate Bridge
echo "[7/7] Building Assassinate Rust Bridge..."
cd "$(dirname "$0")/../.."
cd assassinate_bridge
cargo build --release

echo ""
echo "========================================="
echo "✅ Installation complete!"
echo "========================================="
echo ""
echo "Metasploit Framework: $HOME/metasploit-framework"
echo "Library location: $(pwd)/target/release/libassassinate_bridge.so"
echo ""
echo "To test the bridge:"
echo "  cd assassinate_bridge"
echo "  export MSF_ROOT=$HOME/metasploit-framework"
echo "  cargo test --release"
echo ""
