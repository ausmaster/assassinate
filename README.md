<p align="center">
  <a href="https://github.com/ausmaster/assassinate">
    <img src="./logo.png" alt="Assassinate Logo" width="400">
  </a>
</p>

# Assassinate

[![Rust](https://img.shields.io/badge/rust-1.91+-FF8400)](https://www.rust-lang.org)
[![Python Version](https://img.shields.io/badge/python-3.10--3.13-FF8400)](https://www.python.org)
[![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/ausmaster/assassinate/blob/main/LICENSE)
[![Tests](https://github.com/ausmaster/assassinate/actions/workflows/ci.yml/badge.svg)](https://github.com/ausmaster/assassinate/actions)
[![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

---

## 📚 Overview

**Assassinate** is a high-performance **Python interface** to the **Metasploit Framework** using an IPC-based architecture. Built with lock-free shared memory ring buffers and a Rust daemon that bridges to MSF via Ruby FFI, it provides native-level performance for security automation workflows.

### Key Features

- **Complete MSF Access**: Full Python API (Framework, Modules, Sessions, Payloads, Database, Jobs, Plugins)
- **High Performance**: MessagePack over lock-free shared memory (5-10x faster than JSON)
- **Async/Sync APIs**: Both `async/await` and synchronous interfaces
- **Production Ready**: 118 integration tests, comprehensive CI/CD across 6 Linux distributions
- **Multi-Platform**: Validated on Debian, Kali, Parrot, Ubuntu, Fedora, and Arch Linux

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Python Application                         │
│              assassinate Python Package                     │
└────────────────────┬────────────────────────────────────────┘
                     │ Async IPC Client
                     │ (MessagePack over Shared Memory)
┌────────────────────▼────────────────────────────────────────┐
│              Shared Memory Ring Buffers                     │
│         (Lock-free SPSC, /dev/shm/)                         │
└────────────────────┬────────────────────────────────────────┘
                     │ Binary Protocol
┌────────────────────▼────────────────────────────────────────┐
│                  Rust Daemon                                │
│         IPC Server + Ruby FFI Bridge                        │
│    (rust/daemon + rust/bridge + rust/ipc)                  │
└────────────────────┬────────────────────────────────────────┘
                     │ Magnus Ruby Embed
┌────────────────────▼────────────────────────────────────────┐
│                Metasploit Framework                         │
│                  (Ruby VM)                                  │
└─────────────────────────────────────────────────────────────┘
```

### Components

- **Python Package** (`assassinate/`) - Complete async/sync API with IPC client
- **Rust Daemon** (`rust/daemon/`) - IPC server handling RPC calls
- **Rust Bridge** (`rust/bridge/`) - Magnus-based Ruby FFI to MSF
- **IPC Library** (`rust/ipc/`) - MessagePack protocol, lock-free ring buffers, shared memory

---

## 📂 Project Structure

```plaintext
assassinate/
├── assassinate/              # Python package
│   ├── __init__.py
│   ├── bridge/              # High-level Python API
│   │   ├── core.py          # Framework, initialize()
│   │   ├── modules.py       # Module operations
│   │   ├── sessions.py      # Session management
│   │   ├── datastore.py     # DataStore operations
│   │   ├── payloads.py      # Payload generation
│   │   └── db.py            # Database operations
│   ├── ipc/                 # IPC client implementation
│   │   ├── client.py        # Async IPC client
│   │   ├── protocol.py      # MessagePack protocol
│   │   └── shm.py           # Shared memory interface
│   └── logging.py           # Structured logging
│
├── rust/                    # Rust components
│   ├── ipc/                 # IPC library
│   │   ├── src/
│   │   │   ├── protocol.rs  # MessagePack protocol
│   │   │   ├── ring_buffer.rs  # Lock-free SPSC buffer
│   │   │   └── shm.rs       # Shared memory management
│   │   └── Cargo.toml
│   ├── bridge/              # Ruby FFI bridge
│   │   ├── src/
│   │   │   ├── framework.rs # MSF Framework interface
│   │   │   ├── ruby_bridge.rs  # Magnus Ruby VM
│   │   │   └── error.rs     # Error handling
│   │   └── Cargo.toml
│   └── daemon/              # IPC daemon
│       ├── src/
│       │   └── main.rs      # Daemon server
│       └── Cargo.toml
│
├── tests/                   # Integration tests (118 tests)
│   ├── conftest.py          # Pytest fixtures
│   ├── test_framework_detailed.py
│   ├── test_module_detailed.py
│   ├── test_datastore.py
│   ├── test_payloads.py
│   ├── test_db.py
│   ├── test_jobs.py
│   ├── test_plugins.py
│   └── test_sessions.py
│
├── .github/workflows/       # CI/CD pipelines
│   ├── ci.yml              # Main CI (Rust + Python tests)
│   └── distro-matrix.yml   # Multi-distro validation
│
├── TESTING_GUIDE.md        # Complete testing documentation
├── pyproject.toml          # Python project config
└── README.md               # This file
```

---

## 📥 Installation

### Prerequisites

- **Python**: 3.10-3.13 with `uv` package manager
- **Rust**: 1.91+ (for building daemon)
- **Ruby**: 3.1+ (system Ruby)
- **Metasploit Framework**: 6.4+
- **PostgreSQL**: For full MSF functionality

### Quick Start

#### 1. Install System Dependencies

**Debian/Ubuntu/Kali/Parrot:**
```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential curl git \
  ruby-full ruby-dev \
  postgresql postgresql-contrib libpq-dev \
  libssl-dev pkg-config libclang-dev
```

**Fedora:**
```bash
sudo dnf install -y gcc gcc-c++ make curl git \
  ruby ruby-devel \
  postgresql postgresql-server postgresql-devel \
  openssl-devel clang-devel
```

**Arch Linux:**
```bash
sudo pacman -Syu --needed base-devel curl git \
  ruby postgresql clang openssl
```

#### 2. Install Metasploit Framework

**Kali/Parrot** (use package manager):
```bash
sudo apt-get install metasploit-framework
export MSF_ROOT=/usr/share/metasploit-framework
```

**Other distros** (clone from GitHub):
```bash
git clone --depth 1 https://github.com/rapid7/metasploit-framework.git ~/metasploit-framework
cd ~/metasploit-framework
gem install bundler
bundle install --jobs 4
export MSF_ROOT=$HOME/metasploit-framework
```

#### 3. Install Rust & Build Daemon

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/ausmaster/assassinate.git
cd assassinate

# Build all Rust components
cd rust/ipc && cargo build --release
cd ../bridge && cargo build --release
cd ../daemon && cargo build --release
```

#### 4. Install Python Package

```bash
# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install assassinate
cd /path/to/assassinate
uv sync
```

#### 5. Setup PostgreSQL & MSF Database

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Create database and user
sudo -u postgres psql -c "CREATE USER $USER SUPERUSER;"
sudo -u postgres psql -c "CREATE DATABASE msf_test OWNER $USER;"

# Create MSF database config
cd $MSF_ROOT
cat > config/database.yml <<EOF
development: &pgsql
  adapter: postgresql
  database: msf_test
  username: $USER
  password:
  host: localhost
  port: 5432
  pool: 200
  timeout: 5
test:
  <<: *pgsql
EOF

# Run migrations
cd $MSF_ROOT && bundle exec rake db:migrate
```

#### 6. Start Daemon

```bash
# Start the daemon (required for Python client)
./rust/daemon/target/release/daemon &

# Daemon runs in background, Python clients connect via shared memory
```

---

## 📖 Usage

### Python API

```python
from assassinate import initialize, Framework

# Initialize connection to daemon
initialize()

# Create framework instance
fw = Framework()

# Get MSF version
print(fw.version())

# List modules
exploits = fw.list_modules("exploit")
print(f"Available exploits: {len(exploits)}")

# Create and configure a module
mod = fw.create_module("exploit/unix/ftp/vsftpd_234_backdoor")
mod.set_option("RHOSTS", "192.168.1.100")

# Validate options
if mod.validate():
    print("Module ready to run!")

# Generate a payload
pg = fw.payloads()
raw_payload = pg.generate_raw("cmd/unix/reverse_bash", {
    "LHOST": "192.168.1.5",
    "LPORT": "4444"
})

# Encode payload
encoded = pg.encode(raw_payload, "x86/shikata_ga_nai")

# Access database
db = fw.db()
db.report_host(host="192.168.1.100", os_name="Linux")

# List sessions
sessions = fw.sessions()
session_ids = sessions.list()
```

### Async API

```python
from assassinate.ipc import AsyncIPCClient
import asyncio

async def main():
    async with AsyncIPCClient() as client:
        # Get MSF version
        version = await client.framework_version()
        print(f"MSF Version: {version}")

        # Create module
        mod_result = await client.framework_create_module("exploit/unix/ftp/vsftpd_234_backdoor")
        
        # Configure module
        await client.module_set_option({"key": "RHOSTS", "value": "192.168.1.100"})
        
        # Generate payload
        payload = await client.payloads_generate_raw(
            "cmd/unix/reverse_bash",
            {"LHOST": "192.168.1.5", "LPORT": "4444"}
        )

asyncio.run(main())
```

### API Reference

**IPC Client Methods:**

All methods support both sync and async operation via `AsyncIPCClient`:

- **Framework**: `framework_version()`, `framework_list_modules()`, `framework_create_module()`, `framework_search()`
- **Modules**: `module_set_option()`, `module_get_option()`, `module_validate()`, `module_check()`
- **Payloads**: `payloads_generate_raw()`, `payloads_generate_exe()`, `payloads_encode()`
- **Sessions**: `sessions_list()`, `sessions_get()`, `sessions_stop()`, `sessions_execute()`
- **Database**: `db_report_host()`, `db_report_service()`, `db_report_vuln()`, `db_report_cred()`
- **Jobs**: `jobs_list()`, `jobs_get()`, `jobs_kill()`
- **Plugins**: `plugins_list()`, `plugins_load()`, `plugins_unload()`
- **DataStore**: `datastore_get()`, `datastore_set()`, `datastore_delete()`

**High-Level Python API:**

The `assassinate.bridge` package provides a high-level, Pythonic wrapper:

```python
from assassinate.bridge import Framework

fw = Framework()
exploits = fw.list_modules("exploit")
mod = fw.create_module("exploit/...")
```

See API documentation in code docstrings.

---

## ⚙️ Environment Variables

Assassinate supports the following environment variables for configuration:

### MSF_ROOT

**Purpose:** Specifies the path to the Metasploit Framework installation.

**Used by:**
- Daemon (`rust/daemon`) - When `--msf-root` CLI argument is not provided
- Python scripts - When initializing MSF without explicit path

**Priority:**
1. CLI argument `--msf-root` (daemon only)
2. `MSF_ROOT` environment variable
3. Default: `/usr/share/metasploit-framework`

**Example:**
```bash
# For package-managed MSF (Kali/Parrot)
export MSF_ROOT=/usr/share/metasploit-framework

# For manually installed MSF
export MSF_ROOT=$HOME/metasploit-framework

# Start daemon with env var
./rust/daemon/target/release/daemon
```

### ASSASSINATE_WORKSPACE

**Purpose:** Specifies the MSF database workspace for credential operations.

**Used by:**
- Database credential reporting (`db.report_cred()`)

**Default:** `"default"`

**Example:**
```bash
export ASSASSINATE_WORKSPACE=pentest_project_1
uv run pytest tests/test_db.py
```

### ASSASSINATE_LOG_LEVEL

**Purpose:** Controls Python logging verbosity.

**Used by:**
- Python package logging system

**Valid values:** `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

**Default:** `WARNING`

**Example:**
```bash
# Enable debug logging for tests
ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v

# Quiet logging for production
ASSASSINATE_LOG_LEVEL=ERROR python my_script.py
```

### ASSASSINATE_LOG_FILE

**Purpose:** Specifies a file path for log output (in addition to console).

**Used by:**
- Python package logging system

**Default:** `None` (console only)

**Example:**
```bash
export ASSASSINATE_LOG_FILE=/var/log/assassinate.log
python my_script.py
```

### CARGO_TARGET_DIR

**Purpose:** Specifies the Cargo build output directory for Rust components.

**Used by:**
- Pytest fixtures to locate daemon binary
- CI/CD environments to share build artifacts

**Default:** `rust/daemon/target` (relative to project root)

**Example:**
```bash
# CI environments
export CARGO_TARGET_DIR=/tmp/cargo-target
cargo build --release
uv run pytest tests/
```

---

## ✅ Testing

### Test Suite (118 Tests)

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test module
uv run pytest tests/test_framework_detailed.py -v

# Run with debug logging
ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v
```

### Docker Testing

```bash
# Run tests in Docker (clean environment)
./scripts/test-with-docker.sh

# Rebuild from scratch
./scripts/test-with-docker.sh --rebuild

# Verbose output
./scripts/test-with-docker.sh --verbose
```

### Local CI Validation

```bash
# Run same checks as CI
./.github/scripts/test-ci-locally.sh
```

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for comprehensive testing documentation.

---

## 🚀 CI/CD

### Workflows

**Main CI** (`ci.yml`):
- Rust format & lint (all components)
- Python format & lint
- Build all Rust components
- Run Rust unit tests
- Run Python integration tests (118 tests)

**Multi-Distro** (`distro-matrix.yml`):
- Ubuntu 24.04 Full Test
- Kali Linux (package MSF)
- Parrot Security (package MSF)
- Debian, Ubuntu, Fedora, Arch (GitHub MSF)

All tests run on every PR. See [.github/CI_README.md](.github/CI_README.md) for details.

---

## 🔧 Development

### Code Quality

```bash
# Python formatting
uv run ruff format .

# Python linting
uv run ruff check .

# Python type checking
uv run mypy assassinate

# Rust formatting
cd rust/bridge && cargo fmt
cd rust/ipc && cargo fmt
cd rust/daemon && cargo fmt

# Rust linting
cd rust/bridge && cargo clippy -- -D warnings
```

### Building

```bash
# Build all Rust components
cd rust/ipc && cargo build --release
cd ../bridge && cargo build --release
cd ../daemon && cargo build --release

# Daemon will be at: rust/daemon/target/release/daemon
```

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

---

## 🗨️ Support

- **Issues**: [GitHub Issues](https://github.com/ausmaster/assassinate/issues)
- **Discord**: [Join our community](https://discord.com/invite/PZqkgxu5SA)
- **Documentation**: See [TESTING_GUIDE.md](TESTING_GUIDE.md)

---

## 🎯 Status & Roadmap

**Completed:**
- ✅ Complete Python IPC interface (async/sync)
- ✅ Comprehensive CI/CD across 6 Linux distributions
- ✅ 118 integration tests with full MSF validation
- ✅ Docker testing environment
- ✅ Structured logging (Python + Rust)
- ✅ MessagePack protocol (5-10x faster than JSON)
- ✅ Lock-free shared memory ring buffers

**Planned:**
- [ ] BBOT integration module
- [ ] Performance benchmarking suite
- [ ] Extended platform support (macOS, Windows)
- [ ] API documentation site
- [ ] PyPI package publication

---

## 🙏 Acknowledgments

- **Metasploit Framework** - For the incredible penetration testing platform
- **Magnus** - For excellent Ruby FFI library
- **Rust Community** - For amazing tooling and ecosystem
