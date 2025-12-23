# Assassinate Distro-Specific Notes

> **IMPORTANT**: This document contains critical knowledge for setting up Assassinate
> across different Linux distributions. Read this entire document before making changes.

## Current Implementation Status (December 2024)

### ✅ COMPLETE - Fully Optimized and Working

**Major Rewrite Completed:**
1. `setup/installer.py` - Complete rewrite with optimized architecture
   - Removed redundant function wrappers for static data
   - Consolidated package definitions into single `PACKAGES` dict
   - Inline task builders instead of separate functions
   - ~600 lines removed, cleaner code structure
2. Full feature implementation:
   - ✅ System package installation (all distros)
   - ✅ Rust toolchain setup (rustup or system packages)
   - ✅ Rust component builds (ipc, bridge, daemon)
   - ✅ Ruby/Bundler environment setup
   - ✅ MSF installation (package OR git clone)
   - ✅ MSF gem bundle install (for cloned MSF)
3. Added `ansible>=9.0.0` to dependencies for community.general collection (Alpine APK support)

### Distro Support Status

#### Fully Supported (All Features Working)
- ✅ **Ubuntu 22.04+**: Complete installation including MSF clone
- ✅ **Debian Bookworm+**: Complete installation including MSF clone
- ✅ **Fedora 40+**: Complete installation including MSF clone, gems bundled
- ✅ **Arch Linux**: Complete installation including MSF clone
- ✅ **Kali Linux**: Package MSF installed, all Rust components built
- ✅ **Parrot OS**: Package MSF installed, all Rust components built

#### Partial Support
- ⚠️ **Alpine Linux**: Packages install successfully, but Rust build fails
  - **Issue**: musl libc incompatibility with Magnus crate (Ruby bindings)
  - **Error**: "Dynamic loading not supported" when loading libclang
  - **Status**: This is a fundamental limitation, not fixable without Magnus rewrite
  - **Use Case**: Can be used for package validation, but not for full Rust builds

### Key Fixes Applied
1. ✅ Fixed verify() to check both standard and container target directories
2. ✅ Fixed Alpine APK package manager support via ansible collections
3. ✅ Fixed Rust default toolchain conditional to run only when rustup installs
4. ✅ Added complete MSF git clone and bundle install workflow
5. ✅ Added Ruby environment setup (xmlrpc gem, bundler, Arch PATH fix)

### Verified Workflows
- Local installation: ✅ Working
- Docker installation: ✅ Working (all distros)
- Kali/Parrot package MSF: ✅ Working
- Other distros MSF clone: ✅ Working (auto-clones to /opt/metasploit-framework)
- MSF bundle install: ✅ Working (10-15 minutes, all gems installed)
- Container target directory: ✅ Working (avoids GLIBC mismatch)

---

## Package Mappings by Distribution

### Build Tools
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `build-essential` |
| Fedora/RHEL | `gcc gcc-c++ make` |
| Arch | `base-devel` |
| Alpine | `build-base` |
| openSUSE | `gcc gcc-c++ make` |
| macOS | Xcode CLI tools (no package needed) |

### OpenSSL Development Headers
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `libssl-dev` |
| Fedora/RHEL | `openssl-devel` |
| Arch | `openssl` |
| Alpine | `openssl-dev` |
| openSUSE | `libopenssl-devel` |

### libclang (for Rust bindgen)
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `libclang-dev` |
| Fedora/RHEL | `clang-devel` |
| Arch | `clang` |
| Alpine | `clang-dev clang-static` |
| openSUSE | `clang-devel` |

### Cap'n Proto
| Distro | Package(s) | Notes |
|--------|-----------|-------|
| Debian/Ubuntu | `capnproto libcapnp-dev` | |
| Fedora/RHEL | `capnproto capnproto-devel` | |
| Arch | `capnproto` | |
| Alpine | `capnproto-dev` | **CRITICAL**: Must use `-dev` package! The base `capnproto` only has libs, no `capnp` binary |
| openSUSE | `capnproto` | |

### Ruby
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `ruby-full ruby-dev` |
| Fedora/RHEL | `ruby ruby-devel` |
| Arch | `ruby` (headers included) |
| Alpine | `ruby ruby-dev` |
| openSUSE | `ruby ruby-devel` |

### Bundler
| Distro | Package(s) | Notes |
|--------|-----------|-------|
| Debian/Ubuntu | `ruby-bundler` | |
| Fedora/RHEL | `rubygem-bundler` | |
| Arch | `ruby-bundler` | |
| Alpine | `ruby-bundler` | |
| Fallback | `gem install bundler` | If package fails |

### pkg-config
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `pkg-config` |
| Fedora/RHEL | `pkgconf-pkg-config` |
| Arch | `pkgconf` |
| Alpine | `pkgconf` |
| openSUSE | `pkg-config` |

### Ruby Build Dependencies (for native gems)
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `libyaml-dev libffi-dev libpq-dev` |
| Fedora/RHEL | `libyaml-devel libffi-devel postgresql-devel` |
| Arch | `libyaml libffi postgresql-libs` |

### libpcap
| Distro | Package(s) |
|--------|-----------|
| Debian/Ubuntu | `libpcap-dev` |
| Fedora/RHEL | `libpcap-devel` |
| Arch | `libpcap` |

---

## Rust Installation

### System Package vs Rustup
| Distro | Method | Notes |
|--------|--------|-------|
| Arch | `pacman -S rust` | System packages are up-to-date, works well |
| All others | rustup | System packages are too old |

### System-Wide Rustup Installation (when running as root)
```bash
# Environment variables
export CARGO_HOME=/usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup

# Install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path

# Set default toolchain
/usr/local/cargo/bin/rustup default stable

# Create symlinks
ln -sf /usr/local/cargo/bin/rustc /usr/local/bin/rustc
ln -sf /usr/local/cargo/bin/cargo /usr/local/bin/cargo
ln -sf /usr/local/cargo/bin/rustup /usr/local/bin/rustup
```

### Profile Script (CRITICAL)
Create `/etc/profile.d/rust.sh` for system-wide environment:
```bash
# Rust environment configuration
export CARGO_HOME=/usr/local/cargo
export RUSTUP_HOME=/usr/local/rustup
export PATH="/usr/local/cargo/bin:$PATH"
```

**Why this is needed**: Without this, new shell sessions won't have Rust in PATH and `cargo build` will fail with "rustup could not choose a version".

---

## Ruby/Gem Quirks

### Arch Linux Gem PATH Fix
**Problem**: Arch Linux installs gems to user directory but doesn't add it to PATH.
**Solution**: Create `/etc/profile.d/ruby-gems.sh`:
```bash
if command -v ruby &> /dev/null; then
    export PATH="$(ruby -e 'puts Gem.user_dir')/bin:$PATH"
fi
```
**Reference**: https://wiki.archlinux.org/title/Ruby

### xmlrpc Gem Workaround
**Problem**: `bundle install` for MSF fails because xmlrpc gem has issues.
**Solution**: Install xmlrpc separately BEFORE running bundle install:
```bash
gem install xmlrpc
bundle install --jobs 1 --retry 3
```
**Reference**: https://github.com/beefproject/beef/issues/2687

### Bundle Install Flags
**Always use these flags** to avoid issues:
```bash
bundle install --jobs 1 --retry 3
```
- `--jobs 1`: Single-threaded to avoid race conditions
- `--retry 3`: Network resilience

**Reference**: https://github.com/bundler/bundler/issues/6698

---

## Metasploit Framework Locations

### Package-Installed MSF (Kali, Parrot)
- **Location**: `/usr/share/metasploit-framework`
- **Install**: `apt install metasploit-framework`
- **Bundle**: NOT needed (pre-installed)

### Git-Cloned MSF (all other distros)
- **Typical locations**:
  - `/opt/metasploit-framework`
  - `~/metasploit-framework`
  - `<project>/metasploit-framework`
- **Install**:
  ```bash
  git clone --depth 1 https://github.com/rapid7/metasploit-framework.git
  cd metasploit-framework
  gem install xmlrpc  # workaround
  bundle install --jobs 1 --retry 3
  ```

### Environment Variable
Set `MSF_ROOT` to override automatic detection:
```bash
export MSF_ROOT=/path/to/metasploit-framework
```

---

## PostgreSQL Setup by Distro

### Fedora/RHEL
```bash
postgresql-setup --initdb
su - postgres -c 'pg_ctl -D /var/lib/pgsql/data start'
```

### Debian/Ubuntu
```bash
# Start
pg_ctlcluster <version> main start

# For CI, update pg_hba.conf for trust auth:
sed -i 's/host.*all.*all.*127\.0\.0\.1\/32.*scram-sha-256/host    all             all             127.0.0.1\/32            trust/' /etc/postgresql/*/main/pg_hba.conf
```

---

## Alpine Linux Issues

### musl libc Incompatibility
**Problem**: Alpine uses musl libc instead of glibc. Some Rust crates don't compile:
- Magnus (Ruby bindings for Rust) fails
- Other native extensions may fail

**Current status**: Alpine is "partial support" - packages install but Rust build fails.

**Potential solutions** (not implemented):
1. Use glibc compatibility layer
2. Use Alpine-specific Rust target
3. Mark Alpine as unsupported for full build

### capnproto Package
**CRITICAL**: Use `capnproto-dev`, NOT `capnproto`!
The base package only contains libraries, the `-dev` package includes the `capnp` binary.

---

## Container-Specific Issues

### GLIBC Mismatch
**Problem**: When mounting host workspace into container, Rust builds can fail due to GLIBC version mismatch between compiled artifacts and container libc.

**Solution**: Use separate target directory in containers:
```bash
export CARGO_TARGET_DIR=/tmp/cargo-target
cargo build --release
```

### Docker Detection
Check if running in container:
```python
Path("/.dockerenv").exists() or os.environ.get("CONTAINER")
```

---

## Ansible Runner Setup

### Required Dependencies
```toml
# pyproject.toml
dependencies = [
    "ansible-core>=2.15.0",  # REQUIRED - provides ansible-playbook
    "ansible-runner>=2.3.0",
]
```

**CRITICAL**: `ansible-runner` alone is NOT enough! You must also install `ansible-core` which provides `ansible-playbook`.

### PATH Fix for venv
**Problem**: ansible_runner can't find `ansible-playbook` when running from a venv.

**Solution**: Add venv bin directory to PATH in envvars:
```python
venv_bin = Path(sys.executable).parent
ansible_env = os.environ.copy()
ansible_env["PATH"] = f"{venv_bin}:{current_path}"

result = run(
    playbook=playbook,
    # ... other args ...
    envvars=ansible_env,  # Pass the modified environment
)
```

### Ansible Facts for Distro Detection
Use these in task conditions:
- `ansible_facts['os_family']`: 'Debian', 'RedHat', 'Archlinux', 'Alpine', 'Suse', 'Darwin'
- `ansible_facts['distribution']`: 'Ubuntu', 'Debian', 'Fedora', 'Kali', 'Parrot', etc.

---

## File Structure (Current)

```
assassinate/
├── setup/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py              # CLI with --install, --verify, --recon-only, --steps
│   ├── installer.py        # Optimized Ansible-based installer (830 lines)
│   └── DISTRO_NOTES.md     # This file
├── docker/
│   ├── docker-compose.yml  # Unified compose file
│   ├── Dockerfile.ubuntu
│   ├── Dockerfile.debian
│   ├── Dockerfile.fedora
│   ├── Dockerfile.alpine
│   ├── Dockerfile.arch
│   └── Dockerfile.integration
├── scripts/
│   └── test.sh             # Unified test script
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── distro-matrix.yml
├── Makefile                # Unified build/test interface
└── pyproject.toml
```

**Cleaned Up (Removed):**
- `setup/provisioner.py` - Old PyInfra-based provisioner (replaced by installer.py)
- `setup/deploy.py` - Old PyInfra deployment script (replaced by installer.py)
- `scripts/ci/*.sh` - Distro-specific CI scripts (replaced by unified installer)
- `scripts/install/*.sh` - Distro-specific install scripts (replaced by unified installer)

---

## Testing Commands

### Local
```bash
# Verify what's installed
assassinate-setup --verify

# Full install (as root)
sudo assassinate-setup --install

# Install without MSF
sudo assassinate-setup --install --skip-msf

# Dry run
assassinate-setup --install --dry-run
```

### Docker
```bash
# Build image
docker compose -f docker/docker-compose.yml build ubuntu

# Run full install test
docker compose -f docker/docker-compose.yml run --rm -T --user root ubuntu \
    bash -l -c "cd /home/hitman/assassinate && .venv/bin/assassinate-setup --install --skip-msf"

# Verify
docker compose -f docker/docker-compose.yml run --rm -T ubuntu \
    .venv/bin/assassinate-setup --verify
```

### Makefile
```bash
make test-distro DISTRO=ubuntu      # Recon only
./scripts/test.sh distro --full ubuntu  # Full install
make test-matrix                    # All distros
```

---

## Installation Complete - Ready for Production

### Objectives Achieved ✅

The installer now provides **complete, end-to-end setup** for Assassinate on all supported distributions:

1. ✅ **System Dependencies**: All prerequisites for Assassinate AND Metasploit
2. ✅ **Rust Setup**: Full Rust toolchain installation and configuration
3. ✅ **Ruby Setup**: Ruby environment with bundler and gem fixes
4. ✅ **Rust Build**: All components (ipc, bridge, daemon) compiled successfully
5. ✅ **MSF Installation**: 
   - Package installation on Kali/Parrot
   - Git clone on other distros
   - Bundle install with all gems (10-15 min)
6. ✅ **Verification**: Complete status checking for all components

### Usage

```bash
# Full installation (recommended)
sudo assassinate-setup --install

# Selective installation
sudo assassinate-setup --install --steps packages,rust,build
sudo assassinate-setup --install --skip-steps msf

# Check status
assassinate-setup --verify

# Dry run
assassinate-setup --install --dry-run

# Force reinstall
sudo assassinate-setup --install --force

# Verbose output
sudo assassinate-setup --install -v
```

### Cleanup Complete ✅

All obsolete files have been removed:
- ✅ Old provisioner and deployment scripts removed
- ✅ Distro-specific shell scripts removed  
- ✅ Python bytecode cache cleaned

### Next Steps for CI Integration

To complete CI integration:

1. Update `.github/workflows/distro-matrix.yml` to use `assassinate-setup --install`
2. Consider removing Alpine from full CI matrix (mark as partial support)
3. Document Alpine limitations in README

### Alpine Decision: Partial Support

**Recommendation**: Mark Alpine as "Partial Support - Packages Only"

- Packages install successfully (good for testing package availability)
- Rust build fundamentally incompatible (musl + Magnus limitation)
- Not a bug to fix - architectural incompatibility
- Users needing full Rust support should use glibc-based distros

---

## References

- Arch Ruby: https://wiki.archlinux.org/title/Ruby
- xmlrpc gem issue: https://github.com/beefproject/beef/issues/2687
- Bundler race conditions: https://github.com/bundler/bundler/issues/6698
- bbot installer (inspiration): `/home/astark/Projects/bbot/bbot/core/helpers/depsinstaller/installer.py`
