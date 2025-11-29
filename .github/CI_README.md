# CI/CD Documentation

## Overview

The Assassinate project uses GitHub Actions for continuous integration and testing. The CI pipeline ensures code quality, build integrity, and comprehensive test coverage before merging changes.

## Workflows

### 1. Python IPC Interface CI (`python-ipc-ci.yml`)

**Purpose**: Complete validation of the Python IPC interface and all Rust components.

**Triggers**:
- Push to `main` or `feature/python-interface` branches
- Pull requests to `main`

**Jobs**:

#### `rust-checks` - Rust Code Quality
- Format checking (`cargo fmt`)
- Linting with Clippy (`cargo clippy`)
- Runs on: rust/ipc, rust/bridge, rust/daemon

#### `python-checks` - Python Code Quality
- Format checking (Ruff)
- Linting (Ruff)
- Type checking (MyPy - informational)

#### `build-rust` - Build All Components
- Build IPC library (shared message passing)
- Build Bridge library (Ruby FFI integration)
- Build Daemon binary (IPC server)
- Uploads daemon binary as artifact

#### `integration-tests` - Full Test Suite
- Sets up Metasploit Framework
- Configures PostgreSQL database
- Builds all Rust components
- Runs **118 Python integration tests**
- Test duration: ~60 seconds

#### `test-coverage` - Summary Report
- Generates GitHub Actions summary
- Shows test breakdown by category

## Test Suite Coverage (118 Tests)

### Framework Tests (11 tests)
- `test_framework_detailed.py`: Version, modules, search, threads, sessions

### Module Tests (31 tests)
- `test_module_detailed.py`: Creation, metadata, options, validation, capabilities

### DataStore Tests (11 tests)
- `test_datastore.py`: Framework and module-level option management

### Payload Tests (13 tests)
- `test_payloads.py`: Generation, encoding, executables

### Database Tests (22 tests)
- `test_db.py`: Hosts, services, vulnerabilities, credentials, loot

### Job Tests (8 tests)
- `test_jobs.py`: List, get, kill operations

### Plugin Tests (8 tests)
- `test_plugins.py`: List, load, unload operations

### Session Tests (22 tests)
- `test_sessions.py`: Metadata, properties, interaction

## Local Testing

### Quick Validation

Run the same checks that CI will run:

```bash
./.github/scripts/test-ci-locally.sh
```

This script validates:
- ✓ Rust formatting (all components)
- ✓ Rust linting (clippy)
- ✓ Python formatting (ruff)
- ✓ Python linting (ruff)
- ✓ All builds
- ✓ Full test suite (118 tests)

### Individual Checks

```bash
# Rust formatting
cd rust/ipc && cargo fmt -- --check
cd rust/bridge && cargo fmt -- --check
cd rust/daemon && cargo fmt -- --check

# Rust linting
cd rust/ipc && cargo clippy --all-targets -- -D warnings
cd rust/bridge && cargo clippy --all-targets -- -D warnings
cd rust/daemon && cargo clippy --all-targets -- -D warnings

# Python formatting
uv run ruff format --check .

# Python linting
uv run ruff check .

# Python type checking
uv run mypy assassinate

# Run tests
uv run pytest tests/ -v
```

## CI Requirements

### System Dependencies
- Ruby (full installation with dev headers)
- PostgreSQL (database for MSF)
- Build essentials (gcc, make, etc.)
- libclang-dev (for Rust FFI)
- pkg-config

### Rust Components
- Stable toolchain
- rustfmt (formatting)
- clippy (linting)

### Python Components
- Python 3.13
- uv (package manager)
- pytest (testing framework)
- ruff (formatting & linting)
- mypy (type checking)

## Success Criteria

All jobs must pass:
- ✅ No formatting violations
- ✅ No clippy warnings
- ✅ All builds succeed
- ✅ All 118 tests pass

## Artifacts

The CI pipeline uploads:
- `assassinate-daemon`: Daemon binary (7-day retention)
- `test-results`: Test reports and cache (7-day retention)

## Troubleshooting

### Build Failures

1. **Rust format errors**: Run `cargo fmt` in the failing component
2. **Clippy warnings**: Fix reported issues or add `#[allow(...)]` with justification
3. **Build errors**: Check for missing dependencies or version mismatches

### Test Failures

1. **MSF not found**: Ensure MSF_ROOT environment variable is set
2. **PostgreSQL errors**: Check database setup and permissions
3. **Daemon not starting**: Check shared memory permissions
4. **Timeout errors**: Increase timeout in test fixtures

### Local CI Script Failures

If `.github/scripts/test-ci-locally.sh` fails:

1. Make sure daemon is not already running: `pkill -f daemon`
2. Clean shared memory: `sudo rm -f /dev/shm/*assassinate*`
3. Rebuild all components: `cargo clean && cargo build --release`
4. Re-sync Python deps: `uv sync`

## Future Enhancements

Planned improvements:
- [ ] Code coverage reporting (codecov.io)
- [ ] Performance benchmarks
- [ ] Multi-platform testing (macOS, Windows WSL)
- [ ] Nightly builds against MSF dev branch
- [ ] Security scanning (cargo audit, bandit)
- [ ] Documentation generation and hosting

## Related Workflows

### Legacy Workflows (Deprecated)

- `ci.yml`: Old bridge-only CI (references non-existent assassinate_bridge/)
- `distro-matrix.yml`: Multi-distro validation (not yet updated for new structure)

These will be updated or removed in a future PR.
