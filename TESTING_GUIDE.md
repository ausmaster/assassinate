# Testing Guide

## Overview

Assassinate has comprehensive testing infrastructure with multiple ways to validate code changes before merging.

## Quick Start

```bash
# Fastest: Local validation
./.github/scripts/test-ci-locally.sh

# Most reliable: Docker environment
./scripts/test-with-docker.sh

# Manual: Run specific tests
uv run pytest tests/ -v
```

## Testing Methods

### 1. Local Testing (Fastest)

**Pros**: Fast feedback, uses local environment  
**Cons**: May have environment-specific issues

```bash
# Run CI checks locally
./.github/scripts/test-ci-locally.sh

# Run specific test file
uv run pytest tests/test_framework_detailed.py -v

# Run with different log levels
ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v

# Run specific test
uv run pytest tests/test_module_detailed.py::TestModuleCreation::test_create_exploit_module -v
```

### 2. Docker Testing (Most Reliable)

**Pros**: Clean environment, reproducible, matches CI  
**Cons**: Slower initial build

```bash
# Run all tests in Docker
./scripts/test-with-docker.sh

# Rebuild from scratch
./scripts/test-with-docker.sh --rebuild

# Show detailed output
./scripts/test-with-docker.sh --verbose

# Manual Docker Compose
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### 3. CI/CD (Automatic)

**Triggers**: Push to main or feature/python-interface, PRs to main  
**Runs**: All tests automatically in clean Ubuntu environment

```bash
# Push changes to trigger CI
git push origin feature/python-interface

# View results in GitHub Actions tab
```

## Test Suite Breakdown (118 Tests)

### Framework Tests (11 tests)
Location: `tests/test_framework_detailed.py`

- Version information
- Module listing (exploits, auxiliary, payloads)
- Module search functionality
- Thread count
- Session management

```bash
uv run pytest tests/test_framework_detailed.py -v
```

### Module Tests (31 tests)
Location: `tests/test_module_detailed.py`

- Module creation and deletion
- Metadata (name, type, description, rank)
- Options management (get, set, validate)
- Capabilities (check, compatible payloads)
- Targets and aliases

```bash
uv run pytest tests/test_module_detailed.py -v
```

### DataStore Tests (11 tests)
Location: `tests/test_datastore.py`

- Framework-level options
- Module-level options
- Option CRUD operations
- Datastore isolation

```bash
uv run pytest tests/test_datastore.py -v
```

### Payload Tests (13 tests)
Location: `tests/test_payloads.py`

- Raw payload generation
- Payload encoding
- Executable generation (Linux, Windows, macOS)
- Option handling

```bash
uv run pytest tests/test_payloads.py -v
```

### Database Tests (22 tests)
Location: `tests/test_db.py`

- Host management
- Service tracking
- Vulnerability reporting
- Credential storage
- Loot collection

```bash
uv run pytest tests/test_db.py -v
```

### Job Tests (8 tests)
Location: `tests/test_jobs.py`

- Job listing
- Job information retrieval
- Job termination

```bash
uv run pytest tests/test_jobs.py -v
```

### Plugin Tests (8 tests)
Location: `tests/test_plugins.py`

- Plugin listing
- Plugin loading
- Plugin unloading

```bash
uv run pytest tests/test_plugins.py -v
```

### Session Tests (22 tests)
Location: `tests/test_sessions.py`

- Session metadata
- Session properties (host, port, type)
- Session interaction (read, write, execute)
- Session lifecycle

```bash
uv run pytest tests/test_sessions.py -v
```

## Code Quality Checks

### Rust

```bash
# Format check
cargo fmt -- --check

# Linting
cargo clippy --all-targets -- -D warnings

# All Rust components
cd rust/ipc && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings
cd rust/bridge && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings
cd rust/daemon && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings
```

### Python

```bash
# Format check
uv run ruff format --check .

# Linting
uv run ruff check .

# Type checking
uv run mypy assassinate

# Auto-fix
uv run ruff format .
uv run ruff check --fix .
```

## Debugging Failed Tests

### 1. Check Daemon Status

```bash
# Is daemon running?
ps aux | grep daemon

# Check daemon logs
tail -f /tmp/daemon.log

# Restart daemon
pkill -f daemon
./rust/daemon/target/release/daemon \
    --msf-root /path/to/msf \
    --log-level debug > /tmp/daemon.log 2>&1 &
```

### 2. Check Shared Memory

```bash
# List shared memory
ls -la /dev/shm/

# Clean shared memory
sudo rm -f /dev/shm/*assassinate*
```

### 3. Enable Debug Logging

```bash
# Python debug logs
ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v

# Rust debug logs (restart daemon with --log-level debug)

# Both to files
ASSASSINATE_LOG_FILE=/tmp/python.log ASSASSINATE_LOG_LEVEL=DEBUG uv run pytest tests/ -v
```

### 4. Run Single Test

```bash
# Run one test to isolate issue
uv run pytest tests/test_framework_detailed.py::TestFrameworkVersion::test_version_exists -v -s

# Show print statements
uv run pytest tests/ -v -s

# Stop on first failure
uv run pytest tests/ -v -x
```

## Performance Testing

```bash
# Time test suite
time uv run pytest tests/ -v

# Show slowest tests
uv run pytest tests/ -v --durations=10

# Parallel execution (experimental)
uv run pytest tests/ -v -n auto
```

## Coverage Reporting

```bash
# Run tests with coverage
uv run pytest tests/ --cov=assassinate --cov-report=html

# View HTML report
open htmlcov/index.html
```

## CI/CD Pipeline

### GitHub Actions Workflow

File: `.github/workflows/python-ipc-ci.yml`

**Jobs**:
1. `rust-checks`: Format and lint Rust code
2. `python-checks`: Format and lint Python code
3. `build-rust`: Build all Rust components
4. `integration-tests`: Run full test suite (118 tests)
5. `test-coverage`: Generate summary report

**Artifacts**:
- Daemon binary (7-day retention)
- Test results (7-day retention)

### Viewing CI Results

1. Go to GitHub repository
2. Click "Actions" tab
3. Select workflow run
4. View job details and logs
5. Download artifacts if needed

## Troubleshooting

### Common Issues

**1. "Daemon not found"**
```bash
# Build daemon
cd rust/daemon && cargo build --release

# Check it exists
ls -la rust/daemon/target/release/daemon
```

**2. "MSF_ROOT not set"**
```bash
# Set environment variable
export MSF_ROOT=/path/to/metasploit-framework

# Or pass to pytest
MSF_ROOT=/path/to/msf uv run pytest tests/ -v
```

**3. "Buffer full" or "Buffer empty"**
```bash
# Clean shared memory and restart daemon
sudo rm -f /dev/shm/*assassinate*
# Restart daemon
```

**4. "PostgreSQL connection failed"**
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Check status
sudo systemctl status postgresql
```

**5. Tests timeout**
```bash
# Increase timeout in conftest.py or test
# Check daemon is responding:
tail -f /tmp/daemon.log
```

## Best Practices

1. **Run local checks before pushing**
   ```bash
   ./.github/scripts/test-ci-locally.sh
   ```

2. **Test in Docker before creating PR**
   ```bash
   ./scripts/test-with-docker.sh
   ```

3. **Write tests for new features**
   - Add to appropriate test file
   - Follow existing test patterns
   - Use descriptive test names

4. **Keep tests fast**
   - Use fixtures for setup/teardown
   - Cleanup resources (modules, sessions)
   - Avoid sleep() when possible

5. **Document test failures**
   - Include error messages
   - Show relevant logs
   - List steps to reproduce

## Resources

- CI/CD Documentation: `.github/CI_README.md`
- Test Fixtures: `tests/conftest.py`
- Logging Demo: `examples/logging_demo.py`
- Docker Runner: `scripts/test-with-docker.sh`
- CI Validator: `.github/scripts/test-ci-locally.sh`
