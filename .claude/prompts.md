# Assassinate Project Context

## Environment Setup
- **MSF Location**: `/home/astark/Projects/metasploit-framework`
- **MSF Requires**: Ruby 3.3.8 (per `.ruby-version`)
- **RVM Installed**: `~/.rvm` with Ruby 3.3.8 and gemset `metasploit-framework`

## Environment Setup

All required environment variables are in `.env`. Source it before building or running:

```bash
source .env
```

## Building Rust Components

```bash
source .env
cargo build --release --manifest-path rust/ipc/Cargo.toml
cargo build --release --manifest-path rust/bridge/Cargo.toml
cargo build --release --manifest-path rust/daemon/Cargo.toml
```

## Running the Daemon

```bash
source .env
./rust/daemon/target/release/daemon --msf-root /home/astark/Projects/metasploit-framework
```

## Running Tests

**IMPORTANT**: The project uses a `.venv` virtual environment managed by `uv`. Always use `uv run` to run Python commands - it handles venv activation automatically.

### Python Tests
```bash
source .env
uv run pytest python/tests/ -v
```

### Rust Integration Tests
```bash
source .env
cargo test --manifest-path rust/bridge/Cargo.toml --test integration_tests -- --nocapture
```

See `.claude/DEVELOPMENT_NOTES.md` for detailed troubleshooting.
