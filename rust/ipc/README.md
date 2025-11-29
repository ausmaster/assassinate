# Assassinate IPC

Ultra-low-latency IPC layer for Python <-> Rust/MSF communication.

## Performance Targets

- Ring buffer operations: <100ns
- Round-trip latency: <1μs
- Throughput: >100K ops/sec

## Dependencies

### System Requirements

```bash
# Fedora/RHEL
sudo dnf install capnproto capnproto-devel

# Ubuntu/Debian
sudo apt install capnproto libcapnp-dev

# macOS
brew install capnp
```

### Rust Dependencies

All Rust dependencies are managed via Cargo.toml.

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

## Benchmarks

```bash
cargo bench
```

## Architecture

See [IPC_ARCHITECTURE.md](../IPC_ARCHITECTURE.md) for detailed design.

## Status

Phase 1 (Core IPC Infrastructure) - In Progress
