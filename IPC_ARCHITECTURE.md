# High-Performance IPC Architecture

## Executive Summary

Since Ruby VM threading requirements prevent direct FFI from Python, we implement an ultra-low-latency IPC layer targeting **sub-microsecond** performance - as close to native FFI as physically possible.

**Performance Target**: <1 μs latency for simple calls (comparable to native function call overhead)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Python Process                          │
│                                                                 │
│  ┌────────────────┐         ┌──────────────────────────────┐  │
│  │  Python Client │ ←────→ │  Shared Memory Ring Buffer   │  │
│  │    (asyncio)   │         │   (Lock-Free, Zero-Copy)     │  │
│  └────────────────┘         └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                        ↕
                              Memory-Mapped File
                           (tmpfs/memfd_create)
                                        ↕
┌─────────────────────────────────────────────────────────────────┐
│                      Rust Daemon Process                        │
│                                                                 │
│  ┌──────────────────────────────┐      ┌──────────────────┐   │
│  │  Shared Memory Ring Buffer   │ ←──→ │  Rust MSF Bridge │   │
│  │   (Lock-Free, Zero-Copy)     │      │   (assassinate)  │   │
│  └──────────────────────────────┘      └──────────────────┘   │
│                                                  ↕              │
│                                         ┌──────────────────┐   │
│                                         │   Ruby VM (MSF)  │   │
│                                         │    (Magnus FFI)  │   │
│                                         └──────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### 1. **Shared Memory Transport** (Estimated latency: 0.2-0.5 μs)

**Choice: `memfd` + `mmap` (Linux) / `shm_open` (cross-platform)**

Rationale:
- **Zero-copy**: Data written by Python is directly readable by Rust
- **No syscalls**: Ring buffer operations are pure memory operations
- **Sub-microsecond latency**: Memory access is ~100 ns, cache-line transfer ~200 ns
- **tmpfs backing**: Stays in RAM, never hits disk

**Alternative considered**: Unix domain sockets (27 μs) - rejected, too slow

### 2. **Lock-Free Ring Buffer** (Contention-free: ~100 ns)

**Choice: SPSC (Single Producer, Single Consumer) with atomic operations**

Design:
```rust
struct RingBuffer {
    buffer: *mut u8,           // Shared memory backing
    capacity: usize,           // Power of 2 for mask optimization
    write_pos: AtomicUsize,    // Producer writes here
    read_pos: AtomicUsize,     // Consumer reads here
}
```

Operations:
- **Write**: Atomic fetch-add on `write_pos`, memcpy to buffer
- **Read**: Atomic fetch-add on `read_pos`, return pointer (zero-copy)
- **No locks**: Uses memory ordering (Acquire/Release) for synchronization

Performance:
- `AtomicUsize::fetch_add(Ordering::Release)`: ~5 ns
- Memory barrier: ~20 ns
- Total overhead: **~100 ns per message**

**Alternative considered**: Mutex-based queue - rejected (mutex lock ~50 ns + contention)

### 3. **Zero-Copy Serialization**

**Choice: Cap'n Proto** (Decode time: ~0 ns)

Rationale:
- **True zero-copy**: Data is already in Cap'n Proto format in shared memory
- **No parsing**: Rust reads pointers directly, no deserialization
- **Bounded memory**: Pre-allocate message buffers, no dynamic allocation
- **Schema evolution**: Forward/backward compatibility for versioning

Format example:
```capnp
struct MsfCall {
  callId @0 :UInt64;          # Request ID for response matching
  method @1 :Text;            # Method name (e.g., "framework_version")
  args @2 :List(Value);       # Arguments (union type for flexibility)

  union {
    request @3 :Void;         # This is a request
    response @4 :Value;       # This is a response
    error @5 :Text;           # This is an error
  }
}

struct Value {
  union {
    null @0 :Void;
    bool @1 :Bool;
    int @2 :Int64;
    float @3 :Float64;
    string @4 :Text;
    bytes @5 :Data;
    list @6 :List(Value);
    map @7 :List(KeyValue);
  }
}
```

**Alternative considered**:
- **MessagePack**: Fast but requires parsing (~100-500 ns)
- **JSON**: Too slow (μs range for parse)
- **Protobuf**: Requires serialization/deserialization
- **FlatBuffers**: Good but Cap'n Proto is more mature for Rust

### 4. **Async I/O** (Python: asyncio, Rust: tokio)

**Python Client**:
```python
import asyncio
from assassinate_ipc import MsfClient

async def main():
    client = MsfClient()  # Connects to shared memory

    # Non-blocking call - returns immediately
    version = await client.framework_version()
    print(f"MSF Version: {version}")

    # Concurrent calls pipeline through shared memory
    results = await asyncio.gather(
        client.list_modules("exploits"),
        client.list_modules("payloads"),
        client.search("vsftpd"),
    )
```

**Rust Daemon**:
```rust
#[tokio::main]
async fn main() {
    let ring_buffer = RingBuffer::new("/msf_shm", 64 * 1024 * 1024); // 64 MB
    let msf = Framework::new(None).unwrap();

    loop {
        // Non-blocking read from ring buffer
        if let Some(msg) = ring_buffer.try_read() {
            // Dispatch to MSF handler
            let response = handle_msf_call(msg, &msf).await;
            ring_buffer.write(response);
        }

        // Yield to allow other tasks
        tokio::task::yield_now().await;
    }
}
```

---

## Performance Analysis

### Latency Breakdown (Optimistic Path)

| Operation | Latency | Notes |
|-----------|---------|-------|
| **Python: Serialize request** | ~50 ns | Cap'n Proto builder (just pointer writes) |
| **Python: Write to ring buffer** | ~100 ns | Atomic fetch-add + memcpy |
| **Python: Memory barrier** | ~20 ns | `Release` ordering ensures visibility |
| **Rust: Read from ring buffer** | ~100 ns | Atomic load + pointer arithmetic |
| **Rust: Call MSF method** | ~500 ns | Ruby FFI overhead (rb_funcall) |
| **Rust: Write response** | ~100 ns | Atomic fetch-add + memcpy |
| **Python: Read response** | ~100 ns | Atomic load + pointer cast |
| **Python: Access Cap'n Proto** | ~0 ns | Zero-copy pointer access |
| **TOTAL** | **~970 ns** | **Sub-microsecond!** |

### Throughput

With 64 MB ring buffer:
- **Message slots**: 64 MB / 4 KB avg = 16,384 messages
- **Saturation throughput**: ~1M ops/sec (limited by Ruby FFI, not IPC)
- **Practical throughput**: ~100K ops/sec (with realistic MSF operations)

### Comparison to Alternatives

| Method | Latency | Throughput | Notes |
|--------|---------|------------|-------|
| **Our IPC (shared memory + Cap'n Proto)** | **~1 μs** | **~100K/s** | Zero-copy, lock-free |
| Native FFI (impossible) | ~50 ns | ~20M/s | Baseline (unachievable) |
| Unix domain sockets | ~27 μs | ~37K/s | 27x slower |
| TCP localhost | ~38 μs | ~26K/s | 38x slower |
| ZeroMQ IPC | ~21 μs | ~48K/s | 21x slower |
| gRPC | ~2 ms | ~500/s | 2000x slower |
| pymetasploit3 (msfrpc) | ~10-50 ms | ~100/s | 10,000x slower |

**Our approach is 21-27x faster than standard IPC and only 20x slower than impossible FFI.**

---

## Implementation Plan

### Phase 1: Core IPC Infrastructure (Week 1)

**Deliverables**:
1. `assassinate_ipc` Rust crate:
   - Shared memory ring buffer implementation
   - Cap'n Proto message schema
   - Lock-free SPSC queue with benchmarks

2. Basic daemon:
   - Initialize shared memory
   - Read/write loop with async I/O
   - MSF initialization and basic dispatch

3. Python client stub:
   - Shared memory connection
   - Basic send/receive
   - Cap'n Proto bindings (pycapnp)

**Success Criteria**: Round-trip latency <5 μs for "hello world" message

### Phase 2: MSF API Coverage (Week 2)

**Deliverables**:
1. Implement all MSF methods:
   - Framework operations (version, search, list_modules)
   - Module operations (create, configure, execute)
   - Session management (list, interact, kill)
   - Datastore operations (get, set, merge)
   - Payload generation
   - Database operations

2. Python client library:
   - Pythonic async API wrapping IPC
   - Type hints and docstrings
   - Error handling and retries

**Success Criteria**: All existing `assassinate.bridge` APIs work through IPC

### Phase 3: Optimization (Week 3)

**Deliverables**:
1. **Batch operations**: Send multiple MSF calls in single message
2. **Response streaming**: Use ring buffer for chunked responses
3. **Connection pooling**: Multiple Python processes → single daemon
4. **Memory tuning**: Optimize ring buffer size, message layout

**Success Criteria**: Achieve <1 μs average latency for common operations

### Phase 4: Production Hardening (Week 4)

**Deliverables**:
1. **Error handling**: Timeouts, reconnection, graceful degradation
2. **Monitoring**: Performance metrics, health checks
3. **Security**: Access control for shared memory
4. **Packaging**: systemd service, installation scripts

**Success Criteria**: Production-ready daemon with 99.9% uptime

---

## Code Structure

```
assassinate/
├── assassinate_bridge/           # Existing Rust FFI (unchanged)
│   ├── src/
│   │   ├── lib.rs
│   │   ├── framework.rs
│   │   └── ruby_bridge.rs
│   └── Cargo.toml
│
├── assassinate_ipc/              # NEW: IPC infrastructure
│   ├── src/
│   │   ├── lib.rs                # Public API
│   │   ├── ring_buffer.rs        # Lock-free SPSC queue
│   │   ├── protocol.rs           # Cap'n Proto message handling
│   │   └── shm.rs                # Shared memory management
│   ├── schema/
│   │   └── msf.capnp             # Cap'n Proto schema
│   ├── benches/
│   │   └── latency.rs            # Latency benchmarks
│   └── Cargo.toml
│
├── assassinate_daemon/           # NEW: Rust daemon
│   ├── src/
│   │   ├── main.rs               # Daemon entry point
│   │   ├── dispatcher.rs         # MSF method dispatch
│   │   └── config.rs             # Configuration management
│   └── Cargo.toml
│
├── assassinate/                  # Existing Python package
│   ├── bridge/                   # Update to use IPC
│   │   ├── __init__.py
│   │   ├── core.py               # Updated for IPC
│   │   ├── ipc_client.py         # NEW: IPC client wrapper
│   │   └── ...
│   └── ...
│
└── tests/
    ├── test_ipc_latency.py       # Latency benchmarks
    └── test_ipc_correctness.py   # Functional tests
```

---

## Risk Mitigation

### Risk 1: Latency exceeds target (>1 μs)

**Mitigation**:
- Benchmark each component independently
- Profile with `perf` to find bottlenecks
- Consider `io_uring` for async I/O (Linux 5.1+)
- Fallback: Use 2-4 μs target (still 10x faster than alternatives)

### Risk 2: Ring buffer overflow

**Mitigation**:
- Implement backpressure in Python client (block when full)
- Monitor buffer utilization metrics
- Dynamic resizing (allocate larger shared memory segment)

### Risk 3: Daemon crashes

**Mitigation**:
- systemd auto-restart on failure
- Python client auto-reconnect with exponential backoff
- Health check endpoint (separate Unix socket)

### Risk 4: Memory leaks

**Mitigation**:
- Rust's ownership prevents most leaks
- Use `valgrind` and `miri` for testing
- Monitor daemon RSS over time

---

## Benchmarking Strategy

### Microbenchmarks

1. **Ring buffer write**: `cargo bench ring_buffer_write`
   - Target: <100 ns/write

2. **Ring buffer read**: `cargo bench ring_buffer_read`
   - Target: <100 ns/read

3. **Cap'n Proto serialize**: `cargo bench capnp_serialize`
   - Target: <50 ns for simple message

4. **Round-trip (no MSF)**: `cargo bench round_trip_noop`
   - Target: <500 ns total

### Integration Benchmarks

1. **MSF version call**: `pytest tests/test_ipc_latency.py::test_version`
   - Target: <2 μs (includes Ruby FFI overhead)

2. **Module listing**: `pytest tests/test_ipc_latency.py::test_list_modules`
   - Target: <10 μs for 2000 modules

3. **Throughput test**: `pytest tests/test_ipc_latency.py::test_throughput`
   - Target: >100K ops/sec

### Comparison Tests

Test against existing solutions:
- RPC over Unix socket (baseline)
- pymetasploit3 (msfrpc)
- Direct Rust benchmark (theoretical minimum)

---

## Next Steps

1. **Approve architecture** ← YOU ARE HERE
2. **Implement Phase 1** (Core IPC)
3. **Benchmark and validate** <1 μs target
4. **Iterate on performance**
5. **Complete MSF API coverage**
6. **Production deployment**

---

## Questions for Review

1. Is sub-microsecond latency sufficient, or do we need further optimization?
2. Should we support multiple Python processes, or single-client only for MVP?
3. Linux-only for MVP (memfd), or cross-platform (shm_open) from start?
4. Any specific MSF operations that need prioritization?

---

**Last Updated**: 2025-01-26
**Status**: Design Review
**Performance Target**: <1 μs round-trip latency
