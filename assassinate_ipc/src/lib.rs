//! # Assassinate IPC
//!
//! Ultra-low-latency IPC layer for Python <-> Rust/MSF communication.
//!
//! ## Performance Targets
//! - Ring buffer operations: <100ns
//! - Round-trip latency: <1μs
//! - Throughput: >100K ops/sec
//!
//! ## Architecture
//! ```text
//! Python Process          Shared Memory          Rust Daemon
//! ┌──────────┐           ┌────────────┐         ┌──────────┐
//! │  Client  │ ←────────→│ Ring Buffer│←───────→│   MSF    │
//! └──────────┘           └────────────┘         └──────────┘
//!     (async)            (lock-free)             (tokio)
//! ```
//!
//! ## Example
//! ```no_run
//! use assassinate_ipc::{RingBuffer, protocol};
//!
//! // Create ring buffer in shared memory
//! let rb = RingBuffer::create("msf_ipc", 64 * 1024 * 1024).unwrap();
//!
//! // Serialize and send message
//! let msg = protocol::serialize_call(1, "framework_version", vec![]).unwrap();
//! rb.try_write(&msg).unwrap();
//!
//! // Read response (zero-copy)
//! let response_bytes = rb.try_read().unwrap();
//! ```

pub mod error;
pub mod ring_buffer;
pub mod shm;

// Include generated Cap'n Proto code at crate root
pub mod msf_capnp {
    include!(concat!(env!("OUT_DIR"), "/msf_capnp.rs"));
}

pub mod protocol;

// Re-export main types
pub use error::{IpcError, Result};
pub use ring_buffer::RingBuffer;
pub use shm::SharedMemory;

/// Default ring buffer size (64 MB)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Default shared memory name
pub const DEFAULT_SHM_NAME: &str = "/assassinate_msf_ipc";

/// IPC client for sending MSF requests
pub struct IpcClient {
    ring_buffer: RingBuffer,
    next_call_id: std::sync::atomic::AtomicU64,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(name: &str, capacity: usize) -> Result<Self> {
        let ring_buffer = RingBuffer::create(name, capacity)?;
        Ok(Self {
            ring_buffer,
            next_call_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Open an existing IPC connection
    pub fn open(name: &str, capacity: usize) -> Result<Self> {
        let ring_buffer = RingBuffer::open(name, capacity)?;
        Ok(Self {
            ring_buffer,
            next_call_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Send an MSF method call
    pub fn call(&self, method: &str, args: Vec<serde_json::Value>) -> Result<u64> {
        let call_id = self
            .next_call_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let msg = protocol::serialize_call(call_id, method, args)?;
        self.ring_buffer.try_write(&msg)?;

        Ok(call_id)
    }

    /// Try to read a response (non-blocking)
    pub fn try_recv(&self) -> Result<Vec<u8>> {
        let data = self.ring_buffer.try_read()?;
        Ok(data.to_vec())
    }

    /// Get buffer utilization
    pub fn utilization(&self) -> f64 {
        self.ring_buffer.utilization()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_client() {
        let client = IpcClient::new("test_ipc", 4096).unwrap();
        let call_id = client.call("test_method", vec![]).unwrap();
        assert_eq!(call_id, 1);
    }
}
