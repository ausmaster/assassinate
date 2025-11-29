/// Error types for IPC layer
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("Shared memory error: {0}")]
    SharedMemory(String),

    #[error("Ring buffer full (capacity: {0} bytes)")]
    RingBufferFull(usize),

    #[error("Ring buffer empty")]
    RingBufferEmpty,

    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Timeout after {0}ms")]
    Timeout(u64),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Cap'n Proto error: {0}")]
    CapnProto(#[from] capnp::Error),
}

pub type Result<T> = std::result::Result<T, IpcError>;
