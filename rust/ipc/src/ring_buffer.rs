/// Lock-free SPSC (Single Producer Single Consumer) ring buffer
///
/// Ultra-low-latency message queue using atomic operations and zero-copy reads.
/// Target: <100ns overhead per operation.

use crate::error::{IpcError, Result};
use crate::shm::SharedMemory;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Message header in ring buffer
/// Layout: [length: u32][data: [u8; length]]
const HEADER_SIZE: usize = 4;

/// Lock-free ring buffer for IPC
///
/// Memory layout:
/// [write_pos: 8 bytes][read_pos: 8 bytes][padding: 48 bytes][data: capacity bytes]
///
/// The 48-byte padding ensures write_pos and read_pos are on separate cache lines (64 bytes)
/// to prevent false sharing and maximize performance.
pub struct RingBuffer {
    shm: Arc<SharedMemory>,
    capacity: usize,
    data_offset: usize,
    write_pos: *mut AtomicUsize,
    read_pos: *mut AtomicUsize,
}

impl RingBuffer {
    /// Offset for atomic counters in shared memory
    const WRITE_POS_OFFSET: usize = 0;
    const READ_POS_OFFSET: usize = 8;
    const DATA_OFFSET: usize = 64; // Start after cache line to avoid false sharing

    /// Create a new ring buffer in shared memory
    ///
    /// # Arguments
    /// * `name` - Shared memory name
    /// * `capacity` - Buffer capacity in bytes (should be power of 2 for optimal performance)
    pub fn create(name: &str, capacity: usize) -> Result<Self> {
        // Ensure capacity is power of 2
        if !capacity.is_power_of_two() {
            return Err(IpcError::SharedMemory(
                "Ring buffer capacity must be power of 2".to_string(),
            ));
        }

        let total_size = Self::DATA_OFFSET + capacity;
        let shm = Arc::new(SharedMemory::create(name, total_size)?);

        // Initialize atomic positions
        let write_pos = unsafe { &*(shm.as_ptr().add(Self::WRITE_POS_OFFSET) as *mut AtomicUsize) };
        let read_pos = unsafe { &*(shm.as_ptr().add(Self::READ_POS_OFFSET) as *mut AtomicUsize) };

        write_pos.store(0, Ordering::Release);
        read_pos.store(0, Ordering::Release);

        let write_pos_ptr = unsafe { shm.as_ptr().add(Self::WRITE_POS_OFFSET) as *mut AtomicUsize };
        let read_pos_ptr = unsafe { shm.as_ptr().add(Self::READ_POS_OFFSET) as *mut AtomicUsize };

        Ok(Self {
            shm,
            capacity,
            data_offset: Self::DATA_OFFSET,
            write_pos: write_pos_ptr,
            read_pos: read_pos_ptr,
        })
    }

    /// Open an existing ring buffer
    pub fn open(name: &str, capacity: usize) -> Result<Self> {
        let total_size = Self::DATA_OFFSET + capacity;
        let shm = Arc::new(SharedMemory::open(name, total_size)?);

        let write_pos = unsafe { shm.as_ptr().add(Self::WRITE_POS_OFFSET) as *mut AtomicUsize };
        let read_pos = unsafe { shm.as_ptr().add(Self::READ_POS_OFFSET) as *mut AtomicUsize };

        Ok(Self {
            shm,
            capacity,
            data_offset: Self::DATA_OFFSET,
            write_pos,
            read_pos,
        })
    }

    /// Try to write a message to the ring buffer (non-blocking)
    ///
    /// Returns Ok(()) if successful, Err(RingBufferFull) if buffer is full.
    ///
    /// # Performance
    /// Target: <100ns for small messages
    pub fn try_write(&self, data: &[u8]) -> Result<()> {
        let msg_size = HEADER_SIZE + data.len();

        // Fast path: check if we have space
        let write_pos_val = unsafe { (*self.write_pos).load(Ordering::Acquire) };
        let read_pos_val = unsafe { (*self.read_pos).load(Ordering::Acquire) };

        let available = self.capacity - (write_pos_val - read_pos_val);
        if available < msg_size {
            return Err(IpcError::RingBufferFull(self.capacity));
        }

        // Write message length header (ensure 4-byte alignment)
        let write_offset = (write_pos_val % self.capacity) + self.data_offset;
        let header_ptr = unsafe { self.shm.as_ptr().add(write_offset) };
        unsafe {
            // Use unaligned write to avoid alignment issues
            std::ptr::write_unaligned(header_ptr as *mut u32, data.len() as u32);
        }

        // Write message data
        let data_ptr = unsafe { self.shm.as_ptr().add(write_offset + HEADER_SIZE) };
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        }

        // Update write position with Release ordering to ensure visibility
        unsafe {
            (*self.write_pos).store(write_pos_val + msg_size, Ordering::Release);
        }

        Ok(())
    }

    /// Try to read a message from the ring buffer (non-blocking, zero-copy)
    ///
    /// Returns a slice pointing directly into shared memory.
    /// The slice is valid until the next read operation.
    ///
    /// # Performance
    /// Target: <100ns (just atomic load + pointer arithmetic)
    pub fn try_read(&self) -> Result<&[u8]> {
        let write_pos_val = unsafe { (*self.write_pos).load(Ordering::Acquire) };
        let read_pos_val = unsafe { (*self.read_pos).load(Ordering::Acquire) };

        // Check if data is available
        if write_pos_val == read_pos_val {
            return Err(IpcError::RingBufferEmpty);
        }

        // Read message length header (use unaligned read)
        let read_offset = (read_pos_val % self.capacity) + self.data_offset;
        let header_ptr = unsafe { self.shm.as_ptr().add(read_offset) };
        let msg_len = unsafe { std::ptr::read_unaligned(header_ptr as *const u32) } as usize;

        // Return zero-copy slice into shared memory
        let data_ptr = unsafe { self.shm.as_ptr().add(read_offset + HEADER_SIZE) };
        let slice = unsafe { std::slice::from_raw_parts(data_ptr, msg_len) };

        // Update read position
        unsafe {
            (*self.read_pos).store(read_pos_val + HEADER_SIZE + msg_len, Ordering::Release);
        }

        Ok(slice)
    }

    /// Get current buffer utilization (0.0 = empty, 1.0 = full)
    pub fn utilization(&self) -> f64 {
        let write_pos_val = unsafe { (*self.write_pos).load(Ordering::Acquire) };
        let read_pos_val = unsafe { (*self.read_pos).load(Ordering::Acquire) };
        let used = write_pos_val - read_pos_val;
        used as f64 / self.capacity as f64
    }

    /// Get available space in bytes
    pub fn available(&self) -> usize {
        let write_pos_val = unsafe { (*self.write_pos).load(Ordering::Acquire) };
        let read_pos_val = unsafe { (*self.read_pos).load(Ordering::Acquire) };
        self.capacity - (write_pos_val - read_pos_val)
    }
}

unsafe impl Send for RingBuffer {}
unsafe impl Sync for RingBuffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_write() {
        let rb = RingBuffer::create("test_ring", 4096).unwrap();
        let msg = b"hello world";
        rb.try_write(msg).unwrap();

        let read_msg = rb.try_read().unwrap();
        assert_eq!(read_msg, msg);
    }

    #[test]
    fn test_multiple_messages() {
        let rb = RingBuffer::create("test_ring2", 4096).unwrap();

        for i in 0..10 {
            let msg = format!("message {}", i);
            rb.try_write(msg.as_bytes()).unwrap();
        }

        for i in 0..10 {
            let msg = rb.try_read().unwrap();
            let expected = format!("message {}", i);
            assert_eq!(msg, expected.as_bytes());
        }
    }

    #[test]
    fn test_buffer_full() {
        let rb = RingBuffer::create("test_ring3", 128).unwrap();
        let large_msg = vec![0u8; 200];

        let result = rb.try_write(&large_msg);
        assert!(matches!(result, Err(IpcError::RingBufferFull(_))));
    }
}
