/// Shared memory management for ultra-low-latency IPC
///
/// Uses memfd_create (Linux) for tmpfs-backed shared memory with zero syscall overhead.

use crate::error::{IpcError, Result};
use std::os::unix::io::AsRawFd;
use std::ptr;

/// Shared memory region
pub struct SharedMemory {
    name: String,
    size: usize,
    ptr: *mut u8,
    fd: Option<std::os::unix::io::RawFd>,
}

impl SharedMemory {
    /// Create a new shared memory region with the given name and size
    ///
    /// On Linux, uses memfd_create for tmpfs-backed memory (never hits disk).
    /// Falls back to shm_open for cross-platform compatibility.
    pub fn create(name: &str, size: usize) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::create_memfd(name, size)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::create_shm(name, size)
        }
    }

    /// Open an existing shared memory region
    pub fn open(name: &str, size: usize) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::open_memfd(name, size)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::open_shm(name, size)
        }
    }

    #[cfg(target_os = "linux")]
    fn create_memfd(name: &str, size: usize) -> Result<Self> {
        use memfd::MemfdOptions;

        let opts = MemfdOptions::default().allow_sealing(true);
        let mfd = opts
            .create(name)
            .map_err(|e| IpcError::SharedMemory(format!("memfd_create failed: {}", e)))?;

        // Set size
        mfd.as_file()
            .set_len(size as u64)
            .map_err(|e| IpcError::SharedMemory(format!("ftruncate failed: {}", e)))?;

        // mmap the memory
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                mfd.as_raw_fd(),
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(IpcError::SharedMemory("mmap failed".to_string()));
        }

        Ok(Self {
            name: name.to_string(),
            size,
            ptr: ptr as *mut u8,
            fd: Some(mfd.as_raw_fd()),
        })
    }

    #[cfg(target_os = "linux")]
    fn open_memfd(_name: &str, _size: usize) -> Result<Self> {
        // For memfd, we need file descriptor passing via Unix socket
        // This is a simplified version - full implementation would use SCM_RIGHTS
        Err(IpcError::SharedMemory(
            "memfd open not yet implemented - use shared_memory crate instead".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn create_shm(name: &str, size: usize) -> Result<Self> {
        use shared_memory::{Shmem, ShmemConf};

        let shmem = ShmemConf::new()
            .size(size)
            .flink(name)
            .create()
            .map_err(|e| IpcError::SharedMemory(format!("shm_open failed: {}", e)))?;

        Ok(Self {
            name: name.to_string(),
            size,
            ptr: shmem.as_ptr() as *mut u8,
            fd: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn open_shm(name: &str, size: usize) -> Result<Self> {
        use shared_memory::Shmem;

        let shmem = Shmem::open(name)
            .map_err(|e| IpcError::SharedMemory(format!("shm_open failed: {}", e)))?;

        Ok(Self {
            name: name.to_string(),
            size,
            ptr: shmem.as_ptr() as *mut u8,
            fd: None,
        })
    }

    /// Get a pointer to the shared memory region
    #[inline]
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the size of the shared memory region
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get a slice view of the shared memory
    ///
    /// # Safety
    /// This is unsafe because the memory is shared with other processes.
    /// The caller must ensure proper synchronization.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        std::slice::from_raw_parts(self.ptr, self.size)
    }

    /// Get a mutable slice view of the shared memory
    ///
    /// # Safety
    /// This is unsafe because the memory is shared with other processes.
    /// The caller must ensure proper synchronization.
    #[inline]
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.ptr, self.size)
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.size);
            }
        }
    }
}

// SharedMemory is Send because it manages its own memory safely
unsafe impl Send for SharedMemory {}

// SharedMemory is Sync because access is synchronized via atomic operations in RingBuffer
unsafe impl Sync for SharedMemory {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_write() {
        let mut shm = SharedMemory::create("test_shm", 4096).unwrap();
        let slice = unsafe { shm.as_slice_mut() };
        slice[0] = 42;
        assert_eq!(slice[0], 42);
    }
}
