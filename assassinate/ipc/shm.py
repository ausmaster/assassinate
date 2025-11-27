"""Shared memory access for IPC.

Provides Python interface to the shared memory ring buffer created by the Rust daemon.
"""

from __future__ import annotations

import mmap
import os
import struct
from typing import Optional

from assassinate.ipc.errors import BufferEmptyError, BufferFullError, IpcError


class RingBuffer:
    """Lock-free SPSC ring buffer for IPC.

    This is the Python side of the ring buffer implemented in assassinate_ipc.
    It must match the memory layout of the Rust RingBuffer exactly:

    Memory layout:
        [write_pos: 8 bytes][read_pos: 8 bytes][padding: 48 bytes][data: capacity bytes]
    """

    WRITE_POS_OFFSET = 0
    READ_POS_OFFSET = 8
    DATA_OFFSET = 64
    HEADER_SIZE = 4  # u32 message length

    def __init__(self, name: str, capacity: int):
        """Open an existing ring buffer in shared memory.

        Args:
            name: Shared memory name (must start with /)
            capacity: Buffer capacity in bytes (must match Rust side)
        """
        self.name = name
        self.capacity = capacity
        self.total_size = self.DATA_OFFSET + capacity

        # Open shared memory
        try:
            # Use /dev/shm on Linux (backed by tmpfs)
            if name.startswith("/"):
                # POSIX shared memory
                self.shm_path = f"/dev/shm{name}"
            else:
                self.shm_path = f"/dev/shm/{name}"

            # Check if shared memory exists
            if not os.path.exists(self.shm_path):
                raise IpcError(
                    f"Shared memory '{name}' not found at {self.shm_path}.\n"
                    f"Make sure the assassinate_daemon is running first:\n"
                    f"  ./assassinate_daemon/target/release/assassinate_daemon --msf-root /path/to/msf"
                )

            # Open the shared memory file descriptor
            fd = os.open(self.shm_path, os.O_RDWR)
            self.mmap = mmap.mmap(fd, self.total_size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            os.close(fd)
        except IpcError:
            raise
        except (OSError, FileNotFoundError) as e:
            raise IpcError(
                f"Failed to open shared memory '{name}': {e}\n"
                f"Make sure the assassinate_daemon is running."
            ) from e

    def _read_atomic_u64(self, offset: int) -> int:
        """Read a 64-bit atomic value.

        Note: Python doesn't have true atomic operations, but single reads
        are generally atomic on x86-64 for aligned 64-bit values.
        """
        self.mmap.seek(offset)
        return struct.unpack("<Q", self.mmap.read(8))[0]

    def _write_atomic_u64(self, offset: int, value: int) -> None:
        """Write a 64-bit atomic value."""
        self.mmap.seek(offset)
        self.mmap.write(struct.pack("<Q", value))

    def try_write(self, data: bytes) -> None:
        """Try to write a message to the ring buffer (non-blocking).

        Args:
            data: Message data to write

        Raises:
            BufferFullError: If buffer is full
        """
        msg_size = self.HEADER_SIZE + len(data)

        # Check if we have space
        write_pos = self._read_atomic_u64(self.WRITE_POS_OFFSET)
        read_pos = self._read_atomic_u64(self.READ_POS_OFFSET)

        available = self.capacity - (write_pos - read_pos)
        if available < msg_size:
            raise BufferFullError(f"Ring buffer full (capacity: {self.capacity}, available: {available})")

        # Write message length header (little-endian u32)
        write_offset = (write_pos % self.capacity) + self.DATA_OFFSET
        self.mmap.seek(write_offset)
        self.mmap.write(struct.pack("<I", len(data)))

        # Write message data
        self.mmap.write(data)

        # Update write position
        self._write_atomic_u64(self.WRITE_POS_OFFSET, write_pos + msg_size)

    def try_read(self) -> bytes:
        """Try to read a message from the ring buffer (non-blocking, zero-copy).

        Returns:
            Message data (copied from shared memory)

        Raises:
            BufferEmptyError: If buffer is empty
        """
        write_pos = self._read_atomic_u64(self.WRITE_POS_OFFSET)
        read_pos = self._read_atomic_u64(self.READ_POS_OFFSET)

        # Check if data is available
        if write_pos == read_pos:
            raise BufferEmptyError("Ring buffer empty")

        # Read message length header
        read_offset = (read_pos % self.capacity) + self.DATA_OFFSET
        self.mmap.seek(read_offset)
        msg_len = struct.unpack("<I", self.mmap.read(self.HEADER_SIZE))[0]

        # Read message data
        data = self.mmap.read(msg_len)

        # Update read position
        self._write_atomic_u64(self.READ_POS_OFFSET, read_pos + self.HEADER_SIZE + msg_len)

        return data

    def utilization(self) -> float:
        """Get current buffer utilization (0.0 = empty, 1.0 = full)."""
        write_pos = self._read_atomic_u64(self.WRITE_POS_OFFSET)
        read_pos = self._read_atomic_u64(self.READ_POS_OFFSET)
        used = write_pos - read_pos
        return used / self.capacity

    def close(self) -> None:
        """Close the shared memory mapping."""
        if hasattr(self, "mmap"):
            self.mmap.close()

    def __enter__(self) -> RingBuffer:
        return self

    def __exit__(self, *args) -> None:
        self.close()
