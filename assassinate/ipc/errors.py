"""IPC error types."""

from __future__ import annotations


class IpcError(Exception):
    """Base exception for IPC errors."""

    pass


class ConnectionError(IpcError):
    """Failed to connect to the daemon."""

    pass


class TimeoutError(IpcError):
    """Operation timed out."""

    pass


class BufferFullError(IpcError):
    """Ring buffer is full."""

    pass


class BufferEmptyError(IpcError):
    """Ring buffer is empty."""

    pass


class SerializationError(IpcError):
    """Failed to serialize message."""

    pass


class DeserializationError(IpcError):
    """Failed to deserialize message."""

    pass


class RemoteError(IpcError):
    """Error occurred on daemon side."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
