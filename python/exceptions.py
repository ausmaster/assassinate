from __future__ import annotations


class InitializationError(Exception):
    """Raised when Metasploit Core initialization fails."""
    pass


class RPCError(Exception):
    """Raised when a Metasploit function call fails."""
    pass


class ValidationError(Exception):
    """Raised when invalid inputs are provided."""
    pass
