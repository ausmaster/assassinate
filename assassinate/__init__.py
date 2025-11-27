"""Assassinate - Metasploit Framework Python interface.

A modular exploitation framework providing Python access to the complete
Metasploit Framework through a high-performance Rust FFI bridge.

This package provides:

1. **Low-Level Bridge** (``assassinate.bridge``):
   Direct access to MSF functionality with full control. Use when you need
   low-level access or the high-level API doesn't provide what you need.

2. **High-Level API** (coming soon):
   Pythonic, convenient interface with context managers, better error
   handling, and helper methods. Recommended for most use cases.

Example:
    Using the low-level bridge::

        from assassinate.bridge import initialize, Framework

        # Initialize MSF
        initialize("/opt/metasploit-framework")

        # Create framework and list exploits
        fw = Framework()
        exploits = fw.list_modules("exploits")
        print(f"Available exploits: {len(exploits)}")

Attributes:
    __version__: Package version string.

Note:
    The Rust FFI bridge (assassinate_bridge) must be compiled before use.
    See README.md for installation instructions.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["bridge"]

# Re-export bridge module for easy access
from assassinate import bridge

# Note: High-level API will be added here in future versions
