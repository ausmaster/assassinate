"""Low-level Metasploit Framework bridge module.

This module provides direct Python wrappers around the assassinate_bridge
Rust/PyO3 FFI bindings, offering complete low-level access to MSF functionality.

Public API:
    Functions:
        - initialize(msf_path): Initialize MSF
        - get_version(): Get MSF version

    Classes:
        - Framework: Main MSF interface
        - Module: MSF module (exploit/auxiliary/payload/etc.)
        - DataStore: Key-value configuration store
        - SessionManager: Manages active sessions
        - Session: Active session to compromised target
        - PayloadGenerator: Generates and encodes payloads

Example:
    >>> from assassinate.bridge import initialize, Framework
    >>> initialize("/opt/metasploit-framework")
    >>> fw = Framework()
    >>> exploits = fw.list_modules("exploits")
"""

from __future__ import annotations

from assassinate.bridge.core import Framework, get_version, initialize
from assassinate.bridge.datastore import DataStore
from assassinate.bridge.modules import Module
from assassinate.bridge.payloads import PayloadGenerator
from assassinate.bridge.sessions import Session, SessionManager

__all__ = [
    "initialize",
    "get_version",
    "Framework",
    "Module",
    "DataStore",
    "SessionManager",
    "Session",
    "PayloadGenerator",
]
