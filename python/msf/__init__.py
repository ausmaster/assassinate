"""Python interface to Metasploit Framework.

This module provides a Pythonic API for interacting with Metasploit Framework
through an embedded Ruby VM (via Rust/Pyo3).

Example:
    from msf import init_msf, create_module

    init_msf("/path/to/metasploit-framework")
    module = create_module("exploit/linux/samba/is_known_pipename")
    module.options.RHOSTS = "192.168.1.100"
    session = module.exploit("cmd/unix/interact")
    if session:
        print(session.run_cmd("whoami"))
"""

from __future__ import annotations

from typing import Optional

# Import from Rust extension (maturin places .so in this package as msf.cpython-*.so)
from .msf import (
    AssassinateError,
    ExploitModule as _RustExploitModule,
    PySession as _RustPySession,
    check,
    create_module as _create_module_rust,
    exploit,
    framework_version,
    get_module_info,
    get_session as _get_session_rust,
    init_msf,
    is_initialized,
    kill_session,
    list_modules,
    list_sessions,
    search,
    sleep_releasing_gvl,
    job_list,
    job_info,
    job_kill,
)

from .module import Module
from .session import Session
from .options import ModuleOptions


def create_module(module_name: str) -> Module:
    """
    Create a module instance with rich Python interface.

    Args:
        module_name: Full module name (e.g., "exploit/linux/samba/is_known_pipename")

    Returns:
        Module object with attribute-style options access

    Example:
        module = create_module("exploit/linux/samba/is_known_pipename")
        module.options.RHOSTS = "192.168.1.100"
        module.options.RPORT = 445
        session = module.exploit("cmd/unix/interact")
    """
    rust_module = _create_module_rust(module_name)
    return Module(rust_module)


def get_session(session_id: int) -> Optional[Session]:
    """
    Get a session by ID.

    Args:
        session_id: The session ID to retrieve

    Returns:
        Session object if found, None otherwise

    Example:
        session = get_session(1)
        if session:
            print(f"Got session: {session}")
            print(session.run_cmd("whoami"))
    """
    rust_session = _get_session_rust(session_id)
    if rust_session is not None:
        return Session(rust_session)
    return None


__all__ = [
    # Core
    "init_msf",
    "is_initialized",
    "framework_version",
    # Modules
    "create_module",
    "list_modules",
    "search",
    "get_module_info",
    "check",
    "exploit",
    "Module",
    "ModuleOptions",
    # Sessions
    "get_session",
    "list_sessions",
    "kill_session",
    "Session",
    # Jobs
    "job_list",
    "job_info",
    "job_kill",
    # GVL
    "sleep_releasing_gvl",
    # Exception
    "AssassinateError",
]
