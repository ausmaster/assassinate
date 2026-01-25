"""Python interface to Metasploit Framework.

This module provides a Pythonic API for interacting with Metasploit Framework
through an embedded Ruby VM (via Rust/Pyo3).

The create_module() factory returns type-specific classes based on module type:
- ExploitModule: Vulnerability exploitation (exploit(), check(), targets)
- AuxiliaryModule: Scanners, fuzzers, servers (run(), actions())
- PostModule: Post-exploitation, requires session (run(session))
- EvasionModule: AV/EDR bypass (run(), targets)
- PayloadModule: Shellcode generation (generate(), to_handler())
- EncoderModule: Payload encoding (encode())
- NopModule: NOP sled generation (generate_sled())

Example:
    from msf import init_msf, create_module

    init_msf("/path/to/metasploit-framework")

    # Factory returns appropriate type
    exploit = create_module("exploit/linux/samba/is_known_pipename")
    assert isinstance(exploit, ExploitModule)

    exploit.options.RHOSTS = "192.168.1.100"
    session = exploit.exploit("cmd/unix/interact")
    if session:
        print(session.run_cmd("whoami"))
"""

from __future__ import annotations

from typing import Optional, Union

# Import from Rust extension
from .msf import (
    AssassinateError,
    Module as _RustModule,
    PySession as _RustPySession,
    check,
    create_module as _create_module_rust,
    exploit,
    framework_version,
    module_stats,
    add_module_path,
    reload_modules,
    get_module_info,
    get_session as _get_session_rust,
    init_msf,
    is_initialized,
    kill_session,
    create_shell_session,
    list_modules,
    list_sessions,
    search,
    sleep_releasing_gvl,
    job_list,
    job_info,
    job_kill,
    # Payload generation (Tier 2)
    forge_payload,
    forge_encoded,
    forge_executable,
    list_payloads,
    forge_payload_with_badchars,
    forge_formatted,
    transform_buffer,
    # Database (Tier 3)
    db_active,
    db_driver,
    db_hosts,
    db_services,
    db_vulns,
    db_creds,
    db_loot,
    db_report_host,
    db_report_service,
    db_report_vuln,
    db_report_cred,
    db_workspaces,
    db_workspace,
    db_set_workspace,
    db_add_workspace,
    db_find_workspace,
    db_delete_workspace,
    db_notes,
    db_report_note,
    db_delete_note,
    # Database query methods (Tier 4.5B)
    db_get_host,
    db_get_service,
    db_get_vuln,
    db_update_host,
    db_delete_host,
    db_update_service,
    db_delete_service,
    # Routing (Tier 4)
    route_add,
    route_remove,
    route_list,
    route_flush,
    route_exists,
    route_get,
)

# Import type-specific module classes
from .module import (
    BaseModule,
    AuxiliaryModule,
    EncoderModule,
    EvasionModule,
    ExploitModule,
    NopModule,
    PayloadModule,
    PostModule,
)
from .session import Session
from .options import ModuleOptions

# Type alias for any module type
AnyModule = Union[
    AuxiliaryModule,
    EncoderModule,
    EvasionModule,
    ExploitModule,
    NopModule,
    PayloadModule,
    PostModule,
]

# Module type to class mapping
_MODULE_CLASSES = {
    "auxiliary": AuxiliaryModule,
    "encoder": EncoderModule,
    "evasion": EvasionModule,
    "exploit": ExploitModule,
    "nop": NopModule,
    "payload": PayloadModule,
    "post": PostModule,
}


def create_module(module_name: str) -> AnyModule:
    """
    Create a module instance with the appropriate type-specific class.

    The factory inspects the module type and returns the correct subclass:
    - exploit/* -> ExploitModule
    - auxiliary/* -> AuxiliaryModule
    - post/* -> PostModule
    - evasion/* -> EvasionModule
    - payload/* -> PayloadModule
    - encoder/* -> EncoderModule
    - nop/* -> NopModule

    Args:
        module_name: Full module name (e.g., "exploit/linux/samba/is_known_pipename")

    Returns:
        Type-specific module object (ExploitModule, AuxiliaryModule, etc.)

    Example:
        exploit = create_module("exploit/linux/samba/is_known_pipename")
        assert isinstance(exploit, ExploitModule)
        assert exploit.module_type == "exploit"

        scanner = create_module("auxiliary/scanner/smb/smb_version")
        assert isinstance(scanner, AuxiliaryModule)
        assert scanner.module_type == "auxiliary"
    """
    rust_module = _create_module_rust(module_name)
    module_type = rust_module.module_type()

    # Get the appropriate class for this module type
    module_class = _MODULE_CLASSES.get(module_type, BaseModule)
    return module_class(rust_module)


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
    # Framework operations
    "module_stats",
    "add_module_path",
    "reload_modules",
    # Module factory
    "create_module",
    "list_modules",
    "search",
    "get_module_info",
    "check",
    "exploit",
    # Module classes (type-specific)
    "BaseModule",
    "AuxiliaryModule",
    "EncoderModule",
    "EvasionModule",
    "ExploitModule",
    "NopModule",
    "PayloadModule",
    "PostModule",
    # Module options
    "ModuleOptions",
    # Sessions
    "get_session",
    "list_sessions",
    "kill_session",
    "create_shell_session",
    "Session",
    # Jobs
    "job_list",
    "job_info",
    "job_kill",
    # Payload generation (Tier 2)
    "forge_payload",
    "forge_encoded",
    "forge_executable",
    "list_payloads",
    "forge_payload_with_badchars",
    "forge_formatted",
    "transform_buffer",
    # Database (Tier 3)
    "db_active",
    "db_driver",
    "db_hosts",
    "db_services",
    "db_vulns",
    "db_creds",
    "db_loot",
    "db_report_host",
    "db_report_service",
    "db_report_vuln",
    "db_report_cred",
    "db_workspaces",
    "db_workspace",
    "db_set_workspace",
    "db_add_workspace",
    "db_find_workspace",
    "db_delete_workspace",
    "db_notes",
    "db_report_note",
    "db_delete_note",
    # Database query methods (Tier 4.5B)
    "db_get_host",
    "db_get_service",
    "db_get_vuln",
    "db_update_host",
    "db_delete_host",
    "db_update_service",
    "db_delete_service",
    # Routing (Tier 4)
    "route_add",
    "route_remove",
    "route_list",
    "route_flush",
    "route_exists",
    "route_get",
    # GVL
    "sleep_releasing_gvl",
    # Exception
    "AssassinateError",
    # Type alias
    "AnyModule",
]
