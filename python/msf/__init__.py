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

import logging
from typing import Optional, Union

# Get logger for this module
logger = logging.getLogger("msf")

# Track whether the Rust extension is available
_RUST_AVAILABLE = False
_RUST_IMPORT_ERROR = None

# Try to import from Rust extension
try:
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
        # GVL functions imported but not re-exported (internal use only)
        poll_releasing_gvl as _poll_releasing_gvl,
        sleep_releasing_gvl as _sleep_releasing_gvl,
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
    _RUST_AVAILABLE = True
except ImportError as e:
    _RUST_IMPORT_ERROR = e
    # Define placeholder error class
    class AssassinateError(Exception):
        """Placeholder when Rust module not available."""
        pass

    # Create stub functions that raise helpful errors
    def _not_built(*args, **kwargs):
        raise ImportError(
            "The msf Rust module is not built. Run one of:\n"
            "  uv run maturin develop\n"
            "  uv run assassinate build"
        )

    # Stub out all the Rust functions
    _RustModule = None
    _RustPySession = None
    check = _not_built
    _create_module_rust = _not_built
    exploit = _not_built
    framework_version = _not_built
    module_stats = _not_built
    add_module_path = _not_built
    reload_modules = _not_built
    get_module_info = _not_built
    _get_session_rust = _not_built
    init_msf = _not_built
    is_initialized = lambda: False
    kill_session = _not_built
    create_shell_session = _not_built
    list_modules = _not_built
    list_sessions = _not_built
    search = _not_built
    _poll_releasing_gvl = _not_built
    _sleep_releasing_gvl = _not_built
    job_list = _not_built
    job_info = _not_built
    job_kill = _not_built
    forge_payload = _not_built
    forge_encoded = _not_built
    forge_executable = _not_built
    list_payloads = _not_built
    forge_payload_with_badchars = _not_built
    forge_formatted = _not_built
    transform_buffer = _not_built
    db_active = _not_built
    db_driver = _not_built
    db_hosts = _not_built
    db_services = _not_built
    db_vulns = _not_built
    db_creds = _not_built
    db_loot = _not_built
    db_report_host = _not_built
    db_report_service = _not_built
    db_report_vuln = _not_built
    db_report_cred = _not_built
    db_workspaces = _not_built
    db_workspace = _not_built
    db_set_workspace = _not_built
    db_add_workspace = _not_built
    db_find_workspace = _not_built
    db_delete_workspace = _not_built
    db_notes = _not_built
    db_report_note = _not_built
    db_delete_note = _not_built
    db_get_host = _not_built
    db_get_service = _not_built
    db_get_vuln = _not_built
    db_update_host = _not_built
    db_delete_host = _not_built
    db_update_service = _not_built
    db_delete_service = _not_built
    route_add = _not_built
    route_remove = _not_built
    route_list = _not_built
    route_flush = _not_built
    route_exists = _not_built
    route_get = _not_built

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
    logger.debug(f"create_module() called with: {module_name}")
    try:
        rust_module = _create_module_rust(module_name)
        module_type = rust_module.module_type()
        logger.debug(f"Module type detected: {module_type}")

        # Get the appropriate class for this module type
        module_class = _MODULE_CLASSES.get(module_type, BaseModule)
        instance = module_class(rust_module)
        logger.info(f"Created {module_class.__name__}: {module_name}")
        return instance
    except Exception as e:
        logger.error(f"Failed to create module {module_name}: {e}")
        raise


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
    logger.debug(f"get_session() called with id: {session_id}")
    try:
        rust_session = _get_session_rust(session_id)
        if rust_session is not None:
            session = Session(rust_session)
            logger.info(f"Retrieved session {session_id}: {session.session_type}")
            return session
        logger.debug(f"Session {session_id} not found")
        return None
    except Exception as e:
        logger.error(f"Failed to get session {session_id}: {e}")
        raise


def wait_for_new_session(
    existing_sessions: Optional[set] = None,
    timeout_ms: Optional[int] = None,
    interval_ms: Optional[int] = None,
) -> Optional[Session]:
    """
    Wait for a new session to appear while releasing the GVL.

    This function polls for new sessions, releasing the Ruby GVL between
    checks so that background Ruby threads (like MSF exploit jobs) can
    execute.

    Args:
        existing_sessions: Set of session IDs that existed before waiting.
                          If None, captures current sessions at call time.
        timeout_ms: Maximum time to wait in milliseconds (default: 60000)
        interval_ms: Polling interval in milliseconds (default: 100)

    Returns:
        Session object if a new session appears, None if timeout

    Example:
        # Launch exploit as background job
        exploit.exploit_job("cmd/unix/interact")

        # Wait for session with GVL released
        session = wait_for_new_session(timeout_ms=30000)
        if session:
            print(session.run_cmd("whoami"))
    """
    logger.debug(
        f"wait_for_new_session() called (timeout_ms={timeout_ms}, interval_ms={interval_ms})"
    )

    if existing_sessions is None:
        existing_sessions = set(list_sessions())
        logger.debug(f"Captured existing sessions: {existing_sessions}")

    new_session_id = [None]  # Use list to allow mutation in closure
    poll_count = [0]

    def check_for_session() -> bool:
        poll_count[0] += 1
        current = set(list_sessions())
        new_sessions = current - existing_sessions
        if new_sessions:
            new_session_id[0] = next(iter(new_sessions))
            logger.debug(
                f"New session found: {new_session_id[0]} (after {poll_count[0]} polls)"
            )
            return True
        return False

    logger.info(f"Waiting for new session (timeout: {timeout_ms or 60000}ms)...")
    found = _poll_releasing_gvl(check_for_session, interval_ms, timeout_ms)

    if found and new_session_id[0] is not None:
        session = get_session(new_session_id[0])
        logger.success(f"New session established: {new_session_id[0]}")
        return session

    logger.warning(
        f"Timeout waiting for session after {poll_count[0]} polls"
    )
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
    "wait_for_new_session",
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
    # Exception
    "AssassinateError",
    # Type alias
    "AnyModule",
]


# =============================================================================
# Auto-configure logging from environment variables
# =============================================================================
# Import shared logging configuration from assassinate.log_config
# This ensures consistent logging setup whether using msf directly or via assassinate
from assassinate.log_config import setup_logging as _setup_logging

# The import of log_config triggers auto-configuration via _auto_configure()
# which reads ASSASSINATE_LOG_LEVEL and ASSASSINATE_LOG_FILE environment variables
