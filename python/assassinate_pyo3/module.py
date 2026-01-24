"""Pythonic wrapper for ExploitModule with rich introspection."""

import asyncio
import time
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from .options import ModuleOptions

if TYPE_CHECKING:
    from .session import Session


class Module:
    """
    Rich Python wrapper around MSF exploit/auxiliary modules.

    Provides intuitive access to module configuration and execution.

    Example:
        module = msf.create_module("exploit/linux/samba/is_known_pipename")

        # Introspect
        print(module.author)
        print(module.references)
        print(module.compatible_payloads())

        # Configure with attribute-style access
        module.options.RHOSTS = "192.168.1.100"
        module.options.RPORT = 445

        # Or dict-style
        module.options["SMBUser"] = "admin"

        # Validate and execute
        if module.validate():
            session = module.exploit("cmd/unix/interact")
    """

    def __init__(self, rust_module):
        self._rust = rust_module
        self._options = None  # Lazy-loaded ModuleOptions

    # === Options (attribute-style access) ===

    @property
    def options(self) -> ModuleOptions:
        """Access module options with attribute-style syntax."""
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

    @property
    def targets(self) -> List[str]:
        """Available exploit targets."""
        return self._rust.targets()

    # === Compatibility ===

    def compatible_payloads(self) -> List[str]:
        """Get list of compatible payload names."""
        return self._rust.compatible_payloads()

    def actions(self) -> List[str]:
        """Get available actions (for auxiliary/post modules)."""
        return self._rust.actions()

    def default_action(self) -> Optional[str]:
        """Get default action name."""
        return self._rust.default_action()

    # === Validation ===

    def validate(self) -> bool:
        """Validate all options are correctly configured."""
        return self._rust.validate()

    def has_check(self) -> bool:
        """Check if module supports vulnerability checking."""
        return self._rust.has_check()

    # === Execution ===

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
                    module = msf.create_module("exploit/linux/samba/is_known_pipename")
                    module.options.RHOSTS = target
                    tasks.append(module.exploit_async("cmd/unix/interact"))
                return await asyncio.gather(*tasks)
        """
        from . import sleep_releasing_gvl, list_sessions, get_session
        from .session import Session

        # Launch exploit as background job (creates Ruby thread)
        self._rust.exploit_job(payload)

        # Track sessions that existed before our exploit
        seen_sessions: Set[int] = set(list_sessions())
        start_time = time.time()

        # Poll for new sessions, releasing GVL between checks
        while time.time() - start_time < timeout:
            # Release GVL so Ruby background threads can execute
            # This is where the actual exploit runs!
            sleep_releasing_gvl(100)  # 100ms with GVL released

            # Check for new sessions (GVL re-acquired automatically)
            current_sessions = set(list_sessions())
            new_sessions = current_sessions - seen_sessions

            if new_sessions:
                # Found a new session - return it
                session_id = next(iter(new_sessions))
                rust_session = get_session(session_id)
                if rust_session:
                    return rust_session
                # Session disappeared? Keep looking
                seen_sessions = current_sessions

            # Yield to Python event loop (enables true async)
            await asyncio.sleep(0)

        return None

    def exploit_job(self, payload: str) -> Optional[str]:
        """
        Run exploit as background job (non-blocking).

        This enables parallel exploitation by launching the exploit handler
        as a background job. Monitor for new sessions with list_sessions()
        and check active jobs with job_list().

        Args:
            payload: Payload name (e.g., "cmd/unix/interact")

        Returns:
            Job ID (as string) if job was started, None if it completed immediately

        Example:
            # Launch multiple exploits in parallel
            jobs = []
            for target in ["192.168.1.100", "192.168.1.101"]:
                module = msf.create_module("exploit/linux/samba/is_known_pipename")
                module.options.RHOSTS = target
                job_id = module.exploit_job("cmd/unix/interact")
                if job_id:
                    jobs.append(job_id)

            # Poll for sessions while jobs run
            import time
            seen_sessions = set()
            while msf.job_list():
                for sid in msf.list_sessions():
                    if sid not in seen_sessions:
                        seen_sessions.add(sid)
                        session = msf.get_session(sid)
                        print(f"Got session on {session.host}!")
                time.sleep(1)
        """
        return self._rust.exploit_job(payload)

    # === Backward Compatibility ===

    def set_option(self, key: str, value: Any) -> None:
        """Set option value (prefer module.options.KEY = value)."""
        self._rust.set_option(key, str(value))

    def __repr__(self) -> str:
        return f"<Module: {self.fullname}>"
