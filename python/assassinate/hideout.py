"""Hideout module for managing the assassination framework runtime.

The Hideout is where the hitman operates from. It handles:
- Environment verification and setup
- Framework initialization (direct Pyo3 bridge to Ruby/MSF)
- Ruby environment detection and configuration
- Arsenal access for weapon discovery
- Contract creation for targeted operations
- Kill tracking for compromised assets

For installation/setup, use: assassinate-setup --install

Example:
    >>> from assassinate import Hideout, Target
    >>>
    >>> with Hideout() as hideout:
    ...     # Find weapons
    ...     weapons = hideout.arsenal.find("samba", type="exploit")
    ...     weapon = weapons[0]
    ...
    ...     # Create contract
    ...     target = Target("192.168.1.100")
    ...     contract = hideout.contract(target, weapon)
    ...     contract.configure(SMB_SHARE_NAME="myshare")
    ...
    ...     # Profile and execute
    ...     if contract.profile():
    ...         kill = contract.execute()
    ...         if kill:
    ...             print(kill.interrogate("whoami"))
"""

from __future__ import annotations

import os
from os import environ
from pathlib import Path
from subprocess import DEVNULL, CalledProcessError, TimeoutExpired, run
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Union

import msf
from assassinate.log_config import get_logger

if TYPE_CHECKING:
    from types import TracebackType
    from assassinate.arsenal import Arsenal
    from assassinate.config import AssassinateSettings
    from assassinate.contract import Contract, MassContract
    from assassinate.kill import Kill
    from assassinate.target import Target
    from assassinate.weapon import Bullet, Weapon

logger = get_logger("hideout")


class Hideout:
    """The Hideout - operational headquarters for assassination missions.

    Manages the runtime environment and provides access to the full
    Metasploit Framework arsenal through the embedded Ruby VM.

    The Hideout is your base of operations. From here you can:
    - Access the full MSF module arsenal (exploits, payloads, auxiliary)
    - Create contracts for targeted assassinations
    - Execute precision strikes against targets
    - Track confirmed kills (active sessions)
    - Plan and execute complex multi-stage operations

    Note:
        For installation, use: assassinate-setup --install
        Hideout assumes the environment is already set up.

    Attributes:
        version: Framework version string
        safehouse: Path to MSF installation
        arsenal: Weapon search and discovery

    Example:
        >>> with Hideout() as hideout:
        ...     # Search for weapons
        ...     weapons = hideout.arsenal.find("smb", rank="excellent")
        ...
        ...     # Create and execute a contract
        ...     contract = hideout.contract("192.168.1.100", weapons[0])
        ...     if contract.profile():
        ...         kill = contract.execute()
        ...         print(kill.interrogate("id"))
    """

    __slots__ = (
        "version",
        "safehouse",
        "_initialized",
        "_arsenal",
        "_kills",
        "_config",
    )

    def __init__(
        self,
        safehouse: str | Path | None = None,
        skip_verify: bool = False,
    ):
        """Initialize the Hideout.

        Args:
            safehouse: Path to MSF installation. If not provided, uses config
                       or auto-detection.
            skip_verify: Skip environment verification (not recommended)

        Raises:
            RuntimeError: If environment not ready or initialization fails
            EnvironmentError: If MSF installation cannot be found
        """
        logger.debug("Establishing hideout...")
        self._initialized = False
        self.version: str | None = None
        self._arsenal: Optional["Arsenal"] = None
        self._kills: Dict[int, "Kill"] = {}

        # Load configuration
        from assassinate.config import get_config

        self._config: "AssassinateSettings" = get_config()

        # Discover the safehouse (MSF installation)
        self.safehouse = self._locate_safehouse(safehouse)
        if self.safehouse is None:
            raise EnvironmentError(
                "MSF installation not found. Either:\n"
                "  1. Run 'assassinate-setup config' to auto-detect and save\n"
                "  2. Set ASAS_METASPLOIT__ROOT environment variable\n"
                "  3. Pass safehouse='/path/to/msf' to Hideout()\n"
                "  4. Create ~/.config/assassinate/config.yaml with metasploit.root"
            )
        logger.debug(f"Safehouse located: {self.safehouse}")

        # Verify environment is ready
        if not skip_verify:
            self._verify_environment()

        try:
            # Initialize the framework (embeds Ruby VM directly)
            if not msf.is_initialized():
                logger.info("Initializing framework connection...")
                msf.init_msf(str(self.safehouse))

            self.version = msf.framework_version()
            self._initialized = True
            logger.success(f"Hideout established - Framework v{self.version}")

        except Exception as e:
            logger.error(f"Failed to establish hideout: {e}")
            raise RuntimeError(f"Failed to establish hideout: {e}") from e

    def __enter__(self) -> Hideout:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        self.evacuate()
        return False

    def evacuate(self) -> None:
        """Evacuate the hideout and clean up resources.

        Kills all active sessions and cleans up.
        """
        logger.debug("Evacuating hideout...")
        # Kill any remaining sessions
        try:
            for sid in msf.list_sessions():
                try:
                    msf.kill_session(sid)
                except Exception:
                    pass
        except Exception:
            pass
        self._kills.clear()
        logger.info("Hideout evacuated")

    # =========================================================================
    # Arsenal Access
    # =========================================================================

    @property
    def arsenal(self) -> "Arsenal":
        """Access the weapon arsenal for search and discovery.

        Returns:
            Arsenal instance for finding weapons

        Example:
            >>> weapons = hideout.arsenal.find("samba", type="exploit")
            >>> weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
        """
        if self._arsenal is None:
            from assassinate.arsenal import Arsenal
            self._arsenal = Arsenal(self)
        return self._arsenal

    # =========================================================================
    # Contract Creation
    # =========================================================================

    def contract(
        self,
        target: Union["Target", str],
        weapon: Union["Weapon", str],
        bullet: Optional[Union["Bullet", str]] = None,
    ) -> "Contract":
        """Create a contract for a hit.

        Args:
            target: Target object or IP string
            weapon: Weapon object or module name
            bullet: Bullet object or name (auto-selected if not provided)

        Returns:
            Contract ready for configuration and execution

        Example:
            >>> contract = hideout.contract(
            ...     target="192.168.1.100",
            ...     weapon="exploit/linux/samba/is_known_pipename"
            ... )
            >>> contract.configure(SMB_SHARE_NAME="myshare")
            >>> if contract.profile():
            ...     kill = contract.execute()
        """
        from assassinate.contract import Contract
        return Contract(target, weapon, bullet)

    def mass_contract(
        self,
        targets: List[Union["Target", str]],
        weapon: Union["Weapon", str],
        bullet: Optional[Union["Bullet", str]] = None,
        max_parallel: int = 10,
    ) -> "MassContract":
        """Create a mass contract for parallel attacks.

        Args:
            targets: List of targets (Target objects or IP strings)
            weapon: Weapon to use for all targets
            bullet: Bullet to use (auto-selected if not provided)
            max_parallel: Maximum concurrent operations

        Returns:
            MassContract ready for configuration and mass execution

        Example:
            >>> targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
            >>> mass = hideout.mass_contract(targets, weapon)
            >>> mass.configure(SMB_SHARE_NAME="myshare")
            >>> kills = mass.massacre()
        """
        from assassinate.contract import MassContract
        return MassContract(targets, weapon, bullet, max_parallel)

    # =========================================================================
    # Quick Operations
    # =========================================================================

    def quick_hit(
        self,
        target: Union["Target", str],
        weapon: Union["Weapon", str],
        bullet: Optional[Union["Bullet", str]] = None,
        timeout: int = 60,
        options: Optional[Mapping[str, Any]] = None,
    ) -> Optional["Kill"]:
        """One-liner: configure and execute immediately.

        Convenience method for quick exploitation without managing
        Contract objects manually.

        Args:
            target: Target object or IP string
            weapon: Weapon object or module name
            bullet: Bullet (auto-selected if not provided)
            timeout: Seconds to wait for session
            options: Weapon configuration options (e.g., {"RHOSTS": "...", "SMBUser": "..."})

        Returns:
            Kill on success, None on failure

        Example:
            >>> kill = hideout.quick_hit(
            ...     target="192.168.1.100",
            ...     weapon="exploit/linux/samba/is_known_pipename",
            ...     options={"SMB_SHARE_NAME": "myshare", "SMBUser": "root"}
            ... )
            >>> if kill:
            ...     print(kill.interrogate("id"))
        """
        contract = self.contract(target, weapon, bullet)
        if options:
            contract.configure(**options)
        kill = contract.execute(timeout)

        if kill:
            self._kills[kill.id] = kill

        return kill

    # =========================================================================
    # Kill Management (Active Sessions)
    # =========================================================================

    def kills(self) -> List["Kill"]:
        """Get all confirmed kills (active sessions).

        Returns:
            List of Kill objects for active sessions

        Example:
            >>> for kill in hideout.kills():
            ...     print(f"{kill.host}: {kill.interrogate('whoami')}")
        """
        from assassinate.kill import Kill

        result = []
        for sid in msf.list_sessions():
            # Check if we have a cached Kill
            if sid in self._kills:
                kill = self._kills[sid]
                if kill.confirmed:
                    result.append(kill)
                else:
                    del self._kills[sid]
            else:
                # Create new Kill wrapper
                session = msf.get_session(sid)
                if session:
                    kill = Kill(session)
                    self._kills[sid] = kill
                    result.append(kill)

        return result

    def get_kill(self, session_id: int) -> Optional["Kill"]:
        """Get a specific kill by session ID.

        Args:
            session_id: Session ID to retrieve

        Returns:
            Kill object or None if not found
        """
        from assassinate.kill import Kill

        if session_id in self._kills:
            kill = self._kills[session_id]
            if kill.confirmed:
                return kill
            del self._kills[session_id]

        session = msf.get_session(session_id)
        if session:
            kill = Kill(session)
            self._kills[session_id] = kill
            return kill

        return None

    def silence_all(self) -> int:
        """Silence all kills (terminate all sessions).

        Returns:
            Number of sessions terminated
        """
        count = 0
        for kill in self.kills():
            try:
                kill.silence()
                count += 1
            except Exception:
                pass
        self._kills.clear()
        return count

    # =========================================================================
    # Legacy Arsenal Access - Module Operations
    # =========================================================================

    def arm(self, weapon_name: str) -> msf.AnyModule:
        """Arm a weapon from the arsenal (legacy method).

        Loads and configures an MSF module for use.
        Prefer using `hideout.arsenal.get()` for new code.

        Args:
            weapon_name: Full module path (e.g., "exploit/linux/samba/is_known_pipename")

        Returns:
            Armed module ready for configuration and execution.

        Example:
            >>> weapon = hideout.arm("exploit/unix/ftp/vsftpd_234_backdoor")
            >>> weapon.options.RHOSTS = "192.168.1.100"
            >>> asset = weapon.execute("cmd/unix/interact")
        """
        logger.debug(f"Arming weapon: {weapon_name}")
        return msf.create_module(weapon_name)

    def recon(self, query: str) -> List[str]:
        """Reconnaissance - search the arsenal for available weapons (legacy method).

        Prefer using `hideout.arsenal.find()` for new code.

        Args:
            query: Search query (supports MSF search syntax)

        Returns:
            List of matching module names.

        Example:
            >>> weapons = hideout.recon("type:exploit smb")
            >>> for w in weapons[:5]:
            ...     print(f"  → {w}")
        """
        logger.debug(f"Recon query: {query}")
        return msf.search(query)

    def inventory(self, module_type: str) -> List[str]:
        """Get full inventory of weapons by type (legacy method).

        Args:
            module_type: Type of modules ("exploit", "auxiliary", "payload", etc.)

        Returns:
            List of all module names of that type.

        Example:
            >>> exploits = hideout.inventory("exploit")
            >>> print(f"Arsenal contains {len(exploits)} exploits")
        """
        return msf.list_modules(module_type)

    # =========================================================================
    # Legacy Asset Management - Sessions
    # =========================================================================

    def assets(self) -> List[int]:
        """List all compromised assets (active sessions) (legacy method).

        Prefer using `hideout.kills()` for new code.

        Returns:
            List of session IDs.

        Example:
            >>> for sid in hideout.assets():
            ...     asset = hideout.get_asset(sid)
            ...     print(f"Asset {sid}: {asset.host}")
        """
        return msf.list_sessions()

    def get_asset(self, session_id: int) -> Optional[msf.Session]:
        """Retrieve a compromised asset by ID (legacy method).

        Prefer using `hideout.get_kill()` for new code.

        Args:
            session_id: Session ID to retrieve.

        Returns:
            Session object or None if not found.
        """
        return msf.get_session(session_id)

    def terminate_asset(self, session_id: int) -> bool:
        """Terminate a compromised asset (kill session) (legacy method).

        Args:
            session_id: Session ID to terminate.

        Returns:
            True if successfully terminated.
        """
        logger.debug(f"Terminating asset {session_id}")
        if session_id in self._kills:
            del self._kills[session_id]
        return msf.kill_session(session_id)

    # =========================================================================
    # Operations Management - Jobs
    # =========================================================================

    def active_ops(self) -> List[int]:
        """List active operations (background jobs).

        Returns:
            List of job IDs.
        """
        return msf.job_list()

    def abort_op(self, job_id: int) -> bool:
        """Abort an active operation.

        Args:
            job_id: Job ID to abort.

        Returns:
            True if successfully aborted.
        """
        logger.debug(f"Aborting operation {job_id}")
        return msf.job_kill(job_id)

    # =========================================================================
    # Environment Verification
    # =========================================================================

    def _verify_environment(self) -> None:
        """Verify environment using assassinate-setup --verify.

        Raises:
            RuntimeError: If verification fails.
        """
        logger.info("Verifying operational environment...")
        try:
            result = run(
                ["assassinate-setup", "--verify"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.error("Environment verification failed")
                raise RuntimeError(
                    "Environment not ready. Run: assassinate-setup --install\n"
                    f"{result.stdout}"
                )
            logger.debug("Environment verified successfully")
        except FileNotFoundError:
            # assassinate-setup not in PATH, do quick local check
            logger.debug("assassinate-setup not in PATH, doing quick check")
            self._quick_verify()
        except TimeoutExpired:
            logger.error("Environment verification timed out")
            raise RuntimeError("Environment verification timed out")

    def _quick_verify(self) -> None:
        """Quick local verification when assassinate-setup not available."""
        # Check MSF exists
        if not self.safehouse.exists():
            raise RuntimeError(
                f"Safehouse not found at {self.safehouse}. "
                "Run: assassinate-setup --install"
            )

        # Check Gemfile exists (valid MSF installation)
        if not (self.safehouse / "Gemfile").exists():
            raise RuntimeError(
                f"Invalid safehouse at {self.safehouse} (no Gemfile). "
                "Run: assassinate-setup --install"
            )

        logger.debug("Quick verification passed")

    # =========================================================================
    # Path Discovery
    # =========================================================================

    def _locate_safehouse(self, explicit_path: str | Path | None = None) -> Path | None:
        """Locate the MSF safehouse (installation directory).

        Priority (highest first):
        1. Explicit path argument
        2. Configuration (env vars, config files, auto-detection)

        Args:
            explicit_path: Explicitly provided MSF path (overrides all else)

        Returns:
            Path to MSF installation, or None if not found
        """
        # 1. Explicit path argument takes precedence
        if explicit_path is not None:
            path = Path(explicit_path).expanduser().resolve()
            logger.debug(f"Safehouse from explicit path: {path}")
            return path

        # 2. Use configuration (already handles env vars, config files, auto-detection)
        if self._config.metasploit.root is not None:
            logger.debug(f"Safehouse from config: {self._config.metasploit.root}")
            return self._config.metasploit.root

        # Not found
        logger.warning("No MSF installation found")
        return None

    # =========================================================================
    # Representation
    # =========================================================================

    @property
    def config(self) -> "AssassinateSettings":
        """Access the configuration settings.

        Returns:
            The AssassinateSettings instance used by this Hideout
        """
        return self._config

    def __repr__(self) -> str:
        status = "operational" if self._initialized else "compromised"
        kills = len(self._kills)
        return f"<Hideout status={status} version={self.version} kills={kills}>"
