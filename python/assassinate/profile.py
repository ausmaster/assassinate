"""Profile module - Target profiling and intelligence data structures.

This module provides data structures for storing information gathered
from compromised targets, including system profiles, harvested loot,
and context-aware recommendations.

Example:
    >>> profile = kill.profile()
    >>> print(f"OS: {profile.os_name}")
    >>> print(f"Privileged: {profile.is_privileged}")
    >>>
    >>> if profile.is_windows and profile.is_system:
    ...     print("Running as SYSTEM!")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class TargetProfile:
    """Immutable snapshot of a compromised target's system information.

    Gathered via meterpreter session methods like sys_sysinfo(), sys_getuid(),
    net_get_interfaces(), etc. Once captured, the profile doesn't change -
    create a new profile if you need updated information.

    Attributes:
        os: Full OS string (e.g., "Linux ubuntu 5.4.0 x86_64")
        os_name: Simplified OS name ("Linux", "Windows", "macOS")
        computer: Hostname
        architecture: CPU architecture ("x64", "x86", "arm64")
        user: Current user (e.g., "root", "SYSTEM", "Administrator")
        uid: Unix UID (None on Windows)
        privileges: Windows privilege tokens (empty on Unix)
        is_system: True if running as SYSTEM (Windows)
        interfaces: Network interface information
        routes: Routing table entries
        internal_networks: Discovered internal subnets (for pivoting)
        domain: Windows domain (if joined)
        logged_on_users: Currently logged on users

    Example:
        >>> profile = kill.profile()
        >>> if profile.is_privileged:
        ...     print(f"Root access on {profile.computer}")
        >>> for net in profile.internal_networks:
        ...     print(f"Internal network: {net}")
    """

    os: str = ""
    os_name: str = ""
    computer: str = ""
    architecture: str = ""
    user: str = ""
    uid: Optional[int] = None
    privileges: tuple = field(default_factory=tuple)  # Tuple for hashability
    is_system: bool = False
    interfaces: tuple = field(default_factory=tuple)  # Tuple of frozen dicts
    routes: tuple = field(default_factory=tuple)
    internal_networks: tuple = field(default_factory=tuple)
    domain: str = ""
    logged_on_users: tuple = field(default_factory=tuple)

    @property
    def is_privileged(self) -> bool:
        """Check if running with elevated privileges.

        Returns True for:
        - Linux/Unix: root (uid=0) or user contains "root"
        - Windows: SYSTEM, Administrator, or has SeDebugPrivilege
        """
        if self.is_windows:
            return (
                self.is_system
                or "administrator" in self.user.lower()
                or "SeDebugPrivilege" in self.privileges
                or "SeTcbPrivilege" in self.privileges
            )
        else:
            # Unix: check for root
            return self.uid == 0 or "root" in self.user.lower()

    @property
    def is_windows(self) -> bool:
        """Check if target is Windows."""
        return "windows" in self.os.lower() or self.os_name.lower() == "windows"

    @property
    def is_linux(self) -> bool:
        """Check if target is Linux."""
        return "linux" in self.os.lower() or self.os_name.lower() == "linux"

    @property
    def is_macos(self) -> bool:
        """Check if target is macOS."""
        return (
            "darwin" in self.os.lower()
            or "macos" in self.os.lower()
            or self.os_name.lower() == "macos"
        )

    @property
    def is_unix(self) -> bool:
        """Check if target is Unix-like (Linux, macOS, BSD, etc.)."""
        return not self.is_windows

    @property
    def is_64bit(self) -> bool:
        """Check if target is 64-bit architecture."""
        return "64" in self.architecture or "x64" in self.architecture.lower()

    def __str__(self) -> str:
        priv = "privileged" if self.is_privileged else "unprivileged"
        return f"<TargetProfile {self.os_name} {self.architecture} user={self.user} [{priv}]>"


@dataclass
class LootItem:
    """A piece of loot harvested from a target.

    Represents credentials, files, hashes, or other valuable data
    extracted during post-exploitation.

    Attributes:
        type: Category of loot ("credential", "file", "hash", "token", "key")
        source_module: Post module that extracted this loot
        data: The actual loot data (format varies by type)
        host: Target host where loot was found
        timestamp: When the loot was harvested (optional)

    Example:
        >>> for item in result.loot:
        ...     if item.type == "credential":
        ...         print(f"{item.data['user']}:{item.data['password']}")
    """

    type: str
    source_module: str
    data: Dict[str, Any]
    host: str
    timestamp: Optional[str] = None

    def __str__(self) -> str:
        return f"<LootItem {self.type} from {self.source_module}>"


@dataclass
class HarvestResult:
    """Result of a harvest() operation.

    Contains the target profile, all harvested loot, and statistics
    about what was collected.

    Attributes:
        profile: The target's system profile
        loot: List of harvested loot items
        creds_stored: Number of credentials stored in database
        modules_run: List of post modules that were executed
        errors: Any errors encountered during harvesting

    Example:
        >>> result = kill.harvest(auto=True)
        >>> print(f"Found {len(result.loot)} items")
        >>> print(f"Stored {result.creds_stored} credentials")
        >>> for mod in result.modules_run:
        ...     print(f"  Ran: {mod}")
    """

    profile: TargetProfile
    loot: List[LootItem] = field(default_factory=list)
    creds_stored: int = 0
    modules_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def credentials(self) -> List[LootItem]:
        """Get all credential loot items."""
        return [item for item in self.loot if item.type == "credential"]

    @property
    def files(self) -> List[LootItem]:
        """Get all file loot items."""
        return [item for item in self.loot if item.type == "file"]

    @property
    def hashes(self) -> List[LootItem]:
        """Get all hash loot items."""
        return [item for item in self.loot if item.type == "hash"]

    def __str__(self) -> str:
        return f"<HarvestResult {len(self.loot)} items, {self.creds_stored} creds stored>"


@dataclass
class Recommendation:
    """A context-aware action recommendation.

    Generated based on the target profile to suggest next steps
    like privilege escalation, persistence, or lateral movement.

    Attributes:
        category: Type of recommendation ("privesc", "persist", "lateral", "harvest", "pivot")
        priority: Importance (1 = highest, 5 = lowest)
        title: Short description
        description: Detailed explanation
        module: Suggested MSF module to run (optional)
        options: Suggested module options (optional)

    Example:
        >>> for rec in kill.recommend_actions():
        ...     print(f"[{rec.priority}] {rec.title}")
        ...     if rec.module:
        ...         print(f"    Suggested: {rec.module}")
    """

    category: str
    priority: int
    title: str
    description: str
    module: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "Recommendation") -> bool:
        """Sort by priority (lower is more important)."""
        return self.priority < other.priority

    def __str__(self) -> str:
        return f"<Recommendation [{self.priority}] {self.category}: {self.title}>"


# Post-module registry for context-aware harvesting
# Maps (os, privilege_level) -> list of appropriate post modules
HARVEST_MODULES: Dict[str, Dict[str, List[str]]] = {
    "linux": {
        "root": [
            "post/linux/gather/hashdump",
            "post/multi/gather/ssh_creds",
            "post/linux/gather/enum_configs",
            "post/linux/gather/enum_network",
            "post/linux/gather/ecryptfs_creds",
        ],
        "user": [
            "post/multi/gather/env",
            "post/linux/gather/enum_users_history",
            "post/linux/gather/enum_configs",
            "post/multi/gather/firefox_creds",
            "post/multi/gather/filezilla_creds",
        ],
    },
    "windows": {
        "system": [
            "post/windows/gather/hashdump",
            "post/windows/gather/credentials/credential_collector",
            "post/windows/gather/lsa_secrets",
            "post/windows/gather/cachedump",
            "post/windows/gather/smart_hashdump",
        ],
        "admin": [
            "post/windows/gather/enum_logged_on_users",
            "post/windows/gather/credentials/windows_autologin",
            "post/windows/gather/enum_chrome",
            "post/multi/gather/firefox_creds",
        ],
        "user": [
            "post/multi/gather/env",
            "post/windows/gather/enum_logged_on_users",
            "post/multi/gather/firefox_creds",
            "post/multi/gather/filezilla_creds",
        ],
    },
    "macos": {
        "root": [
            "post/osx/gather/hashdump",
            "post/multi/gather/ssh_creds",
            "post/osx/gather/enum_keychain",
        ],
        "user": [
            "post/multi/gather/env",
            "post/multi/gather/firefox_creds",
            "post/osx/gather/enum_keychain",
        ],
    },
}

# Privilege escalation suggestions by platform
PRIVESC_MODULES: Dict[str, List[str]] = {
    "linux": [
        "post/multi/recon/local_exploit_suggester",
        "post/linux/gather/enum_protections",
    ],
    "windows": [
        "post/multi/recon/local_exploit_suggester",
        "post/windows/gather/enum_patches",
    ],
    "macos": [
        "post/multi/recon/local_exploit_suggester",
    ],
}

# Persistence modules by platform
PERSISTENCE_MODULES: Dict[str, List[str]] = {
    "linux": [
        "post/linux/manage/sshkey_persistence",
    ],
    "windows": [
        "post/windows/manage/persistence_exe",
    ],
    "macos": [
        "post/osx/manage/launch_daemon_persist",
    ],
}
