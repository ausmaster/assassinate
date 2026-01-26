"""Catalog module - indexed collections of Weapons and Bullets for easy filtering.

Provides pre-indexed, filterable collections that make weapon and bullet
discovery intuitive and fast.

Example:
    >>> # Filter weapons
    >>> smb_exploits = arsenal.weapons.filter(service="smb", type="exploit")
    >>> for w in smb_exploits:
    ...     print(f"{w.name} ({w.rank}) - port {w.port}")

    >>> # Get the actual Weapon object
    >>> weapon = smb_exploits[0].weapon()

    >>> # Filter bullets
    >>> meterpreter_bullets = arsenal.bullets.filter(
    ...     platform="linux",
    ...     is_meterpreter=True,
    ...     connection="reverse"
    ... )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Dict, Iterator, List, Optional, Set, Union

from assassinate.console import print_weapon_info, print_bullet_info

if TYPE_CHECKING:
    from assassinate.weapon import Bullet, Weapon
    from assassinate.arsenal import Arsenal


@dataclass
class WeaponInfo:
    """Lightweight weapon metadata for fast filtering.

    Contains extracted fields from MSF modules that are commonly
    used for filtering and discovery. The full Weapon object can
    be retrieved via the weapon() method.

    Attributes:
        fullname: Full module path (e.g., "exploit/linux/samba/is_known_pipename")
        name: Short name (last path component)
        type: Module type (exploit, auxiliary, post, etc.)
        rank: Reliability rank string
        rank_score: Numeric rank for sorting (600=excellent, 0=manual)
        platforms: Target platforms (linux, windows, etc.)
        service: Inferred target service (smb, ftp, http, etc.)
        port: Default target port
        cves: List of CVE identifiers
        description: Short description (first sentence)
        authors: List of authors
    """

    fullname: str
    name: str
    type: str
    rank: str
    rank_score: int
    platforms: List[str] = field(default_factory=list)
    service: Optional[str] = None
    port: Optional[int] = None
    cves: List[str] = field(default_factory=list)
    description: str = ""
    authors: List[str] = field(default_factory=list)

    # Reference to parent catalog for lazy weapon loading
    _catalog: Optional["WeaponCatalog"] = field(default=None, repr=False)

    def weapon(self) -> "Weapon":
        """Get the full Weapon object.

        Returns:
            Weapon instance with all methods available
        """
        if self._catalog:
            return self._catalog._get_weapon(self.fullname)
        # Fallback: create directly
        from assassinate.weapon import Weapon
        import msf
        return Weapon(msf.create_module(self.fullname))

    def matches(self, **criteria) -> bool:
        """Check if this weapon matches all criteria.

        Args:
            **criteria: Field names and values to match

        Returns:
            True if all criteria match
        """
        for key, value in criteria.items():
            if not self._match_field(key, value):
                return False
        return True

    def _match_field(self, key: str, value) -> bool:
        """Check if a single field matches."""
        # Handle special cases
        if key == "platform":
            # Match if any platform matches
            return value.lower() in [p.lower() for p in self.platforms]

        if key == "min_rank":
            # Minimum rank score
            rank_scores = {
                "excellent": 600, "great": 500, "good": 400,
                "normal": 300, "average": 200, "low": 100, "manual": 0,
            }
            min_score = rank_scores.get(value.lower(), 0) if isinstance(value, str) else value
            return self.rank_score >= min_score

        if key == "has_cve":
            return len(self.cves) > 0 if value else len(self.cves) == 0

        if key == "query":
            # Fuzzy text search
            query_lower = value.lower()
            return (
                query_lower in self.fullname.lower() or
                query_lower in self.description.lower() or
                any(query_lower in cve.lower() for cve in self.cves)
            )

        # Direct field match
        field_value = getattr(self, key, None)
        if field_value is None:
            return value is None

        if isinstance(field_value, str) and isinstance(value, str):
            return field_value.lower() == value.lower()

        return field_value == value

    def __repr__(self) -> str:
        parts = [f"<WeaponInfo {self.fullname} ({self.rank})"]
        if self.service:
            parts.append(f"service={self.service}")
        if self.port:
            parts.append(f"port={self.port}")
        if self.cves:
            parts.append(f"cves={len(self.cves)}")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return f"{self.fullname} ({self.rank})"

    def summary(self, full: bool = False) -> str:
        """Get a detailed multi-line summary of this weapon.

        Args:
            full: If True, show all authors without truncation.

        Returns:
            Formatted string with full weapon details
        """
        lines = [
            f"{'═' * 70}",
            f"  {self.fullname}",
            f"{'═' * 70}",
            f"",
            f"  Type: {self.type.upper()}    Rank: {self.rank.upper()}",
        ]

        if self.service or self.port:
            svc_info = []
            if self.service:
                svc_info.append(f"Service: {self.service}")
            if self.port:
                svc_info.append(f"Port: {self.port}")
            lines.append(f"  {', '.join(svc_info)}")

        if self.platforms:
            lines.append(f"  Platforms: {', '.join(self.platforms)}")

        if self.cves:
            lines.append(f"  CVEs: {', '.join(self.cves)}")

        if self.description:
            lines.append(f"")
            lines.append(f"  Description:")
            # Word-wrap description at ~65 chars
            desc = self.description
            while desc:
                if len(desc) <= 65:
                    lines.append(f"    {desc}")
                    break
                # Find last space before 65 chars
                idx = desc[:65].rfind(' ')
                if idx == -1:
                    idx = 65
                lines.append(f"    {desc[:idx]}")
                desc = desc[idx:].lstrip()

        if self.authors:
            lines.append(f"")
            if full:
                lines.append(f"  Authors: {', '.join(self.authors)}")
            else:
                lines.append(f"  Authors: {', '.join(self.authors[:3])}")
                if len(self.authors) > 3:
                    lines[-1] += f" (+{len(self.authors) - 3} more)"

        lines.append(f"{'─' * 70}")
        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: If True, show all authors without truncation.
        """
        print_weapon_info(
            fullname=self.fullname,
            name=self.name,
            weapon_type=self.type,
            rank=self.rank,
            service=self.service,
            port=self.port,
            platforms=self.platforms,
            cves=self.cves,
            description=self.description,
            authors=self.authors,
            full=full,
        )


@dataclass
class BulletInfo:
    """Lightweight bullet metadata for fast filtering.

    Contains extracted fields from payload names that are commonly
    used for filtering and selection.

    Attributes:
        name: Full payload name (e.g., "linux/x64/meterpreter/reverse_tcp")
        platform: Target platform (linux, windows, cmd, etc.)
        arch: Architecture (x64, x86, cmd, etc.)
        type: Payload type (staged, stageless, single)
        connection: Connection type (reverse, bind, none)
        is_meterpreter: Whether this is a meterpreter payload
        is_shell: Whether this is a basic shell payload
        handler: Handler type (reverse_tcp, reverse_https, etc.)
    """

    name: str
    platform: str
    arch: str
    type: str
    connection: str
    is_meterpreter: bool
    is_shell: bool
    handler: str

    # Reference to parent catalog
    _catalog: Optional["BulletCatalog"] = field(default=None, repr=False)

    def bullet(self) -> "Bullet":
        """Get the full Bullet object.

        Returns:
            Bullet instance
        """
        from assassinate.weapon import Bullet
        return Bullet(self.name)

    def matches(self, **criteria) -> bool:
        """Check if this bullet matches all criteria."""
        for key, value in criteria.items():
            if not self._match_field(key, value):
                return False
        return True

    def _match_field(self, key: str, value) -> bool:
        """Check if a single field matches."""
        if key == "query":
            return value.lower() in self.name.lower()

        field_value = getattr(self, key, None)
        if field_value is None:
            return value is None

        if isinstance(field_value, str) and isinstance(value, str):
            return field_value.lower() == value.lower()

        return field_value == value

    def __repr__(self) -> str:
        parts = [f"<BulletInfo {self.name}"]
        parts.append(f"({self.type}, {self.connection})")
        if self.is_meterpreter:
            parts.append("meterpreter")
        elif self.is_shell:
            parts.append("shell")
        return " ".join(parts) + ">"

    def __str__(self) -> str:
        return self.name

    def summary(self) -> str:
        """Get a detailed multi-line summary of this bullet.

        Returns:
            Formatted string with full bullet details
        """
        payload_type = "Meterpreter" if self.is_meterpreter else "Shell" if self.is_shell else "Other"

        lines = [
            f"{'═' * 60}",
            f"  {self.name}",
            f"{'═' * 60}",
            f"",
            f"  Platform: {self.platform}    Arch: {self.arch}",
            f"  Type: {self.type}    Connection: {self.connection}",
            f"  Payload Type: {payload_type}",
            f"  Handler: {self.handler}",
            f"{'─' * 60}",
        ]
        return "\n".join(lines)

    def p(self, full: bool = False) -> None:
        """Print rich formatted summary.

        Args:
            full: Reserved for future use (consistency with other classes).
        """
        print_bullet_info(
            name=self.name,
            platform=self.platform,
            arch=self.arch,
            bullet_type=self.type,
            connection=self.connection,
            is_meterpreter=self.is_meterpreter,
            is_shell=self.is_shell,
            handler=self.handler,
            full=full,
        )


class WeaponCatalog:
    """Indexed collection of weapons with filtering capabilities.

    Provides fast filtering over all available weapons without loading
    full module instances until needed.

    Example:
        >>> # Filter by multiple criteria
        >>> results = catalog.filter(
        ...     type="exploit",
        ...     service="smb",
        ...     platform="linux",
        ...     min_rank="good"
        ... )

        >>> # Chain filters
        >>> linux_smb = catalog.filter(platform="linux").filter(service="smb")

        >>> # Iterate all weapons
        >>> for info in catalog:
        ...     print(f"{info.name}: {info.service}")

        >>> # Get weapon object
        >>> weapon = results[0].weapon()
    """

    def __init__(self, arsenal: "Arsenal"):
        """Initialize weapon catalog.

        Args:
            arsenal: Parent Arsenal instance
        """
        self._arsenal = arsenal
        self._entries: List[WeaponInfo] = []
        self._loaded = False
        self._weapon_cache: Dict[str, "Weapon"] = {}

    def _ensure_loaded(self) -> None:
        """Lazily load weapon index on first access."""
        if self._loaded:
            return

        import msf

        # Load all module types
        for mod_type in ["exploit", "auxiliary", "post", "evasion"]:
            try:
                module_names = msf.list_modules(mod_type)
                for name in module_names:
                    try:
                        info = self._create_info(name, mod_type)
                        if info:
                            self._entries.append(info)
                    except Exception:
                        # Skip modules that fail to load
                        continue
            except Exception:
                continue

        self._loaded = True

    def _create_info(self, fullname: str, mod_type: str) -> Optional[WeaponInfo]:
        """Create WeaponInfo from module name."""
        import msf

        try:
            # Get module info without fully loading
            raw_info = msf.get_module_info(fullname)

            # Extract name from path
            name = fullname.split("/")[-1]

            # Extract rank
            rank = raw_info.get("rank", "normal")
            rank_scores = {
                "excellent": 600, "great": 500, "good": 400,
                "normal": 300, "average": 200, "low": 100, "manual": 0,
            }
            rank_score = rank_scores.get(rank.lower(), 300)

            # Extract platforms
            platforms = raw_info.get("platform", [])
            if isinstance(platforms, str):
                platforms = [platforms]

            # Infer service from path
            service = self._infer_service(fullname)

            # Extract port from default options
            port = None
            if "default_options" in raw_info:
                rport = raw_info["default_options"].get("RPORT")
                if rport:
                    try:
                        port = int(rport)
                    except (ValueError, TypeError):
                        pass

            # Extract CVEs from references
            cves = []
            refs = raw_info.get("references", [])
            for ref in refs:
                if isinstance(ref, str):
                    matches = re.findall(r'CVE-\d{4}-\d+', ref, re.IGNORECASE)
                    cves.extend(matches)

            # Get description (first sentence)
            desc = raw_info.get("description", "")
            if desc:
                # Truncate to first sentence
                for end in [". ", ".\n", "!"]:
                    idx = desc.find(end)
                    if idx != -1:
                        desc = desc[:idx + 1]
                        break
                if len(desc) > 100:
                    desc = desc[:97] + "..."

            # Get authors
            authors = raw_info.get("author", [])
            if isinstance(authors, str):
                authors = [authors]

            return WeaponInfo(
                fullname=fullname,
                name=name,
                type=mod_type,
                rank=rank,
                rank_score=rank_score,
                platforms=platforms,
                service=service,
                port=port,
                cves=list(set(cves)),
                description=desc,
                authors=authors[:5],  # Limit authors
                _catalog=self,
            )
        except Exception:
            return None

    def _infer_service(self, fullname: str) -> Optional[str]:
        """Infer service from module path."""
        service_hints = {
            "smb": "smb", "samba": "smb", "cifs": "smb",
            "ftp": "ftp", "vsftpd": "ftp", "proftpd": "ftp",
            "http": "http", "apache": "http", "nginx": "http", "tomcat": "http",
            "https": "https",
            "ssh": "ssh", "openssh": "ssh",
            "mysql": "mysql", "mariadb": "mysql",
            "postgres": "postgresql", "postgresql": "postgresql",
            "telnet": "telnet",
            "smtp": "smtp", "sendmail": "smtp", "postfix": "smtp",
            "imap": "imap",
            "pop3": "pop3",
            "dns": "dns", "bind": "dns",
            "ldap": "ldap",
            "rdp": "rdp", "remote_desktop": "rdp",
            "vnc": "vnc",
            "redis": "redis",
            "mongodb": "mongodb",
            "docker": "docker",
        }

        path_lower = fullname.lower()
        for hint, service in service_hints.items():
            if hint in path_lower:
                return service
        return None

    def _get_weapon(self, fullname: str) -> "Weapon":
        """Get or create a Weapon instance."""
        if fullname not in self._weapon_cache:
            from assassinate.weapon import Weapon
            import msf
            self._weapon_cache[fullname] = Weapon(msf.create_module(fullname))
        return self._weapon_cache[fullname]

    def filter(self, **criteria) -> "WeaponCatalog":
        """Filter weapons by criteria.

        Args:
            **criteria: Field names and values to match
                - type: Module type (exploit, auxiliary, post, evasion)
                - service: Target service (smb, ftp, http, etc.)
                - platform: Target platform (linux, windows, etc.)
                - port: Target port number
                - rank: Exact rank match
                - min_rank: Minimum rank (excellent, great, good, etc.)
                - has_cve: Whether CVE is present (True/False)
                - query: Fuzzy text search in name/description/CVEs

        Returns:
            New WeaponCatalog with filtered entries

        Example:
            >>> smb_exploits = catalog.filter(type="exploit", service="smb")
            >>> good_ones = smb_exploits.filter(min_rank="good")
        """
        self._ensure_loaded()

        filtered = WeaponCatalog(self._arsenal)
        filtered._loaded = True
        filtered._weapon_cache = self._weapon_cache
        filtered._entries = [e for e in self._entries if e.matches(**criteria)]
        return filtered

    def search(self, query: str) -> "WeaponCatalog":
        """Fuzzy text search.

        Args:
            query: Search term to match against name, description, CVEs

        Returns:
            New WeaponCatalog with matching entries
        """
        return self.filter(query=query)

    def by_service(self, service: str) -> "WeaponCatalog":
        """Filter by target service.

        Args:
            service: Service name (smb, ftp, http, etc.)

        Returns:
            Filtered catalog
        """
        return self.filter(service=service)

    def by_platform(self, platform: str) -> "WeaponCatalog":
        """Filter by target platform.

        Args:
            platform: Platform name (linux, windows, etc.)

        Returns:
            Filtered catalog
        """
        return self.filter(platform=platform)

    def exploits(self) -> "WeaponCatalog":
        """Get only exploit modules."""
        return self.filter(type="exploit")

    def auxiliary(self) -> "WeaponCatalog":
        """Get only auxiliary modules."""
        return self.filter(type="auxiliary")

    def post(self) -> "WeaponCatalog":
        """Get only post modules."""
        return self.filter(type="post")

    def sorted_by_rank(self, descending: bool = True) -> "WeaponCatalog":
        """Sort by rank score.

        Args:
            descending: Highest rank first (default True)

        Returns:
            Sorted catalog
        """
        self._ensure_loaded()

        sorted_cat = WeaponCatalog(self._arsenal)
        sorted_cat._loaded = True
        sorted_cat._weapon_cache = self._weapon_cache
        sorted_cat._entries = sorted(
            self._entries,
            key=lambda e: e.rank_score,
            reverse=descending
        )
        return sorted_cat

    def limit(self, n: int) -> "WeaponCatalog":
        """Limit results to first N entries.

        Args:
            n: Maximum entries to return

        Returns:
            Limited catalog
        """
        self._ensure_loaded()

        limited = WeaponCatalog(self._arsenal)
        limited._loaded = True
        limited._weapon_cache = self._weapon_cache
        limited._entries = self._entries[:n]
        return limited

    def all(self) -> List[WeaponInfo]:
        """Get all entries as a list."""
        self._ensure_loaded()
        return list(self._entries)

    def first(self) -> Optional[WeaponInfo]:
        """Get the first entry or None."""
        self._ensure_loaded()
        return self._entries[0] if self._entries else None

    def count(self) -> int:
        """Count matching entries."""
        self._ensure_loaded()
        return len(self._entries)

    def __iter__(self) -> Iterator[WeaponInfo]:
        """Iterate over weapon info entries."""
        self._ensure_loaded()
        return iter(self._entries)

    def __len__(self) -> int:
        """Number of entries."""
        self._ensure_loaded()
        return len(self._entries)

    def __getitem__(self, index: Union[int, slice]) -> Union[WeaponInfo, List[WeaponInfo]]:
        """Get entry by index or slice."""
        self._ensure_loaded()
        return self._entries[index]

    def __bool__(self) -> bool:
        """True if catalog has entries."""
        self._ensure_loaded()
        return len(self._entries) > 0

    def __repr__(self) -> str:
        if not self._loaded:
            return "<WeaponCatalog (not loaded)>"
        return f"<WeaponCatalog: {len(self._entries)} weapons>"


class BulletCatalog:
    """Indexed collection of bullets (payloads) with filtering capabilities.

    Provides fast filtering over all available payloads.

    Example:
        >>> # Filter meterpreter bullets for Linux
        >>> results = catalog.filter(
        ...     platform="linux",
        ...     is_meterpreter=True,
        ...     connection="reverse"
        ... )

        >>> # Get bullet object
        >>> bullet = results[0].bullet()
    """

    def __init__(self):
        """Initialize bullet catalog."""
        self._entries: List[BulletInfo] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        """Lazily load bullet index."""
        if self._loaded:
            return

        import msf

        try:
            payload_names = msf.list_modules("payload")
            for name in payload_names:
                info = self._create_info(name)
                if info:
                    self._entries.append(info)
        except Exception:
            pass

        self._loaded = True

    def _create_info(self, name: str) -> BulletInfo:
        """Create BulletInfo from payload name."""
        from assassinate.weapon import Bullet
        b = Bullet(name)

        return BulletInfo(
            name=name,
            platform=b.platform,
            arch=b.arch,
            type=b.type,
            connection=b.connection,
            is_meterpreter=b.is_meterpreter,
            is_shell=b.is_shell,
            handler=b.handler_type,
            _catalog=self,
        )

    def filter(self, **criteria) -> "BulletCatalog":
        """Filter bullets by criteria.

        Args:
            **criteria: Field names and values to match
                - platform: Target platform (linux, windows, cmd, etc.)
                - arch: Architecture (x64, x86, etc.)
                - type: Payload type (staged, stageless, single)
                - connection: Connection type (reverse, bind, none)
                - is_meterpreter: True/False
                - is_shell: True/False
                - handler: Handler type (reverse_tcp, etc.)
                - query: Fuzzy text search

        Returns:
            New BulletCatalog with filtered entries
        """
        self._ensure_loaded()

        filtered = BulletCatalog()
        filtered._loaded = True
        filtered._entries = [e for e in self._entries if e.matches(**criteria)]
        return filtered

    def search(self, query: str) -> "BulletCatalog":
        """Fuzzy text search."""
        return self.filter(query=query)

    def meterpreter(self) -> "BulletCatalog":
        """Get only meterpreter payloads."""
        return self.filter(is_meterpreter=True)

    def shells(self) -> "BulletCatalog":
        """Get only shell payloads."""
        return self.filter(is_shell=True)

    def reverse(self) -> "BulletCatalog":
        """Get only reverse connection payloads."""
        return self.filter(connection="reverse")

    def bind(self) -> "BulletCatalog":
        """Get only bind payloads."""
        return self.filter(connection="bind")

    def for_platform(self, platform: str) -> "BulletCatalog":
        """Filter by platform."""
        return self.filter(platform=platform)

    def for_arch(self, arch: str) -> "BulletCatalog":
        """Filter by architecture."""
        return self.filter(arch=arch)

    def staged(self) -> "BulletCatalog":
        """Get only staged payloads."""
        return self.filter(type="staged")

    def stageless(self) -> "BulletCatalog":
        """Get only stageless payloads."""
        return self.filter(type="stageless")

    def limit(self, n: int) -> "BulletCatalog":
        """Limit results."""
        self._ensure_loaded()

        limited = BulletCatalog()
        limited._loaded = True
        limited._entries = self._entries[:n]
        return limited

    def all(self) -> List[BulletInfo]:
        """Get all entries as list."""
        self._ensure_loaded()
        return list(self._entries)

    def first(self) -> Optional[BulletInfo]:
        """Get first entry or None."""
        self._ensure_loaded()
        return self._entries[0] if self._entries else None

    def count(self) -> int:
        """Count entries."""
        self._ensure_loaded()
        return len(self._entries)

    def __iter__(self) -> Iterator[BulletInfo]:
        """Iterate over bullet info entries."""
        self._ensure_loaded()
        return iter(self._entries)

    def __len__(self) -> int:
        """Number of entries."""
        self._ensure_loaded()
        return len(self._entries)

    def __getitem__(self, index: Union[int, slice]) -> Union[BulletInfo, List[BulletInfo]]:
        """Get entry by index or slice."""
        self._ensure_loaded()
        return self._entries[index]

    def __bool__(self) -> bool:
        """True if catalog has entries."""
        self._ensure_loaded()
        return len(self._entries) > 0

    def __repr__(self) -> str:
        if not self._loaded:
            return "<BulletCatalog (not loaded)>"
        return f"<BulletCatalog: {len(self._entries)} bullets>"
