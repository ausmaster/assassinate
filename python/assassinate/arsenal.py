"""Arsenal module - the weapon armory with smart search capabilities.

The Arsenal provides intelligent search and filtering of MSF modules,
making it easy to find the right weapon for the job.

Example:
    >>> arsenal = hideout.arsenal

    >>> # NEW: Catalog-based filtering (recommended)
    >>> smb_exploits = arsenal.weapons.filter(service="smb", type="exploit")
    >>> for w in smb_exploits:
    ...     print(f"{w.name} ({w.rank}) - {w.description}")
    >>> weapon = smb_exploits[0].weapon()  # Get full Weapon object

    >>> # Filter bullets
    >>> linux_meterpreter = arsenal.bullets.filter(
    ...     platform="linux",
    ...     is_meterpreter=True
    ... )

    >>> # Legacy search (still supported)
    >>> weapons = arsenal.find("samba", type="exploit", rank="excellent")

    >>> # Find by CVE
    >>> weapons = arsenal.find("CVE-2017-7494")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Dict

import msf
from assassinate.weapon import Weapon
from assassinate.catalog import WeaponCatalog, BulletCatalog

if TYPE_CHECKING:
    from assassinate.hideout import Hideout


class Arsenal:
    """The weapon arsenal - search and discover available weapons.

    Provides intelligent search and filtering across all MSF modules.
    Results are returned as Weapon objects for easy inspection.

    Attributes:
        hideout: Parent Hideout instance
        weapons: WeaponCatalog for filtering weapons
        bullets: BulletCatalog for filtering payloads

    Example:
        >>> # NEW: Catalog-based filtering (recommended)
        >>> smb_exploits = arsenal.weapons.filter(
        ...     type="exploit",
        ...     service="smb",
        ...     min_rank="good"
        ... )
        >>> for info in smb_exploits[:5]:
        ...     print(f"{info.name} ({info.rank})")
        >>> weapon = smb_exploits[0].weapon()  # Get full Weapon

        >>> # Filter bullets
        >>> meterpreter = arsenal.bullets.meterpreter().reverse()
        >>> for b in meterpreter.for_platform("linux")[:5]:
        ...     print(b.name)

        >>> # Legacy methods still work
        >>> weapons = arsenal.find("smb", type="exploit")
        >>> weapon = arsenal.get("exploit/linux/samba/is_known_pipename")
    """

    def __init__(self, hideout: "Hideout"):
        """Initialize arsenal with a hideout reference.

        Args:
            hideout: Parent Hideout instance for MSF access
        """
        self._hideout = hideout
        self._counts_cache: Optional[Dict[str, int]] = None
        self._weapons_catalog: Optional[WeaponCatalog] = None
        self._bullets_catalog: Optional[BulletCatalog] = None

    # =========================================================================
    # Catalog Access (New API)
    # =========================================================================

    @property
    def weapons(self) -> WeaponCatalog:
        """Access the weapon catalog for filtering.

        Returns:
            WeaponCatalog with chainable filter methods

        Example:
            >>> # Filter by multiple criteria
            >>> results = arsenal.weapons.filter(
            ...     type="exploit",
            ...     service="smb",
            ...     platform="linux"
            ... )

            >>> # Chain filters
            >>> good_smb = arsenal.weapons.exploits().by_service("smb").filter(min_rank="good")

            >>> # Get weapon object from result
            >>> weapon = results[0].weapon()
        """
        if self._weapons_catalog is None:
            self._weapons_catalog = WeaponCatalog(self)
        return self._weapons_catalog

    @property
    def bullets(self) -> BulletCatalog:
        """Access the bullet catalog for filtering.

        Returns:
            BulletCatalog with chainable filter methods

        Example:
            >>> # Filter meterpreter bullets
            >>> results = arsenal.bullets.filter(
            ...     platform="linux",
            ...     is_meterpreter=True,
            ...     connection="reverse"
            ... )

            >>> # Use convenience methods
            >>> linux_meterpreter = arsenal.bullets.meterpreter().for_platform("linux")

            >>> # Get bullet object
            >>> bullet = results[0].bullet()
        """
        if self._bullets_catalog is None:
            self._bullets_catalog = BulletCatalog()
        return self._bullets_catalog

    # =========================================================================
    # Smart Search
    # =========================================================================

    def find(
        self,
        query: Optional[str] = None,
        *,
        service: Optional[str] = None,
        platform: Optional[str] = None,
        type: Optional[str] = None,  # noqa: A002 - intentional shadowing
        port: Optional[int] = None,
        rank: Optional[str] = None,
        limit: int = 20,
    ) -> List[Weapon]:
        """Find weapons matching criteria.

        All criteria are combined with AND logic. Results are sorted by
        rank (highest first) and limited.

        Args:
            query: Fuzzy search term (matches name, description, CVE)
            service: Filter by target service (smb, ftp, http, etc.)
            platform: Filter by target platform (linux, windows, etc.)
            type: Filter by module type (exploit, auxiliary, post, etc.)
            port: Filter by default port
            rank: Minimum rank (excellent, great, good, normal, average, low)
            limit: Maximum results to return (default 20, 0 for unlimited)

        Returns:
            List of matching Weapon objects, sorted by rank

        Example:
            >>> # Find SambaCry-like exploits
            >>> weapons = arsenal.find("samba", type="exploit", rank="good")

            >>> # Find Windows SMB exploits
            >>> weapons = arsenal.find(service="smb", platform="windows")

            >>> # Find by CVE
            >>> weapons = arsenal.find("CVE-2017-7494")
        """
        # Build MSF search query
        search_terms = []
        if query:
            search_terms.append(query)
        if type:
            search_terms.append(f"type:{type}")
        if platform:
            search_terms.append(f"platform:{platform}")

        # Get initial results from MSF search
        if search_terms:
            search_query = " ".join(search_terms)
            module_names = msf.search(search_query)
        else:
            # No query, get all modules (expensive!)
            module_names = []
            for mod_type in ["exploit", "auxiliary", "post", "payload", "evasion"]:
                module_names.extend(msf.list_modules(mod_type))

        # Convert to Weapons and apply additional filters
        weapons: List[Weapon] = []
        rank_scores = {
            "excellent": 600, "great": 500, "good": 400,
            "normal": 300, "average": 200, "low": 100, "manual": 0,
        }
        min_rank_score = rank_scores.get(rank.lower(), 0) if rank else 0

        for name in module_names:
            try:
                mod = msf.create_module(name)
                weapon = Weapon(mod)

                # Apply additional filters
                if service and weapon.service != service.lower():
                    continue
                if port and weapon.port != port:
                    continue
                if rank and weapon.rank_score < min_rank_score:
                    continue

                weapons.append(weapon)
            except Exception:
                # Skip modules that fail to load
                continue

        # Sort by rank (highest first)
        weapons.sort(key=lambda w: w.rank_score, reverse=True)

        # Apply limit
        if limit > 0:
            weapons = weapons[:limit]

        return weapons

    def get(self, name: str) -> Weapon:
        """Get a specific weapon by name or path.

        Args:
            name: Full module path (e.g., "exploit/linux/samba/is_known_pipename")

        Returns:
            Weapon instance

        Raises:
            ValueError: If module not found

        Example:
            >>> weapon = arsenal.get("exploit/linux/samba/is_known_pipename")
            >>> print(weapon.describe())
        """
        try:
            mod = msf.create_module(name)
            return Weapon(mod)
        except Exception as e:
            raise ValueError(f"Weapon not found: {name}") from e

    # =========================================================================
    # Category Browsing
    # =========================================================================

    def exploits(self, query: Optional[str] = None, limit: int = 20) -> List[Weapon]:
        """Find exploit modules.

        Args:
            query: Optional search query within exploits
            limit: Maximum results (default 20)

        Returns:
            List of exploit Weapons
        """
        return self.find(query, type="exploit", limit=limit)

    def auxiliary(self, query: Optional[str] = None, limit: int = 20) -> List[Weapon]:
        """Find auxiliary modules (scanners, fuzzers, etc.).

        Args:
            query: Optional search query within auxiliary
            limit: Maximum results (default 20)

        Returns:
            List of auxiliary Weapons
        """
        return self.find(query, type="auxiliary", limit=limit)

    def post(self, query: Optional[str] = None, limit: int = 20) -> List[Weapon]:
        """Find post-exploitation modules.

        Args:
            query: Optional search query within post modules
            limit: Maximum results (default 20)

        Returns:
            List of post Weapons
        """
        return self.find(query, type="post", limit=limit)

    def evasion(self, query: Optional[str] = None, limit: int = 20) -> List[Weapon]:
        """Find evasion modules.

        Args:
            query: Optional search query within evasion
            limit: Maximum results (default 20)

        Returns:
            List of evasion Weapons
        """
        return self.find(query, type="evasion", limit=limit)

    # =========================================================================
    # Service-Based Discovery
    # =========================================================================

    def for_service(
        self,
        service: str,
        type: Optional[str] = None,  # noqa: A002
        limit: int = 20,
    ) -> List[Weapon]:
        """Find weapons that target a specific service.

        Args:
            service: Service name (smb, ftp, http, ssh, etc.)
            type: Optional module type filter
            limit: Maximum results

        Returns:
            List of Weapons targeting the service

        Example:
            >>> smb_exploits = arsenal.for_service("smb", type="exploit")
            >>> ftp_scanners = arsenal.for_service("ftp", type="auxiliary")
        """
        return self.find(service=service, type=type, limit=limit)

    def for_port(
        self,
        port: int,
        type: Optional[str] = None,  # noqa: A002
        limit: int = 20,
    ) -> List[Weapon]:
        """Find weapons that target a specific port.

        Args:
            port: Port number
            type: Optional module type filter
            limit: Maximum results

        Returns:
            List of Weapons targeting the port
        """
        return self.find(port=port, type=type, limit=limit)

    def for_platform(
        self,
        platform: str,
        type: Optional[str] = None,  # noqa: A002
        limit: int = 20,
    ) -> List[Weapon]:
        """Find weapons that target a specific platform.

        Args:
            platform: Platform name (linux, windows, osx, etc.)
            type: Optional module type filter
            limit: Maximum results

        Returns:
            List of Weapons for the platform
        """
        return self.find(platform=platform, type=type, limit=limit)

    # =========================================================================
    # Statistics
    # =========================================================================

    def count(self, type: Optional[str] = None) -> int:  # noqa: A002
        """Count available weapons.

        Args:
            type: Optional module type to count (default: all)

        Returns:
            Number of weapons

        Example:
            >>> print(f"Total: {arsenal.count()}")
            >>> print(f"Exploits: {arsenal.count('exploit')}")
        """
        if self._counts_cache is None:
            self._counts_cache = {}
            for mod_type in ["exploit", "auxiliary", "post", "payload", "evasion", "encoder", "nop"]:
                try:
                    self._counts_cache[mod_type] = len(msf.list_modules(mod_type))
                except Exception:
                    self._counts_cache[mod_type] = 0

        if type:
            return self._counts_cache.get(type.lower(), 0)
        return sum(self._counts_cache.values())

    def stats(self) -> Dict[str, int]:
        """Get weapon count by type.

        Returns:
            Dict mapping type to count

        Example:
            >>> stats = arsenal.stats()
            >>> for type, count in stats.items():
            ...     print(f"{type}: {count}")
        """
        # Ensure cache is populated
        self.count()
        return self._counts_cache.copy() if self._counts_cache else {}

    # =========================================================================
    # Display
    # =========================================================================

    def __repr__(self) -> str:
        stats = self.stats()
        parts = [f"{stats.get('exploit', 0)} exploits"]
        if stats.get("auxiliary"):
            parts.append(f"{stats['auxiliary']} auxiliary")
        if stats.get("post"):
            parts.append(f"{stats['post']} post")
        return f"<Arsenal: {', '.join(parts)}>"
