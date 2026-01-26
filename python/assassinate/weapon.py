"""Weapon and Bullet modules - the tools of the trade.

Weapon wraps MSF modules with a user-friendly, discovery-focused interface.
Bullet represents shellcode/stagers (ammunition) that can be loaded into weapons.

Example:
    >>> weapon = Weapon(msf_module)
    >>> print(weapon.name)           # "is_known_pipename"
    >>> print(weapon.service)        # "smb"
    >>> print(weapon.rank)           # "excellent"
    >>> print(weapon.describe())     # Full formatted description

    >>> # Get compatible ammunition
    >>> bullets = weapon.bullets()
    >>> for b in bullets[:3]:
    ...     print(f"{b.name} - {b.type}/{b.arch}")

    >>> # Load a specific bullet
    >>> weapon.load(weapon.bullet("meterpreter/reverse_tcp"))
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from assassinate.log_config import get_logger

if TYPE_CHECKING:
    import msf

logger = get_logger("weapon")


class Bullet:
    """A bullet (shellcode/stager) - ammunition for a weapon.

    Parses payload names to extract metadata about type, architecture,
    platform, and connection type.

    Bullet naming convention (follows MSF payload paths):
        <platform>/<arch>/<type>[/<connection>]
        Examples:
        - linux/x64/meterpreter/reverse_tcp
        - windows/meterpreter/reverse_https
        - cmd/unix/interact

    Attributes:
        name: Full payload name
        weapon: Optional Weapon this bullet is loaded into

    Example:
        >>> bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        >>> print(bullet.platform)    # "linux"
        >>> print(bullet.arch)        # "x64"
        >>> print(bullet.type)        # "staged"
        >>> print(bullet.connection)  # "reverse_tcp"
    """

    __slots__ = ("name", "_weapon")

    def __init__(self, name: str, weapon: Optional["Weapon"] = None):
        """Initialize a bullet.

        Args:
            name: Full payload name (e.g., "linux/x64/meterpreter/reverse_tcp")
            weapon: Optional Weapon this bullet is for
        """
        self.name = name
        self._weapon = weapon

    @property
    def platform(self) -> str:
        """Target platform (linux, windows, osx, cmd, etc.)."""
        parts = self.name.split("/")
        if parts:
            return parts[0]
        return "unknown"

    @property
    def arch(self) -> str:
        """Target architecture (x86, x64, cmd, etc.)."""
        parts = self.name.split("/")

        # Check for explicit arch in path
        known_archs = {"x86", "x64", "x86_64", "armle", "aarch64", "mipsle", "mipsbe"}
        for part in parts[1:]:
            if part in known_archs:
                return part

        # cmd payloads don't have traditional arch
        if parts[0] == "cmd":
            return "cmd"

        # Default to x86 for Windows/Linux without explicit arch
        if len(parts) >= 2 and parts[1] in ("meterpreter", "shell", "shell_reverse_tcp"):
            return "x86"

        return "native"

    @property
    def type(self) -> str:
        """Bullet type: staged, stageless, or single."""
        name_lower = self.name.lower()

        # Meterpreter with underscore (meterpreter_reverse_tcp) = stageless
        # Meterpreter with slash (meterpreter/reverse_tcp) = staged
        if "meterpreter_" in name_lower or "shell_reverse" in name_lower:
            return "stageless"
        if "/meterpreter/" in name_lower or "/shell/" in name_lower:
            return "staged"

        # Single payloads (interact, exec, etc.)
        if "interact" in name_lower or "/exec" in name_lower:
            return "single"

        # Default based on structure
        parts = self.name.split("/")
        if len(parts) >= 4:
            return "staged"
        return "single"

    @property
    def connection(self) -> str:
        """Connection type: reverse, bind, or none."""
        name_lower = self.name.lower()

        if "reverse" in name_lower:
            return "reverse"
        if "bind" in name_lower:
            return "bind"
        if "interact" in name_lower:
            return "none"

        return "unknown"

    @property
    def handler_type(self) -> str:
        """Get the specific handler type (reverse_tcp, reverse_https, etc.)."""
        name_lower = self.name.lower()

        # Extract connection type from end of name
        handlers = [
            "reverse_tcp", "reverse_https", "reverse_http",
            "bind_tcp", "bind_named_pipe",
            "reverse_tcp_uuid", "reverse_https_uuid",
        ]
        for h in handlers:
            if h in name_lower:
                return h

        if "interact" in name_lower:
            return "interact"

        return "unknown"

    @property
    def is_meterpreter(self) -> bool:
        """Whether this is a meterpreter payload."""
        return "meterpreter" in self.name.lower()

    @property
    def is_shell(self) -> bool:
        """Whether this is a shell payload (not meterpreter)."""
        name_lower = self.name.lower()
        return "shell" in name_lower and "meterpreter" not in name_lower

    def describe(self) -> str:
        """Get a formatted description of the bullet.

        Returns:
            Multi-line string with bullet details
        """
        lines = [
            f"Bullet: {self.name}",
            f"  Platform: {self.platform}",
            f"  Arch: {self.arch}",
            f"  Type: {self.type}",
            f"  Connection: {self.connection}",
        ]

        if self.is_meterpreter:
            lines.append("  Features: Meterpreter (full featured)")
        elif self.is_shell:
            lines.append("  Features: Basic shell")

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<Bullet {self.name}>"

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Bullet):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return False

    def __hash__(self) -> int:
        return hash(self.name)


class Weapon:
    """A weapon from the arsenal (MSF module wrapper).

    Provides a user-friendly interface to MSF modules with focus on
    discovery and self-description.

    Attributes:
        name: Short weapon name (e.g., "is_known_pipename")
        fullname: Full module path
        type: Module type (exploit, auxiliary, etc.)

    Example:
        >>> weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
        >>> print(weapon.describe())  # Full description
        >>> weapon.configure(RHOSTS="192.168.1.100", SMB_SHARE_NAME="data")
        >>> print(weapon.payloads())  # Compatible payloads
    """

    __slots__ = ("_module", "_cached_bullets", "_loaded_bullet")

    def __init__(self, msf_module: "msf.AnyModule"):
        """Initialize a weapon from an MSF module.

        Args:
            msf_module: The underlying MSF module instance
        """
        self._module = msf_module
        self._cached_bullets: Optional[List[Bullet]] = None
        self._loaded_bullet: Optional[Bullet] = None
        logger.debug(f"Weapon initialized: {msf_module.fullname}")

    # =========================================================================
    # Identity
    # =========================================================================

    @property
    def name(self) -> str:
        """Short weapon name (last component of path)."""
        return self.fullname.split("/")[-1]

    @property
    def fullname(self) -> str:
        """Full module path (e.g., 'exploit/linux/samba/is_known_pipename')."""
        return self._module.fullname

    @property
    def type(self) -> str:
        """Module type (exploit, auxiliary, post, etc.)."""
        return self._module.module_type

    @property
    def category(self) -> str:
        """Module category (second path component, e.g., 'linux' or 'scanner')."""
        parts = self.fullname.split("/")
        if len(parts) >= 2:
            return parts[1]
        return ""

    @property
    def subcategory(self) -> str:
        """Module subcategory (third path component, e.g., 'samba' or 'smb')."""
        parts = self.fullname.split("/")
        if len(parts) >= 3:
            return parts[2]
        return ""

    # =========================================================================
    # Description
    # =========================================================================

    @property
    def description(self) -> str:
        """Full module description text."""
        return self._module.description

    @property
    def short_description(self) -> str:
        """First sentence of the description."""
        desc = self.description
        # Find first sentence ending
        for end in [". ", ".\n", "!"]:
            idx = desc.find(end)
            if idx != -1:
                return desc[:idx + 1]
        # No sentence ending found, truncate
        if len(desc) > 100:
            return desc[:97] + "..."
        return desc

    @property
    def authors(self) -> List[str]:
        """List of module authors."""
        return self._module.author

    @property
    def references(self) -> List[str]:
        """Security references (CVEs, URLs, etc.)."""
        return self._module.references

    @property
    def cves(self) -> List[str]:
        """Extract CVE identifiers from references."""
        cves = []
        for ref in self.references:
            # References are often formatted as "CVE-YYYY-NNNN" or "[CVE, YYYY-NNNN]"
            matches = re.findall(r'CVE-\d{4}-\d+', ref, re.IGNORECASE)
            cves.extend(matches)
        return list(set(cves))  # Deduplicate

    @property
    def rank(self) -> str:
        """Reliability rank (excellent, great, good, normal, average, low, manual)."""
        return self._module.rank

    @property
    def rank_score(self) -> int:
        """Numeric rank score for sorting (higher is better)."""
        rank_scores = {
            "excellent": 600,
            "great": 500,
            "good": 400,
            "normal": 300,
            "average": 200,
            "low": 100,
            "manual": 0,
        }
        return rank_scores.get(self.rank.lower(), 0)

    # =========================================================================
    # Technical Details
    # =========================================================================

    @property
    def platforms(self) -> List[str]:
        """Target platforms (linux, windows, unix, etc.)."""
        return self._module.platform

    @property
    def architectures(self) -> List[str]:
        """Target architectures (x86, x64, etc.)."""
        return self._module.arch

    @property
    def privileged(self) -> bool:
        """Whether the module requires privileged access."""
        return self._module.privileged

    @property
    def disclosure_date(self) -> Optional[str]:
        """Vulnerability disclosure date."""
        return self._module.disclosure_date

    @property
    def service(self) -> Optional[str]:
        """Target service name inferred from module path or options.

        Returns:
            Service name like 'smb', 'ftp', 'http' or None
        """
        # Common service mappings from module paths
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

        # Check path components
        path_lower = self.fullname.lower()
        for hint, service in service_hints.items():
            if hint in path_lower:
                return service

        return None

    @property
    def port(self) -> Optional[int]:
        """Default target port from RPORT option."""
        try:
            schema = self._module.options.schema()
            if "RPORT" in schema:
                default = schema["RPORT"].get("default")
                if default:
                    return int(default)
        except (ValueError, TypeError, KeyError):
            pass
        return None

    @property
    def targets(self) -> List[str]:
        """Available exploit targets (for exploit modules)."""
        if hasattr(self._module, "targets"):
            return self._module.targets
        return []

    # =========================================================================
    # Configuration
    # =========================================================================

    @property
    def options(self) -> "msf.ModuleOptions":
        """Access module options with attribute-style syntax.

        Example:
            weapon.options.RHOSTS = "192.168.1.100"
            weapon.options.RPORT = 445
        """
        return self._module.options

    def configure(self, **kwargs) -> "Weapon":
        """Configure multiple options at once.

        Args:
            **kwargs: Option names and values

        Returns:
            self for method chaining

        Example:
            weapon.configure(
                RHOSTS="192.168.1.100",
                SMB_SHARE_NAME="data",
                TARGET=0
            )
        """
        logger.debug(f"Configuring weapon {self.name} with {len(kwargs)} options")
        for key, value in kwargs.items():
            self._module.options[key] = value
        return self

    def validate(self) -> bool:
        """Validate that all required options are set."""
        return self._module.validate()

    def missing_options(self) -> List[str]:
        """Get list of required options that aren't set."""
        return self._module.options.missing_required()

    # =========================================================================
    # Bullets (Ammunition)
    # =========================================================================

    def bullets(self, refresh: bool = False) -> List[Bullet]:
        """Get compatible bullets (payloads) for this weapon.

        Args:
            refresh: Force refresh of cached bullets

        Returns:
            List of compatible Bullet objects
        """
        if self._cached_bullets is None or refresh:
            logger.debug(f"Fetching compatible bullets for {self.name}")
            if hasattr(self._module, "compatible_payloads"):
                names = self._module.compatible_payloads()
                self._cached_bullets = [Bullet(name, self) for name in names]
                logger.debug(f"Found {len(self._cached_bullets)} compatible bullets")
            else:
                self._cached_bullets = []
        return self._cached_bullets

    def bullet(self, query: str) -> Optional[Bullet]:
        """Find a specific bullet by name fragment.

        Args:
            query: Bullet name fragment (case-insensitive)

        Returns:
            First matching Bullet or None

        Example:
            >>> weapon.bullet("meterpreter/reverse_tcp")
            <Bullet linux/x64/meterpreter/reverse_tcp>
        """
        query_lower = query.lower()
        for b in self.bullets():
            if query_lower in b.name.lower():
                return b
        return None

    def best_bullet(
        self,
        prefer_meterpreter: bool = True,
        prefer_staged: bool = True,
    ) -> Optional[Bullet]:
        """Auto-select the best bullet for this weapon.

        Args:
            prefer_meterpreter: Prefer meterpreter over shell
            prefer_staged: Prefer staged over stageless

        Returns:
            Best matching Bullet or None
        """
        compatible = self.bullets()
        if not compatible:
            return None

        # Score bullets
        def score(b: Bullet) -> int:
            s = 0
            if prefer_meterpreter and b.is_meterpreter:
                s += 100
            if prefer_staged and b.type == "staged":
                s += 50
            if b.connection == "reverse":
                s += 25  # Reverse connections are usually more reliable
            if "tcp" in b.name.lower():
                s += 10  # TCP is usually more reliable than HTTP
            return s

        return max(compatible, key=score)

    def load(self, bullet: Union[Bullet, str]) -> "Weapon":
        """Load a bullet into the weapon.

        Args:
            bullet: Bullet object or payload name string

        Returns:
            self for method chaining

        Example:
            >>> weapon.load("cmd/unix/interact")
            >>> weapon.load(weapon.best_bullet())
        """
        if isinstance(bullet, str):
            # Find the bullet by name
            found = self.bullet(bullet)
            if found:
                self._loaded_bullet = found
                logger.debug(f"Loaded bullet: {found.name}")
            else:
                # Create a new Bullet from the string
                self._loaded_bullet = Bullet(bullet, self)
                logger.debug(f"Created and loaded bullet: {bullet}")
        else:
            self._loaded_bullet = bullet
            logger.debug(f"Loaded bullet: {bullet.name}")
        return self

    @property
    def loaded(self) -> Optional[Bullet]:
        """Get the currently loaded bullet."""
        return self._loaded_bullet

    @property
    def is_loaded(self) -> bool:
        """Check if a bullet is loaded."""
        return self._loaded_bullet is not None

    # =========================================================================
    # Vulnerability Check
    # =========================================================================

    def has_check(self) -> bool:
        """Whether this weapon supports vulnerability checking."""
        if hasattr(self._module, "has_check"):
            return self._module.has_check()
        return False

    def check(self) -> str:
        """Run vulnerability check against configured target.

        Returns:
            Check result string (e.g., "The target is vulnerable.")

        Raises:
            AttributeError: If module doesn't support checking
        """
        logger.info(f"Running vulnerability check with {self.name}")
        if hasattr(self._module, "check"):
            try:
                result = self._module.check()
                logger.info(f"Check result: {result}")
                return result
            except Exception as e:
                logger.error(f"Check failed for {self.name}: {e}")
                raise
        logger.warning(f"{self.name} does not support vulnerability checking")
        raise AttributeError(f"{self.name} does not support vulnerability checking")

    # =========================================================================
    # Display
    # =========================================================================

    def describe(self) -> str:
        """Get a comprehensive, formatted description.

        Returns:
            Multi-line string with full weapon details
        """
        lines = [
            f"{'=' * 60}",
            f"  {self.fullname}",
            f"{'=' * 60}",
            "",
            f"Name: {self.name}",
            f"Type: {self.type.capitalize()}",
            f"Rank: {self.rank.capitalize()}",
        ]

        if self.platforms:
            lines.append(f"Platforms: {', '.join(self.platforms)}")
        if self.architectures:
            lines.append(f"Architectures: {', '.join(self.architectures)}")
        if self.service:
            lines.append(f"Service: {self.service}")
        if self.port:
            lines.append(f"Default Port: {self.port}")
        if self.disclosure_date:
            lines.append(f"Disclosed: {self.disclosure_date}")

        lines.extend(["", "Description:"])
        # Wrap description
        desc = self.description
        for line in desc.split("\n"):
            if line.strip():
                lines.append(f"  {line.strip()}")

        if self.cves:
            lines.extend(["", f"CVEs: {', '.join(self.cves)}"])

        if self.authors:
            lines.extend(["", f"Authors: {', '.join(self.authors[:3])}"])
            if len(self.authors) > 3:
                lines.append(f"  ... and {len(self.authors) - 3} more")

        if self.references:
            lines.extend(["", "References:"])
            for ref in self.references[:5]:
                lines.append(f"  - {ref}")
            if len(self.references) > 5:
                lines.append(f"  ... and {len(self.references) - 5} more")

        if self.targets:
            lines.extend(["", "Targets:"])
            for i, target in enumerate(self.targets[:5]):
                lines.append(f"  {i}: {target}")
            if len(self.targets) > 5:
                lines.append(f"  ... and {len(self.targets) - 5} more")

        # Show current configuration
        missing = self.missing_options()
        if missing:
            lines.extend(["", "Required Options (not set):"])
            for opt in missing:
                lines.append(f"  * {opt}")

        lines.append("")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<Weapon {self.name} ({self.type}, {self.rank})>"

    def __str__(self) -> str:
        return f"{self.fullname} - {self.short_description}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Weapon):
            return self.fullname == other.fullname
        if isinstance(other, str):
            return self.fullname == other or self.name == other
        return False

    def __hash__(self) -> int:
        return hash(self.fullname)
