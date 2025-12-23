"""Hideout preparation module for pre-mission environment reconnaissance.

Before any operation, the hideout must be secured and all equipment verified.
This module performs reconnaissance checks on:
- Arsenal (Rust compiled artifacts)
- Armory (Rust toolchain + Cap'n Proto)
- Safehouse (MSF installation)
- Contacts (Ruby environment)

For installation/setup, use: assassinate-setup
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from os import environ
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired, run
from typing import Callable

from assassinate.log_config import get_logger

logger = get_logger("prep")

# Known safehouse locations (MSF installation paths)
KNOWN_SAFEHOUSES = [
    Path("/opt/metasploit-framework"),
    Path("/opt/metasploit-framework/embedded/framework"),
    Path("/usr/share/metasploit-framework"),
]

# Remedy command for all setup issues
SETUP_REMEDY = "Run: assassinate-setup --help"


@dataclass
class Requirement:
    """A requirement that must be met for hideout operations.

    Attributes:
        name: Codename for this requirement
        met: Whether the requirement is satisfied
        status: Intel on current status
        details: Additional reconnaissance details
        remedy: How to resolve if requirement is not met
    """

    name: str
    met: bool
    status: str
    details: str = ""
    remedy: str = SETUP_REMEDY


@dataclass
class PrepReport:
    """Hideout preparation reconnaissance report.

    Attributes:
        requirements: List of all verified requirements
    """

    requirements: list[Requirement] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        """Check if hideout is operational."""
        return all(req.met for req in self.requirements)

    @property
    def compromised(self) -> list[Requirement]:
        """Get list of unmet requirements (compromised elements)."""
        return [req for req in self.requirements if not req.met]

    def summary(self) -> str:
        """Generate reconnaissance summary."""
        lines = [
            "╔══════════════════════════════════════════════════╗",
            "║         HIDEOUT RECONNAISSANCE REPORT            ║",
            "╚══════════════════════════════════════════════════╝",
            "",
        ]

        for req in self.requirements:
            icon = "✓" if req.met else "✗"
            state = "SECURED" if req.met else "COMPROMISED"
            lines.append(f"[{icon} {state}] {req.name}")
            lines.append(f"          {req.status}")
            if req.details:
                lines.append(f"          Intel: {req.details}")
            if not req.met and req.remedy:
                lines.append(f"          Action: {req.remedy}")
            lines.append("")

        secured = sum(1 for r in self.requirements if r.met)
        total = len(self.requirements)
        lines.append(f"Operational Status: {secured}/{total} assets secured")

        if not self.ready:
            lines.append("")
            lines.append(
                "⚠ HIDEOUT COMPROMISED - Run 'assassinate-setup' to secure"
            )

        return "\n".join(lines)


class HideoutPrep:
    """Hideout preparation and reconnaissance handler.

    Performs reconnaissance to verify all requirements are met:
    - Armory: Rust compiler, Cargo, Cap'n Proto
    - Arsenal: Compiled Rust artifacts (daemon, bridge, ipc)
    - Safehouse: MSF installation location
    - Contacts: Ruby and Bundler availability

    For installation/building, use the assassinate-setup command.

    Attributes:
        project_root: Root directory of operations
        rust_dir: Armory location (Rust crates)
        safehouse: Path to MSF installation
        ruby_cmd: Path to Ruby executable
        bundle_cmd: Path to Bundler executable
        ruby_env: Environment variables for Ruby execution
    """

    # Arsenal manifest - required weapons and their verification
    arsenal: dict[str, Callable[[Path], bool]] = {
        "daemon": lambda d: (d / "daemon").exists(),
        "bridge": lambda d: bool(
            list(d.glob("*.rlib")) or list(d.glob("*.so"))
        ),
        "ipc": lambda d: bool(list(d.glob("*.rlib")) or list(d.glob("*.so"))),
    }

    __slots__ = (
        "project_root",
        "rust_dir",
        "safehouse",
        "ruby_cmd",
        "bundle_cmd",
        "ruby_env",
        "_omnibus_root",
    )

    def __init__(self, project_root: Path | None = None):
        """Initialize hideout reconnaissance.

        Args:
            project_root: Root directory of operations.
                Auto-detected if not provided.
        """
        self.project_root = project_root or self._find_project_root()
        self.rust_dir = self.project_root / "rust"
        self.safehouse = self._locate_safehouse()
        self._omnibus_root: Path | None = None
        self.ruby_cmd, self.bundle_cmd, self.ruby_env = (
            self._identify_contacts()
        )

    @staticmethod
    def _find_project_root() -> Path:
        """Locate operations root by searching for pyproject.toml."""
        try:
            current = Path(__file__).parent
        except NameError:
            current = Path.cwd()

        while current != current.parent:
            if (current / "pyproject.toml").exists():
                return current
            current = current.parent
        raise RuntimeError("Could not locate operations root")

    def _locate_safehouse(self) -> Path:
        """Locate the MSF safehouse (installation directory).

        Checks in order:
        1. MSF_ROOT environment variable
        2. Project-local metasploit-framework directory
        3. Known system installation paths
        """
        # Check environment variable
        msf_root_env = environ.get("MSF_ROOT")
        if msf_root_env:
            path = Path(msf_root_env)
            logger.debug(f"Safehouse from MSF_ROOT: {path}")
            return path

        # Check project-local directory
        local_msf = self.project_root / "metasploit-framework"
        if local_msf.exists() and (local_msf / "Gemfile").exists():
            logger.debug(f"Safehouse (local): {local_msf}")
            return local_msf

        # Scan known locations
        for path in KNOWN_SAFEHOUSES:
            if path.exists() and (path / "Gemfile").exists():
                logger.debug(f"Safehouse (detected): {path}")
                return path

        # Fall back to project-local (even if not present)
        logger.debug(f"Safehouse (fallback): {local_msf}")
        return local_msf

    def _find_omnibus_root(self) -> Path | None:
        """Find omnibus installation root if applicable."""
        if self._omnibus_root is not None:
            return self._omnibus_root

        try:
            msf_path = self.safehouse.resolve()
            # Check if inside embedded/framework
            if len(msf_path.parts) >= 2 and msf_path.parts[-2:] == (
                "embedded",
                "framework",
            ):
                omnibus_root = msf_path.parent.parent
                if (omnibus_root / "embedded" / "bin" / "ruby").exists():
                    self._omnibus_root = omnibus_root
                    return omnibus_root

            # Check common omnibus path
            omnibus_path = Path("/opt/metasploit-framework")
            if (omnibus_path / "embedded" / "bin" / "ruby").exists():
                self._omnibus_root = omnibus_path
                return omnibus_path
        except (OSError, PermissionError):
            pass

        return None

    def _identify_contacts(self) -> tuple[str, str, dict[str, str]]:
        """Identify Ruby contacts (executables) for MSF operations.

        Checks in order:
        1. Omnibus embedded Ruby
        2. rbenv Ruby
        3. System Ruby
        """
        ruby_cmd = "ruby"
        bundle_cmd = "bundle"
        env = environ.copy()

        # Check for omnibus Ruby
        omnibus_root = self._find_omnibus_root()
        if omnibus_root:
            embedded_bin = omnibus_root / "embedded" / "bin"
            omnibus_ruby = embedded_bin / "ruby"
            omnibus_bundle = embedded_bin / "bundle"
            if omnibus_ruby.exists():
                ruby_cmd = str(omnibus_ruby)
                bundle_cmd = (
                    str(omnibus_bundle) if omnibus_bundle.exists() else "bundle"
                )
                # Set library path for omnibus
                embedded_lib = omnibus_root / "embedded" / "lib"
                if embedded_lib.exists():
                    existing = env.get("LD_LIBRARY_PATH", "")
                    env["LD_LIBRARY_PATH"] = (
                        f"{embedded_lib}:{existing}"
                        if existing
                        else str(embedded_lib)
                    )
                logger.debug(f"Using omnibus Ruby: {ruby_cmd}")
                return (ruby_cmd, bundle_cmd, env)

        # Check for rbenv Ruby
        ruby_version_file = self.project_root / ".ruby-version"
        rbenv_root = Path.home() / ".rbenv"

        if ruby_version_file.exists() and rbenv_root.exists():
            try:
                ruby_version = ruby_version_file.read_text().strip()
                rbenv_bin = rbenv_root / "versions" / ruby_version / "bin"
                if rbenv_bin.exists():
                    ruby_cmd = str(rbenv_bin / "ruby")
                    bundle_cmd = str(rbenv_bin / "bundle")
                    logger.debug(f"Using rbenv Ruby {ruby_version}")
                    return (ruby_cmd, bundle_cmd, env)
            except (IOError, OSError) as e:
                logger.warning(f"Cannot read .ruby-version: {e}")

        logger.debug("Using system Ruby")
        return (ruby_cmd, bundle_cmd, env)

    def check(self) -> PrepReport:
        """Perform full hideout reconnaissance.

        Returns:
            PrepReport with status of all requirements.
        """
        logger.info("Initiating hideout reconnaissance...")
        report = PrepReport()

        # Armory checks (build tools)
        report.requirements.append(self._check_rust_compiler())
        report.requirements.append(self._check_cargo())
        report.requirements.append(self._check_capnp())

        # Arsenal check (compiled artifacts)
        report.requirements.append(self._check_arsenal())

        # Safehouse check (MSF)
        report.requirements.append(self._check_safehouse())

        # Contact checks (Ruby environment)
        report.requirements.append(self._check_ruby())
        report.requirements.append(self._check_bundler())

        secured = sum(1 for r in report.requirements if r.met)
        total = len(report.requirements)
        logger.info(f"Reconnaissance complete: {secured}/{total} secured")
        return report

    def _check_rust_compiler(self) -> Requirement:
        """Verify Rust compiler is in the armory."""
        rustc = shutil.which("rustc")
        if not rustc:
            return Requirement(
                name="Rust Compiler",
                met=False,
                status="rustc not found in armory",
                details="Required for building arsenal",
                remedy="Install from https://rustup.rs/",
            )

        try:
            result = run(
                ["rustc", "--version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return Requirement(
                name="Rust Compiler",
                met=True,
                status="rustc secured",
                details=result.stdout.strip(),
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Rust Compiler",
                met=False,
                status="rustc malfunction",
                details=str(e),
            )

    def _check_cargo(self) -> Requirement:
        """Verify Cargo is in the armory."""
        cargo = shutil.which("cargo")
        if not cargo:
            return Requirement(
                name="Cargo",
                met=False,
                status="cargo not found in armory",
                details="Required for building arsenal",
                remedy="Install from https://rustup.rs/",
            )

        try:
            result = run(
                ["cargo", "--version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return Requirement(
                name="Cargo",
                met=True,
                status="cargo secured",
                details=result.stdout.strip(),
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Cargo",
                met=False,
                status="cargo malfunction",
                details=str(e),
            )

    def _check_capnp(self) -> Requirement:
        """Verify Cap'n Proto is in the armory."""
        capnp = shutil.which("capnp")
        if not capnp:
            return Requirement(
                name="Cap'n Proto",
                met=False,
                status="capnp not found in armory",
                details="Required for IPC schema compilation",
                remedy="apt install capnproto or brew install capnp",
            )

        try:
            result = run(
                ["capnp", "--version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            return Requirement(
                name="Cap'n Proto",
                met=True,
                status="capnp secured",
                details=result.stdout.strip(),
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Cap'n Proto",
                met=False,
                status="capnp malfunction",
                details=str(e),
            )

    def _check_arsenal(self) -> Requirement:
        """Verify arsenal (compiled Rust artifacts) is ready."""
        missing_weapons = []
        ready_weapons = []

        for weapon, verify in self.arsenal.items():
            weapon_dir = self.rust_dir / weapon
            release_dir = weapon_dir / "target" / "release"

            try:
                if release_dir.exists() and verify(release_dir):
                    ready_weapons.append(weapon)
                else:
                    missing_weapons.append(weapon)
            except (OSError, PermissionError):
                missing_weapons.append(weapon)

        if not missing_weapons:
            return Requirement(
                name="Arsenal",
                met=True,
                status="All weapons forged and ready",
                details=f"Ready: {', '.join(ready_weapons)}",
            )
        else:
            details = f"Missing: {', '.join(missing_weapons)}"
            if ready_weapons:
                details += f" | Ready: {', '.join(ready_weapons)}"
            return Requirement(
                name="Arsenal",
                met=False,
                status="Arsenal incomplete",
                details=details,
                remedy="Run: assassinate-setup",
            )

    def _check_safehouse(self) -> Requirement:
        """Verify MSF safehouse is established."""
        try:
            if not self.safehouse.exists():
                return Requirement(
                    name="Safehouse (MSF)",
                    met=False,
                    status="Safehouse not established",
                    details=f"Expected: {self.safehouse}",
                    remedy="Set MSF_ROOT or run: assassinate-setup",
                )

            gemfile = self.safehouse / "Gemfile"
            if not gemfile.exists():
                return Requirement(
                    name="Safehouse (MSF)",
                    met=False,
                    status="Safehouse compromised - missing Gemfile",
                    details=str(self.safehouse),
                    remedy="Clone MSF: git clone https://github.com/rapid7/metasploit-framework",
                )

            # Determine installation type for intel
            omnibus_root = self._find_omnibus_root()
            if omnibus_root:
                install_type = "omnibus"
            elif "/usr/share" in str(self.safehouse):
                install_type = "system package"
            else:
                install_type = "local"

            return Requirement(
                name="Safehouse (MSF)",
                met=True,
                status=f"Safehouse secured ({install_type})",
                details=str(self.safehouse),
            )

        except (OSError, PermissionError) as e:
            return Requirement(
                name="Safehouse (MSF)",
                met=False,
                status="Safehouse access denied",
                details=str(e),
            )

    def _check_ruby(self) -> Requirement:
        """Verify Ruby contact is available."""
        ruby = shutil.which(self.ruby_cmd) or (
            Path(self.ruby_cmd).exists() if "/" in self.ruby_cmd else None
        )

        if not ruby:
            return Requirement(
                name="Ruby",
                met=False,
                status="Ruby contact not found",
                details=f"Searched: {self.ruby_cmd}",
                remedy="Install Ruby or use omnibus MSF",
            )

        try:
            result = run(
                [self.ruby_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.ruby_env,
                timeout=10,
            )

            # Determine contact type
            if "omnibus" in self.ruby_cmd or "/opt/metasploit" in self.ruby_cmd:
                contact_type = "omnibus"
            elif ".rbenv" in self.ruby_cmd:
                contact_type = "rbenv"
            else:
                contact_type = "system"

            return Requirement(
                name="Ruby",
                met=True,
                status=f"Ruby contact established ({contact_type})",
                details=result.stdout.strip(),
            )
        except (CalledProcessError, TimeoutExpired, FileNotFoundError) as e:
            return Requirement(
                name="Ruby",
                met=False,
                status="Ruby contact unresponsive",
                details=str(e),
            )

    def _check_bundler(self) -> Requirement:
        """Verify Bundler contact is available."""
        bundler = shutil.which(self.bundle_cmd) or (
            Path(self.bundle_cmd).exists() if "/" in self.bundle_cmd else None
        )

        if not bundler:
            return Requirement(
                name="Bundler",
                met=False,
                status="Bundler contact not found",
                details=f"Searched: {self.bundle_cmd}",
                remedy="Install: gem install bundler",
            )

        try:
            result = run(
                [self.bundle_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.ruby_env,
                timeout=10,
            )
            return Requirement(
                name="Bundler",
                met=True,
                status="Bundler contact established",
                details=result.stdout.strip(),
            )
        except (CalledProcessError, TimeoutExpired, FileNotFoundError) as e:
            return Requirement(
                name="Bundler",
                met=False,
                status="Bundler contact unresponsive",
                details=str(e),
            )

    def quick_check(self) -> bool:
        """Perform quick operational check (arsenal only).

        Returns:
            True if arsenal is ready, False otherwise.
        """
        arsenal_req = self._check_arsenal()
        return arsenal_req.met
