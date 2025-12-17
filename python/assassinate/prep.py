"""Hideout preparation module for pre-mission environment checks.

Before any operation, the hideout must be prepared and all requirements
verified. This module ensures Rust, Ruby, and MSF dependencies are ready.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from os import environ
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired, run
from typing import Callable

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from python.log_config import get_logger

logger = get_logger("prep")

# Known safehouse locations (MSF installation paths)
KNOWN_SAFEHOUSES = [
    # Rapid7 omnibus installer (includes embedded Ruby)
    Path("/opt/metasploit-framework"),
    # Kali Linux / Debian package
    Path("/usr/share/metasploit-framework"),
    # macOS omnibus installer
    Path("/opt/metasploit-framework"),
]


@dataclass
class Requirement:
    """A requirement that must be met for hideout preparation.

    Attributes:
        name: Name of the requirement (e.g., "Rust Compiler")
        met: Whether the requirement is satisfied
        status: Human-readable status message
        details: Additional details about the requirement
        remedy: How to fix if requirement is not met
    """

    name: str
    met: bool
    status: str
    details: str = ""
    remedy: str = ""


@dataclass
class PrepReport:
    """Hideout preparation report.

    Attributes:
        requirements: List of all checked requirements
    """

    requirements: list[Requirement] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        """Check if all requirements are met."""
        return all(req.met for req in self.requirements)

    @property
    def unmet(self) -> list[Requirement]:
        """Get list of unmet requirements."""
        return [req for req in self.requirements if not req.met]

    def summary(self) -> str:
        """Generate a preparation summary."""
        lines = [
            "╔══════════════════════════════════════════════════╗",
            "║           HIDEOUT PREPARATION REPORT             ║",
            "╚══════════════════════════════════════════════════╝",
            "",
        ]

        for req in self.requirements:
            icon = "✓" if req.met else "✗"
            state = "READY" if req.met else "MISSING"
            lines.append(f"[{icon} {state}] {req.name}")
            lines.append(f"          {req.status}")
            if req.details:
                lines.append(f"          Details: {req.details}")
            if not req.met and req.remedy:
                lines.append(f"          Remedy: {req.remedy}")
            lines.append("")

        met = sum(1 for r in self.requirements if r.met)
        total = len(self.requirements)
        lines.append(f"Preparation Status: {met}/{total} requirements met")

        if not self.ready:
            lines.append("")
            lines.append(
                "⚠ HIDEOUT NOT READY - Resolve issues before proceeding"
            )

        return "\n".join(lines)


class HideoutPrep:
    """Hideout preparation handler.

    Verifies all requirements are met before the hideout can be used:
    - Rust compiler and artifacts
    - Ruby environment
    - MSF installation and gems

    Attributes:
        project_root: Root directory of the project
        rust_dir: Directory containing Rust crates
        safehouse: Path to MSF installation (the "safehouse")
        ruby_cmd: Path to Ruby executable
        bundle_cmd: Path to Bundler executable
        ruby_env: Environment variables for Ruby execution
    """

    # Required arsenal (Rust artifacts)
    arsenal: dict[str, Callable[[Path], bool]] = {
        "daemon": lambda d: (d / "daemon").exists(),
        "bridge": lambda d: any(d.glob("*.rlib")),
        "ipc": lambda d: any(d.glob("*.rlib")) or any(d.glob("*.so")),
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
        """Initialize hideout preparation.

        Args:
            project_root: Project root directory. Auto-detected if not provided.
        """
        self.project_root = project_root or self._find_project_root()
        self.rust_dir = self.project_root / "rust"
        self.safehouse = self._locate_safehouse()
        self._omnibus_root: Path | None = None
        self.ruby_cmd, self.bundle_cmd, self.ruby_env = self._identify_ruby()

    @staticmethod
    def _find_project_root() -> Path:
        """Locate project root by searching for pyproject.toml."""
        try:
            current = Path(__file__).parent
        except NameError:
            current = Path.cwd()

        while current != current.parent:
            if (current / "pyproject.toml").exists():
                return current
            current = current.parent
        raise RuntimeError("Could not locate project root")

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
            logger.debug(f"Safehouse from MSF_ROOT: {msf_root_env}")
            return Path(msf_root_env)

        # Check project-local directory
        local_msf = self.project_root / "metasploit-framework"
        if local_msf.exists() and (local_msf / "Gemfile").exists():
            logger.debug(f"Safehouse (local): {local_msf}")
            return local_msf

        # Scan known locations
        detected = self._scan_known_safehouses()
        if detected:
            logger.debug(f"Safehouse (detected): {detected}")
            return detected

        # Fall back to project-local
        logger.debug(f"Safehouse (fallback): {local_msf}")
        return local_msf

    def _scan_known_safehouses(self) -> Path | None:
        """Scan known safehouse locations for MSF installation."""
        for path in KNOWN_SAFEHOUSES:
            try:
                # Check for omnibus structure
                omnibus_framework = path / "embedded" / "framework"
                if omnibus_framework.exists():
                    if (omnibus_framework / "Gemfile").exists():
                        return omnibus_framework

                # Check standard structure
                if path.exists() and (path / "Gemfile").exists():
                    return path
            except (OSError, PermissionError):
                continue
        return None

    def _find_omnibus_root(self) -> Path | None:
        """Find omnibus installation root if applicable."""
        if self._omnibus_root is not None:
            return self._omnibus_root

        try:
            msf_path = self.safehouse.resolve()
            # Check if inside embedded/framework
            if msf_path.parts[-2:] == ("embedded", "framework"):
                omnibus_root = msf_path.parent.parent
                if (omnibus_root / "embedded" / "bin" / "ruby").exists():
                    self._omnibus_root = omnibus_root
                    return omnibus_root

            # Check common omnibus paths
            for path in [Path("/opt/metasploit-framework")]:
                if (path / "embedded" / "bin" / "ruby").exists():
                    self._omnibus_root = path
                    return path
        except (OSError, PermissionError):
            pass

        return None

    def _identify_ruby(self) -> tuple[str, str, dict[str, str]]:
        """Identify the appropriate Ruby for MSF.

        Checks in order:
        1. Omnibus embedded Ruby
        2. rbenv Ruby (from .ruby-version)
        3. System Ruby
        """
        ruby_cmd = "ruby"
        bundle_cmd = "bundle"
        env = environ.copy()

        # Check for omnibus Ruby
        omnibus_root = self._find_omnibus_root()
        if omnibus_root:
            embedded_bin = omnibus_root / "embedded" / "bin"
            if embedded_bin.exists():
                omnibus_ruby = embedded_bin / "ruby"
                omnibus_bundle = embedded_bin / "bundle"
                if omnibus_ruby.exists():
                    ruby_cmd = str(omnibus_ruby)
                    bundle_cmd = str(omnibus_bundle)
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
                rbenv_ruby = rbenv_root / "versions" / ruby_version / "bin"
                if rbenv_ruby.exists():
                    ruby_cmd = str(rbenv_ruby / "ruby")
                    bundle_cmd = str(rbenv_ruby / "bundle")
                    ruby_lib = rbenv_root / "versions" / ruby_version / "lib"
                    if ruby_lib.exists():
                        env["LD_LIBRARY_PATH"] = str(ruby_lib)
                    logger.debug(f"Using rbenv Ruby {ruby_version}")
                    return (ruby_cmd, bundle_cmd, env)
            except (IOError, OSError, PermissionError) as e:
                logger.warning(f"Cannot read .ruby-version: {e}")

        logger.debug("Using system Ruby")
        return (ruby_cmd, bundle_cmd, env)

    def check(self) -> PrepReport:
        """Check all hideout preparation requirements.

        Returns:
            PrepReport with status of all requirements.
        """
        logger.info("Checking hideout preparation...")
        report = PrepReport()

        # Check all requirements
        report.requirements.append(self._check_rust_compiler())
        report.requirements.append(self._check_cargo())
        report.requirements.append(self._check_rust_arsenal())
        report.requirements.append(self._check_safehouse())
        report.requirements.append(self._check_ruby())
        report.requirements.append(self._check_ruby_compat())
        report.requirements.append(self._check_bundler())
        report.requirements.append(self._check_gems())

        met = sum(1 for r in report.requirements if r.met)
        logger.info(
            f"Prep check complete: {met}/{len(report.requirements)} ready"
        )
        return report

    def _check_rust_compiler(self) -> Requirement:
        """Check for Rust compiler availability."""
        try:
            result = run(
                ["rustc", "--version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            version = result.stdout.strip()
            return Requirement(
                name="Rust Compiler",
                met=True,
                status="Rust compiler available",
                details=version,
            )
        except FileNotFoundError:
            return Requirement(
                name="Rust Compiler",
                met=False,
                status="Rust compiler not found",
                remedy="Install from https://rustup.rs/",
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Rust Compiler",
                met=False,
                status="Rust compiler check failed",
                details=str(e),
                remedy="Verify installation: rustc --version",
            )

    def _check_cargo(self) -> Requirement:
        """Check for Cargo availability."""
        try:
            result = run(
                ["cargo", "--version"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            version = result.stdout.strip()
            return Requirement(
                name="Cargo",
                met=True,
                status="Cargo available",
                details=version,
            )
        except FileNotFoundError:
            return Requirement(
                name="Cargo",
                met=False,
                status="Cargo not found",
                remedy="Install from https://rustup.rs/",
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Cargo",
                met=False,
                status="Cargo check failed",
                details=str(e),
                remedy="Verify installation: cargo --version",
            )

    def _check_rust_arsenal(self) -> Requirement:
        """Check that Rust arsenal (compiled artifacts) is ready."""
        missing = []
        ready = []

        for weapon, check_ready in self.arsenal.items():
            weapon_path = self.rust_dir / weapon
            release_dir = weapon_path / "target" / "release"

            try:
                if release_dir.exists() and check_ready(release_dir):
                    ready.append(weapon)
                else:
                    missing.append(weapon)
            except (OSError, PermissionError):
                missing.append(weapon)

        if not missing:
            return Requirement(
                name="Rust Arsenal",
                met=True,
                status="All Rust artifacts compiled",
                details=f"Ready: {', '.join(ready)}",
            )
        else:
            return Requirement(
                name="Rust Arsenal",
                met=False,
                status=f"Missing artifacts: {', '.join(missing)}",
                details=f"Ready: {', '.join(ready)}"
                if ready
                else "None compiled",
                remedy="Run: cargo build --release in rust/* directories",
            )

    def _check_safehouse(self) -> Requirement:
        """Check that MSF safehouse is available."""
        try:
            if self.safehouse.exists():
                gemfile = self.safehouse / "Gemfile"

                # Determine installation type
                omnibus_root = self._find_omnibus_root()
                if omnibus_root:
                    install_type = f"omnibus ({omnibus_root})"
                elif "/usr/share" in str(self.safehouse):
                    install_type = "system package (Kali/Debian)"
                else:
                    install_type = "local/development"

                if gemfile.exists():
                    return Requirement(
                        name="Safehouse (MSF)",
                        met=True,
                        status="MSF installation found",
                        details=f"{self.safehouse} ({install_type})",
                    )
                else:
                    return Requirement(
                        name="Safehouse (MSF)",
                        met=False,
                        status="MSF directory incomplete",
                        details=f"Missing Gemfile at {self.safehouse}",
                        remedy="Initialize git submodule or clone MSF repo",
                    )
            else:
                remedy_lines = [
                    "Install MSF:",
                    "  1. Set MSF_ROOT=/path/to/metasploit-framework",
                    "  2. Omnibus: curl -o msfinstall https://raw.githubusercontent.com"
                    "/rapid7/metasploit-omnibus/master/config/templates"
                    "/metasploit-framework-wrappers/msfupdate.erb && "
                    "chmod 755 msfinstall && ./msfinstall",
                    "  3. Kali: apt install metasploit-framework",
                    "  4. Clone: git clone https://github.com/rapid7/"
                    "metasploit-framework",
                ]
                return Requirement(
                    name="Safehouse (MSF)",
                    met=False,
                    status="MSF installation not found",
                    details=f"Searched: {self.safehouse}",
                    remedy="\n".join(remedy_lines),
                )
        except (OSError, PermissionError) as e:
            return Requirement(
                name="Safehouse (MSF)",
                met=False,
                status="Cannot access MSF location",
                details=str(e),
                remedy="Check directory permissions",
            )

    def _check_ruby(self) -> Requirement:
        """Check for Ruby availability."""
        omnibus_root = self._find_omnibus_root()
        if omnibus_root:
            ruby_type = "omnibus embedded"
        elif ".rbenv" in self.ruby_cmd:
            ruby_type = "rbenv"
        else:
            ruby_type = "system"

        try:
            result = run(
                [self.ruby_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.ruby_env,
                timeout=10,
            )
            version = result.stdout.strip()
            return Requirement(
                name="Ruby",
                met=True,
                status=f"Ruby available ({ruby_type})",
                details=f"{version} ({self.ruby_cmd})",
            )
        except FileNotFoundError:
            if omnibus_root:
                remedy = (
                    "Omnibus Ruby missing. Reinstall MSF via omnibus installer."
                )
            else:
                remedy = (
                    "Install Ruby:\n"
                    "  1. rbenv: rbenv install 3.3.8\n"
                    "  2. Kali/Debian: apt install ruby\n"
                    "  3. Use omnibus MSF (includes Ruby)"
                )
            return Requirement(
                name="Ruby",
                met=False,
                status="Ruby not found",
                details=f"Tried: {self.ruby_cmd}",
                remedy=remedy,
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Ruby",
                met=False,
                status="Ruby check failed",
                details=str(e),
                remedy="Verify Ruby installation",
            )

    def _check_ruby_compat(self) -> Requirement:
        """Check Ruby version compatibility with MSF."""
        specifier = self._get_msf_ruby_requirements()
        recommended = self._get_msf_recommended_ruby()

        if specifier is None and recommended is None:
            return Requirement(
                name="Ruby Compatibility",
                met=False,
                status="Cannot determine MSF Ruby requirements",
                details="MSF gemspec or .ruby-version not found",
                remedy="Ensure safehouse is properly set up",
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
            version = self._parse_ruby_version(result.stdout.strip())

            req_str = str(specifier) if specifier else "unknown"
            rec_str = str(recommended) if recommended else ""
            is_compatible = specifier is None or version in specifier

            if is_compatible:
                details = f"Found: {version}, Required: {req_str}"
                if rec_str:
                    details += f", Recommended: {rec_str}"
                return Requirement(
                    name="Ruby Compatibility",
                    met=True,
                    status="Ruby version compatible with MSF",
                    details=details,
                )
            else:
                remedy = f"Install compatible Ruby ({req_str})."
                if rec_str:
                    remedy += f" Run: rbenv install {rec_str}"
                return Requirement(
                    name="Ruby Compatibility",
                    met=False,
                    status="Ruby version incompatible with MSF",
                    details=f"Found: {version}, Required: {req_str}",
                    remedy=remedy,
                )
        except FileNotFoundError:
            return Requirement(
                name="Ruby Compatibility",
                met=False,
                status="Cannot check - Ruby not found",
                remedy="Install Ruby first",
            )
        except InvalidVersion as e:
            return Requirement(
                name="Ruby Compatibility",
                met=False,
                status="Cannot parse Ruby version",
                details=str(e),
                remedy="Check Ruby installation",
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Ruby Compatibility",
                met=False,
                status="Ruby version check failed",
                details=str(e),
                remedy="Verify Ruby installation",
            )

    def _check_bundler(self) -> Requirement:
        """Check for Bundler availability."""
        try:
            result = run(
                [self.bundle_cmd, "--version"],
                capture_output=True,
                text=True,
                check=True,
                env=self.ruby_env,
                timeout=10,
            )
            version = result.stdout.strip()
            return Requirement(
                name="Bundler",
                met=True,
                status="Bundler available",
                details=version,
            )
        except FileNotFoundError:
            return Requirement(
                name="Bundler",
                met=False,
                status="Bundler not found",
                details=f"Tried: {self.bundle_cmd}",
                remedy="Install: gem install bundler",
            )
        except (CalledProcessError, TimeoutExpired) as e:
            return Requirement(
                name="Bundler",
                met=False,
                status="Bundler check failed",
                details=str(e),
                remedy="Verify: gem install bundler",
            )

    def _check_gems(self) -> Requirement:
        """Check that MSF gems are installed."""
        if not self.safehouse.exists():
            return Requirement(
                name="MSF Gems",
                met=False,
                status="Cannot check - safehouse not found",
                remedy="Set up safehouse first",
            )

        gemfile = self.safehouse / "Gemfile"
        if not gemfile.exists():
            return Requirement(
                name="MSF Gems",
                met=False,
                status="Cannot check - no Gemfile found",
                remedy="Initialize MSF repository",
            )

        # Omnibus packages include all dependencies
        omnibus_root = self._find_omnibus_root()
        if omnibus_root:
            try:
                result = run(
                    [self.bundle_cmd, "check"],
                    cwd=self.safehouse,
                    capture_output=True,
                    text=True,
                    env=self.ruby_env,
                    timeout=30,
                )
                if result.returncode == 0:
                    return Requirement(
                        name="MSF Gems",
                        met=True,
                        status="Gems installed (omnibus)",
                        details="Pre-installed with omnibus package",
                    )
            except (FileNotFoundError, TimeoutExpired, OSError):
                pass
            return Requirement(
                name="MSF Gems",
                met=True,
                status="Gems assumed ready (omnibus)",
                details="Omnibus packages include all dependencies",
            )

        try:
            result = run(
                [self.bundle_cmd, "check"],
                cwd=self.safehouse,
                capture_output=True,
                text=True,
                env=self.ruby_env,
                timeout=30,
            )
            if result.returncode == 0:
                return Requirement(
                    name="MSF Gems",
                    met=True,
                    status="All gems installed",
                    details="bundle check passed",
                )
            else:
                return Requirement(
                    name="MSF Gems",
                    met=False,
                    status="Gems missing or incomplete",
                    details=result.stderr.strip() or result.stdout.strip(),
                    remedy=f"Run: cd {self.safehouse} && bundle install",
                )
        except FileNotFoundError:
            return Requirement(
                name="MSF Gems",
                met=False,
                status="Cannot check - Bundler not found",
                remedy="Install Bundler first",
            )
        except TimeoutExpired:
            return Requirement(
                name="MSF Gems",
                met=False,
                status="Gem check timed out",
                remedy=f"Check manually: cd {self.safehouse} && bundle check",
            )
        except (CalledProcessError, OSError) as e:
            return Requirement(
                name="MSF Gems",
                met=False,
                status="Gem check failed",
                details=str(e),
                remedy=f"Run: cd {self.safehouse} && bundle install",
            )

    @staticmethod
    def _parse_ruby_version(version_string: str) -> Version:
        """Parse Ruby version string into Version object."""
        match = re.search(r"(\d+\.\d+\.\d+)", version_string)
        if match:
            return Version(match.group(1))
        return Version(version_string.strip())

    @staticmethod
    def _ruby_constraint_to_pep440(constraint: str) -> str:
        """Convert Ruby version constraint to PEP 440 format."""
        # Ruby ~> (pessimistic) operator
        pessimistic_match = re.match(
            r"~>\s*(\d+)\.(\d+)(?:\.(\d+))?", constraint
        )
        if pessimistic_match:
            major = int(pessimistic_match.group(1))
            minor = int(pessimistic_match.group(2))
            patch = pessimistic_match.group(3)
            if patch:
                return f">={major}.{minor}.{patch},<{major}.{minor + 1}.0"
            else:
                return f">={major}.{minor}.0,<{major + 1}.0.0"

        return re.sub(r"\s+", "", constraint)

    def _get_msf_ruby_requirements(self) -> SpecifierSet | None:
        """Read Ruby version requirements from MSF gemspec."""
        gemspec = self.safehouse / "metasploit-framework.gemspec"
        if not gemspec.exists():
            logger.debug(f"MSF gemspec not found: {gemspec}")
            return None

        try:
            content = gemspec.read_text()
        except (IOError, OSError, PermissionError) as e:
            logger.warning(f"Cannot read MSF gemspec: {e}")
            return None

        match = re.search(
            r"required_ruby_version\s*=\s*['\"]([^'\"]+)['\"]",
            content,
        )

        if not match:
            logger.debug("No required_ruby_version in gemspec")
            return None

        ruby_constraint = match.group(1)
        logger.debug(f"MSF Ruby constraint: {ruby_constraint}")

        try:
            pep440_constraint = self._ruby_constraint_to_pep440(ruby_constraint)
            return SpecifierSet(pep440_constraint)
        except InvalidSpecifier as e:
            logger.warning(f"Cannot parse constraint '{ruby_constraint}': {e}")
            return None

    def _get_msf_recommended_ruby(self) -> Version | None:
        """Read recommended Ruby version from MSF .ruby-version."""
        ruby_version_file = self.safehouse / ".ruby-version"
        if not ruby_version_file.exists():
            logger.debug("MSF .ruby-version not found")
            return None

        try:
            version_str = ruby_version_file.read_text().strip()
            return self._parse_ruby_version(version_str)
        except (IOError, OSError, PermissionError) as e:
            logger.warning(f"Cannot read MSF .ruby-version: {e}")
            return None
        except InvalidVersion as e:
            logger.warning(f"Cannot parse MSF .ruby-version: {e}")
            return None
