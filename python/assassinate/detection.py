"""Auto-detection for MSF installation and Ruby environment.

This module provides automatic detection of:
- Metasploit Framework installation path
- Ruby version manager (RVM, rbenv, system)
- Ruby version from MSF's .ruby-version file
- Ruby environment variables (GEM_HOME, GEM_PATH, PATH)

The detection logic follows common installation patterns and can be
overridden via configuration if auto-detection doesn't work for your setup.

Example:
    >>> from assassinate.detection import detect_msf_root, detect_ruby_manager
    >>> msf_path = detect_msf_root()
    >>> print(msf_path)
    /opt/metasploit-framework
    >>> manager = detect_ruby_manager()
    >>> print(manager)
    rvm
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Literal

# =============================================================================
# MSF Detection
# =============================================================================

# Common MSF installation paths, ordered by likelihood
MSF_SEARCH_PATHS = [
    # Standard package installations
    Path("/opt/metasploit-framework"),
    Path("/opt/metasploit-framework/embedded/framework"),
    Path("/usr/share/metasploit-framework"),
    # User installations
    Path.home() / "Projects" / "metasploit-framework",
    Path.home() / "metasploit-framework",
    Path.home() / "git" / "metasploit-framework",
    Path.home() / "src" / "metasploit-framework",
    # Kali Linux default
    Path("/usr/share/metasploit-framework"),
    # macOS Homebrew
    Path("/opt/homebrew/Cellar/metasploit"),
    Path("/usr/local/Cellar/metasploit"),
]


def detect_msf_root() -> Path | None:
    """Auto-detect MSF installation path.

    Searches common installation locations for a valid MSF installation.
    A valid installation has a Gemfile in the root directory.

    Returns:
        Path to MSF installation, or None if not found

    Example:
        >>> path = detect_msf_root()
        >>> if path:
        ...     print(f"Found MSF at: {path}")
        ... else:
        ...     print("MSF not found")
    """
    for path in MSF_SEARCH_PATHS:
        expanded = path.expanduser()
        if expanded.exists() and (expanded / "Gemfile").exists():
            return expanded.resolve()

    # Check if MSF is in PATH (msfconsole might reveal location)
    msfconsole = shutil.which("msfconsole")
    if msfconsole:
        # msfconsole is typically at MSF_ROOT/msfconsole or a symlink
        msfconsole_path = Path(msfconsole).resolve()
        potential_root = msfconsole_path.parent
        if (potential_root / "Gemfile").exists():
            return potential_root

    return None


def is_valid_msf_root(path: Path | str) -> bool:
    """Check if a path is a valid MSF installation.

    Args:
        path: Path to check

    Returns:
        True if path contains a valid MSF installation
    """
    path = Path(path).expanduser()
    if not path.exists():
        return False
    if not (path / "Gemfile").exists():
        return False
    # Additional checks for a valid MSF installation
    if not (path / "lib" / "msf").exists():
        return False
    return True


# =============================================================================
# Ruby Manager Detection
# =============================================================================


def detect_ruby_manager() -> Literal["rvm", "rbenv", "system"]:
    """Detect which Ruby version manager is installed and active.

    Checks for RVM first (more common in MSF installations), then rbenv.
    Falls back to "system" if neither is found.

    Returns:
        "rvm", "rbenv", or "system"

    Example:
        >>> manager = detect_ruby_manager()
        >>> print(f"Using {manager} for Ruby version management")
    """
    # Check for RVM
    rvm_path = Path.home() / ".rvm"
    if rvm_path.exists():
        # Verify rvm command is available
        if shutil.which("rvm") or (rvm_path / "bin" / "rvm").exists():
            return "rvm"
        # Check for rvm in scripts (might need sourcing)
        if (rvm_path / "scripts" / "rvm").exists():
            return "rvm"

    # Check for rbenv
    rbenv_path = Path.home() / ".rbenv"
    if rbenv_path.exists():
        if shutil.which("rbenv") or (rbenv_path / "bin" / "rbenv").exists():
            return "rbenv"

    # Check for system-wide rbenv
    if shutil.which("rbenv"):
        return "rbenv"

    return "system"


def detect_ruby_version(msf_root: Path | str) -> str | None:
    """Detect Ruby version from MSF's .ruby-version file.

    MSF includes a .ruby-version file specifying the required Ruby version.
    This function reads and returns that version.

    Args:
        msf_root: Path to MSF installation

    Returns:
        Ruby version string (e.g., "3.3.8"), or None if not found

    Example:
        >>> version = detect_ruby_version("/opt/metasploit-framework")
        >>> print(f"MSF requires Ruby {version}")
    """
    msf_root = Path(msf_root).expanduser()
    ruby_version_file = msf_root / ".ruby-version"

    if not ruby_version_file.exists():
        return None

    try:
        version = ruby_version_file.read_text().strip()
        # Clean up version string (remove ruby- prefix if present)
        if version.startswith("ruby-"):
            version = version[5:]
        return version
    except Exception:
        return None


def is_ruby_version_installed(
    version: str,
    manager: Literal["rvm", "rbenv", "system"] = "auto",
) -> bool:
    """Check if a specific Ruby version is installed.

    Args:
        version: Ruby version to check (e.g., "3.3.8")
        manager: Ruby manager to check, or "auto" to detect

    Returns:
        True if the version is installed
    """
    if manager == "auto":
        manager = detect_ruby_manager()

    if manager == "rvm":
        rvm_ruby = Path.home() / ".rvm" / "rubies" / f"ruby-{version}"
        return rvm_ruby.exists()
    elif manager == "rbenv":
        rbenv_ruby = Path.home() / ".rbenv" / "versions" / version
        return rbenv_ruby.exists()
    else:
        # System Ruby - just check if ruby command exists and version matches
        ruby_path = shutil.which("ruby")
        if not ruby_path:
            return False
        try:
            import subprocess

            result = subprocess.run(
                ["ruby", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return version in result.stdout
        except Exception:
            return False


# =============================================================================
# Ruby Environment
# =============================================================================


def get_ruby_env(
    manager: Literal["rvm", "rbenv", "system"],
    version: str | None = None,
    msf_root: Path | str | None = None,
) -> dict[str, str]:
    """Get environment variables for Ruby execution.

    Constructs the appropriate environment for running Ruby with the
    specified version manager and version. This includes GEM_HOME,
    GEM_PATH, PATH, and BUNDLE_GEMFILE settings.

    Args:
        manager: Ruby version manager ("rvm", "rbenv", "system")
        version: Ruby version (e.g., "3.3.8"). Auto-detected if None.
        msf_root: Path to MSF for BUNDLE_GEMFILE. Optional.

    Returns:
        Dictionary of environment variables to use

    Example:
        >>> env = get_ruby_env("rvm", "3.3.8", "/opt/metasploit-framework")
        >>> subprocess.run(["ruby", "script.rb"], env=env)
    """
    env = os.environ.copy()

    if manager == "rvm" and version:
        rvm_root = Path.home() / ".rvm"
        gem_home = rvm_root / "gems" / f"ruby-{version}"
        gem_global = rvm_root / "gems" / f"ruby-{version}@global"
        ruby_bin = rvm_root / "rubies" / f"ruby-{version}" / "bin"

        env.update(
            {
                "GEM_HOME": str(gem_home),
                "GEM_PATH": f"{gem_home}:{gem_global}",
                "MY_RUBY_HOME": str(rvm_root / "rubies" / f"ruby-{version}"),
                "RUBY_VERSION": f"ruby-{version}",
                "PATH": f"{gem_home}/bin:{ruby_bin}:{rvm_root}/bin:{env.get('PATH', '')}",
            }
        )

    elif manager == "rbenv" and version:
        rbenv_root = Path.home() / ".rbenv"
        version_root = rbenv_root / "versions" / version

        env.update(
            {
                "RBENV_VERSION": version,
                "RBENV_ROOT": str(rbenv_root),
                "PATH": f"{rbenv_root}/shims:{rbenv_root}/bin:{env.get('PATH', '')}",
            }
        )

        # Set GEM_HOME/PATH if version directory exists
        if version_root.exists():
            gem_dir = version_root / "lib" / "ruby" / "gems"
            # Find the actual gem directory (version-specific)
            if gem_dir.exists():
                gem_dirs = list(gem_dir.glob("*"))
                if gem_dirs:
                    env["GEM_HOME"] = str(gem_dirs[0])
                    env["GEM_PATH"] = str(gem_dirs[0])

    # Set BUNDLE_GEMFILE if MSF root provided
    if msf_root:
        msf_root = Path(msf_root).expanduser()
        gemfile = msf_root / "Gemfile"
        if gemfile.exists():
            env["BUNDLE_GEMFILE"] = str(gemfile)
            # Also set BUNDLE_WITHOUT to skip dev/test groups
            env["BUNDLE_WITHOUT"] = "development:test"

    return env


def get_rvm_command(version: str) -> list[str]:
    """Get the command prefix to run Ruby via RVM.

    Args:
        version: Ruby version to use

    Returns:
        Command list to prefix Ruby commands (e.g., ["rvm", "3.3.8", "do"])

    Example:
        >>> cmd = get_rvm_command("3.3.8")
        >>> subprocess.run(cmd + ["ruby", "--version"])
    """
    return ["rvm", version, "do"]


def get_rbenv_command(version: str) -> list[str]:
    """Get the command prefix to run Ruby via rbenv.

    Args:
        version: Ruby version to use

    Returns:
        Command list with RBENV_VERSION set in environment

    Note:
        rbenv uses RBENV_VERSION env var rather than command prefix.
        Use get_ruby_env() instead for subprocess calls.
    """
    # rbenv doesn't use a command prefix like rvm
    # Instead, set RBENV_VERSION in environment
    return []


# =============================================================================
# Full Environment Setup
# =============================================================================


def get_full_ruby_env(
    msf_root: Path | str | None = None,
    ruby_version: str | None = None,
    ruby_manager: Literal["rvm", "rbenv", "system", "auto"] = "auto",
) -> dict[str, str]:
    """Get complete Ruby environment for MSF execution.

    This is the high-level function that auto-detects everything needed
    and returns a complete environment dictionary.

    Args:
        msf_root: Path to MSF (auto-detected if None)
        ruby_version: Ruby version (read from .ruby-version if None)
        ruby_manager: Ruby manager (auto-detected if "auto")

    Returns:
        Complete environment dictionary for subprocess calls

    Example:
        >>> env = get_full_ruby_env()
        >>> subprocess.run(["bundle", "exec", "ruby", "msfconsole"], env=env)
    """
    # Auto-detect MSF root if needed
    if msf_root is None:
        msf_root = detect_msf_root()

    # Auto-detect Ruby manager if needed
    if ruby_manager == "auto":
        ruby_manager = detect_ruby_manager()

    # Auto-detect Ruby version if needed
    if ruby_version is None and msf_root:
        ruby_version = detect_ruby_version(msf_root)

    return get_ruby_env(ruby_manager, ruby_version, msf_root)


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # MSF detection
    "detect_msf_root",
    "is_valid_msf_root",
    "MSF_SEARCH_PATHS",
    # Ruby detection
    "detect_ruby_manager",
    "detect_ruby_version",
    "is_ruby_version_installed",
    # Ruby environment
    "get_ruby_env",
    "get_rvm_command",
    "get_rbenv_command",
    "get_full_ruby_env",
]
