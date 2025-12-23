"""Assassinate Dependency Installer using Ansible Runner.

Provides unified, cross-platform dependency installation using ansible_runner.
Handles all setup for Assassinate and Metasploit Framework across distros.

Usage:
    assassinate-setup --install
    assassinate-setup --install --steps packages,rust,build
    assassinate-setup --install --skip-steps msf
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("assassinate.installer")


# =============================================================================
# Constants
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RUST_DIR = PROJECT_ROOT / "rust"
CACHE_DIR = PROJECT_ROOT / ".installer_cache"
CARGO_HOME = "/usr/local/cargo"
RUSTUP_HOME = "/usr/local/rustup"
CONTAINER_TARGET = "/tmp/cargo-target"
MSF_CLONE_PATH = "/opt/metasploit-framework"
MSF_CLONE_URL = "https://github.com/rapid7/metasploit-framework.git"
SECURITY_DISTROS = ("Kali", "Parrot")
RUST_COMPONENTS = ("ipc", "bridge", "daemon")

# Ansible condition helpers
OS_FAMILY = "ansible_facts['os_family']"
DISTRO = "ansible_facts['distribution']"


# =============================================================================
# Installation Steps
# =============================================================================


class Step(Enum):
    """Installation steps that can be individually selected or skipped."""

    PACKAGES = auto()
    RUST = auto()
    BUILD = auto()
    RUBY = auto()
    MSF = auto()

    @classmethod
    def all(cls) -> set[Step]:
        return set(cls)

    @classmethod
    def from_string(cls, s: str) -> Step:
        return cls[s.upper()]

    @classmethod
    def parse_list(cls, s: str) -> set[Step]:
        return {cls.from_string(x.strip()) for x in s.split(",") if x.strip()}


# =============================================================================
# Package Definitions
# =============================================================================


@dataclass(frozen=True)
class DistroPackages:
    """Package definitions for a distribution family."""

    build: tuple[str, ...]
    rust_deps: tuple[str, ...]
    capnp: tuple[str, ...]
    ruby: tuple[str, ...]
    ruby_build: tuple[str, ...] = ()
    rust: tuple[str, ...] = ()  # System rust packages (Arch)
    msf: tuple[str, ...] = ()  # Package MSF (Kali/Parrot)

    @property
    def all_packages(self) -> list[str]:
        """All packages except MSF (handled separately)."""
        return [
            *self.build,
            *self.rust_deps,
            *self.capnp,
            *self.ruby,
            *self.ruby_build,
            *self.rust,
        ]


DISTRO_PACKAGES: dict[str, DistroPackages] = {
    "Debian": DistroPackages(
        build=("build-essential", "git", "curl", "cmake"),
        rust_deps=("libssl-dev", "pkg-config", "libclang-dev", "libpcap-dev"),
        capnp=("capnproto", "libcapnp-dev"),
        ruby=("ruby-full", "ruby-dev", "ruby-bundler"),
        ruby_build=("libyaml-dev", "libffi-dev", "libpq-dev"),
        msf=("metasploit-framework",),
    ),
    "RedHat": DistroPackages(
        build=("gcc", "gcc-c++", "make", "git", "curl", "cmake"),
        rust_deps=(
            "openssl-devel",
            "pkgconf-pkg-config",
            "clang-devel",
            "libpcap-devel",
        ),
        capnp=("capnproto", "capnproto-devel"),
        ruby=("ruby", "ruby-devel", "rubygem-bundler"),
        ruby_build=("libyaml-devel", "libffi-devel", "postgresql-devel"),
    ),
    "Archlinux": DistroPackages(
        build=("base-devel", "git", "curl", "cmake"),
        rust_deps=("openssl", "pkgconf", "clang", "libpcap"),
        capnp=("capnproto",),
        ruby=("ruby", "ruby-bundler"),
        ruby_build=("libyaml", "libffi", "postgresql-libs"),
        rust=("rust",),
    ),
    "Suse": DistroPackages(
        build=("gcc", "gcc-c++", "make", "git", "curl", "cmake"),
        rust_deps=(
            "libopenssl-devel",
            "pkg-config",
            "clang-devel",
            "libpcap-devel",
        ),
        capnp=("capnproto",),
        ruby=("ruby", "ruby-devel"),
        ruby_build=("libyaml-devel", "libffi-devel", "postgresql-devel"),
    ),
    "Darwin": DistroPackages(
        build=("git", "cmake"),
        rust_deps=("openssl", "pkg-config", "llvm"),
        capnp=("capnp",),
        ruby=("ruby",),
        ruby_build=("libyaml", "libffi", "postgresql"),
    ),
}


# =============================================================================
# Task Factory
# =============================================================================


class TaskFactory:
    """Factory for creating Ansible tasks with consistent patterns."""

    @staticmethod
    def package(
        name: str, packages: list[str], family: str, **kwargs
    ) -> dict[str, Any]:
        """Create a package installation task."""
        task: dict[str, Any] = {
            "name": name,
            "become": True,
            "when": f"{OS_FAMILY} == '{family}'",
            "ignore_errors": kwargs.get("ignore_errors", True),
        }
        if family == "Darwin":
            task["community.general.homebrew"] = {
                "name": packages,
                "state": "present",
            }
            task.pop("become")
        else:
            task["package"] = {"name": packages, "state": "present"}
        return task

    @staticmethod
    def shell(name: str, cmd: str, **kwargs) -> dict[str, Any]:
        """Create a shell command task."""
        task: dict[str, Any] = {
            "name": name,
            "ansible.builtin.shell": {"cmd": cmd},
        }
        if chdir := kwargs.get("chdir"):
            task["ansible.builtin.shell"]["chdir"] = str(chdir)
        if env := kwargs.get("environment"):
            task["environment"] = env
        for key in (
            "become",
            "when",
            "ignore_errors",
            "register",
            "changed_when",
            "timeout",
        ):
            if key in kwargs:
                task[key] = kwargs[key]
        return task

    @staticmethod
    def command(name: str, cmd: str, **kwargs) -> dict[str, Any]:
        """Create a command task."""
        task: dict[str, Any] = {
            "name": name,
            "ansible.builtin.command": {"cmd": cmd},
        }
        for key in ("register", "ignore_errors", "changed_when", "when"):
            if key in kwargs:
                task[key] = kwargs[key]
        return task

    @staticmethod
    def file(
        name: str, src: str, dest: str, state: str = "link", **kwargs
    ) -> dict[str, Any]:
        """Create a file/symlink task."""
        task: dict[str, Any] = {
            "name": name,
            "ansible.builtin.file": {"src": src, "dest": dest, "state": state},
            "become": True,
        }
        if state == "link":
            task["ansible.builtin.file"]["force"] = True
        for key in ("when", "ignore_errors", "loop"):
            if key in kwargs:
                task[key] = kwargs[key]
        return task

    @staticmethod
    def copy(
        name: str, dest: str, content: str, mode: str = "0644", **kwargs
    ) -> dict[str, Any]:
        """Create a copy/template task."""
        task: dict[str, Any] = {
            "name": name,
            "ansible.builtin.copy": {
                "dest": dest,
                "content": content,
                "mode": mode,
            },
            "become": True,
        }
        for key in ("when", "ignore_errors"):
            if key in kwargs:
                task[key] = kwargs[key]
        return task

    @staticmethod
    def git(name: str, repo: str, dest: str, **kwargs) -> dict[str, Any]:
        """Create a git clone task."""
        return {
            "name": name,
            "ansible.builtin.git": {
                "repo": repo,
                "dest": dest,
                "depth": 1,
                "force": False,
            },
            "become": True,
            **{
                k: v
                for k, v in kwargs.items()
                if k in ("when", "ignore_errors")
            },
        }

    @staticmethod
    def stat(name: str, path: str, register: str) -> dict[str, Any]:
        """Create a stat check task."""
        return {
            "name": name,
            "ansible.builtin.stat": {"path": path},
            "register": register,
        }

    @staticmethod
    def get_url(
        name: str, url: str, dest: str, mode: str = "0755", **kwargs
    ) -> dict[str, Any]:
        """Create a URL download task."""
        task: dict[str, Any] = {
            "name": name,
            "ansible.builtin.get_url": {"url": url, "dest": dest, "mode": mode},
        }
        if when := kwargs.get("when"):
            task["when"] = when
        return task


# =============================================================================
# Task Generators
# =============================================================================


def generate_package_tasks() -> list[dict[str, Any]]:
    """Generate package installation tasks for all distro families."""
    return [
        TaskFactory.package(
            f"Install packages ({family})", pkgs.all_packages, family
        )
        for family, pkgs in DISTRO_PACKAGES.items()
    ]


def generate_rust_tasks() -> list[dict[str, Any]]:
    """Generate Rust installation tasks."""
    rust_env = {"CARGO_HOME": CARGO_HOME, "RUSTUP_HOME": RUSTUP_HOME}
    not_arch = f"{OS_FAMILY} != 'Archlinux'"
    needs_install = f"{not_arch} and rustc_check.rc != 0"

    return [
        # Arch uses system packages
        TaskFactory.package("Install Rust (Arch)", ["rust"], "Archlinux"),
        # Check existing
        TaskFactory.command(
            "Check for existing rustc",
            "which rustc",
            register="rustc_check",
            ignore_errors=True,
            changed_when=False,
            when=not_arch,
        ),
        # Download and install
        TaskFactory.get_url(
            "Download rustup",
            "https://sh.rustup.rs",
            "/tmp/rustup.sh",
            when=needs_install,
        ),
        TaskFactory.shell(
            "Install Rust via rustup",
            "/tmp/rustup.sh -y --default-toolchain stable --no-modify-path",
            environment=rust_env,
            become=True,
            when=needs_install,
        ),
        TaskFactory.shell(
            "Set Rust default toolchain",
            f"{CARGO_HOME}/bin/rustup default stable",
            environment=rust_env,
            become=True,
            when=needs_install,
            ignore_errors=True,
        ),
        # Symlinks
        {
            "name": "Create Rust symlinks",
            "ansible.builtin.file": {
                "src": f"{CARGO_HOME}/bin/{{{{ item }}}}",
                "dest": "/usr/local/bin/{{ item }}",
                "state": "link",
                "force": True,
            },
            "loop": ["rustc", "cargo", "rustup"],
            "become": True,
            "when": not_arch,
            "ignore_errors": True,
        },
        # Profile script
        TaskFactory.copy(
            "Create Rust profile script",
            "/etc/profile.d/rust.sh",
            f'export CARGO_HOME="{CARGO_HOME}"\nexport RUSTUP_HOME="{RUSTUP_HOME}"\nexport PATH="{CARGO_HOME}/bin:$PATH"\n',
            when=not_arch,
        ),
    ]


def generate_build_tasks() -> list[dict[str, Any]]:
    """Generate Rust component build tasks."""
    env = {
        "CARGO_HOME": CARGO_HOME,
        "RUSTUP_HOME": RUSTUP_HOME,
        "PATH": f"{CARGO_HOME}/bin:/usr/local/bin:/usr/bin:/bin",
    }
    if Path("/.dockerenv").exists() or os.environ.get("CONTAINER"):
        env["CARGO_TARGET_DIR"] = CONTAINER_TARGET

    return [
        TaskFactory.shell(
            f"Build Rust {comp}",
            "cargo build --release",
            chdir=RUST_DIR / comp,
            environment=env,
        )
        for comp in RUST_COMPONENTS
    ]


def generate_ruby_tasks() -> list[dict[str, Any]]:
    """Generate Ruby/Bundler setup tasks."""
    return [
        TaskFactory.copy(
            "Create Arch gem PATH script",
            "/etc/profile.d/ruby-gems.sh",
            "if command -v ruby &>/dev/null; then\n  export PATH=\"$(ruby -e 'puts Gem.user_dir')/bin:$PATH\"\nfi\n",
            when=f"{OS_FAMILY} == 'Archlinux'",
        ),
        TaskFactory.shell(
            "Install xmlrpc gem",
            "gem install xmlrpc --no-document",
            become=True,
            ignore_errors=True,
        ),
        TaskFactory.shell(
            "Install bundler gem",
            "gem install bundler --no-document",
            become=True,
            ignore_errors=True,
        ),
    ]


def generate_msf_tasks() -> list[dict[str, Any]]:
    """Generate MSF installation tasks."""
    is_security = f"{DISTRO} in {list(SECURITY_DISTROS)}"
    not_security = f"{DISTRO} not in {list(SECURITY_DISTROS)}"

    return [
        TaskFactory.stat(
            "Check for package MSF",
            "/usr/share/metasploit-framework/Gemfile",
            "msf_pkg",
        ),
        TaskFactory.stat(
            "Check for cloned MSF", f"{MSF_CLONE_PATH}/Gemfile", "msf_cloned"
        ),
        TaskFactory.package(
            "Install MSF package (Kali/Parrot)",
            ["metasploit-framework"],
            "Debian",
            when=f"{is_security} and not msf_pkg.stat.exists",
        ),
        TaskFactory.git(
            "Clone Metasploit Framework",
            MSF_CLONE_URL,
            MSF_CLONE_PATH,
            when=f"{not_security} and not msf_pkg.stat.exists and not msf_cloned.stat.exists",
        ),
    ]


def generate_bundle_tasks(msf_root: str) -> list[dict[str, Any]]:
    """Generate MSF bundle install tasks."""
    return [
        TaskFactory.shell(
            "Check MSF bundle status",
            "bundle check",
            chdir=msf_root,
            register="bundle_check",
            ignore_errors=True,
            changed_when=False,
        ),
        TaskFactory.shell(
            "Install MSF gems (10-15 minutes)",
            "bundle install --jobs 1 --retry 3",
            chdir=msf_root,
            become=True,
            when="bundle_check.rc != 0",
            timeout=1800,
        ),
    ]


# =============================================================================
# Installer Class
# =============================================================================


@dataclass
class Installer:
    """Ansible-based dependency installer for Assassinate."""

    verbose: bool = False
    dry_run: bool = False
    force: bool = False
    steps: set[Step] = field(default_factory=Step.all)

    _cache: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._load_cache()
        os.environ.setdefault("ANSIBLE_TIMEOUT", "300")

    # -------------------------------------------------------------------------
    # Cache
    # -------------------------------------------------------------------------

    def _load_cache(self) -> None:
        try:
            self._cache = json.loads((CACHE_DIR / "status.json").read_text())
        except (json.JSONDecodeError, OSError, FileNotFoundError):
            self._cache = {}

    def _save_cache(self) -> None:
        (CACHE_DIR / "status.json").write_text(
            json.dumps(self._cache, indent=2)
        )

    def _is_cached(self, key: str) -> bool:
        return self._cache.get(key, False) and not self.force

    def _mark_done(self, key: str) -> None:
        self._cache[key] = True
        self._save_cache()

    # -------------------------------------------------------------------------
    # Ansible Execution
    # -------------------------------------------------------------------------

    def _run_ansible(
        self, tasks: list[dict[str, Any]], name: str
    ) -> tuple[bool, str]:
        """Execute Ansible tasks via ansible_runner."""
        try:
            from ansible_runner.interface import run
        except ImportError:
            return False, "ansible_runner not installed"

        if self.dry_run:
            log.info(f"[DRY RUN] Would run {len(tasks)} tasks for {name}")
            return True, ""

        data_dir = CACHE_DIR / f"ansible_{name}"
        shutil.rmtree(data_dir, ignore_errors=True)
        data_dir.mkdir(parents=True)

        try:
            result = run(
                playbook={"hosts": "all", "gather_facts": True, "tasks": tasks},
                private_data_dir=str(data_dir),
                host_pattern="localhost",
                inventory={
                    "all": {
                        "hosts": {
                            "localhost": {
                                "ansible_connection": "local",
                                "ansible_python_interpreter": sys.executable,
                            }
                        }
                    }
                },
                quiet=not self.verbose,
                verbosity=2 if self.verbose else 0,
                envvars={
                    **os.environ,
                    "PATH": f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}",
                },
            )

            if result.status == "successful":
                return True, ""

            for event in result.events:
                if event.get("event") == "runner_on_failed":
                    return False, event.get("event_data", {}).get(
                        "res", {}
                    ).get("msg", "Unknown error")
            return False, "Unknown failure"

        except Exception as e:
            return False, str(e)
        finally:
            if not self.verbose:
                shutil.rmtree(data_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Step Runners
    # -------------------------------------------------------------------------

    def _run_step(
        self,
        step: Step,
        name: str,
        cache_key: str,
        task_generator: Callable[[], list[dict[str, Any]]],
        warn_only: bool = False,
    ) -> bool:
        """Generic step runner with caching and logging."""
        if step not in self.steps:
            log.info(f"⏭ Skipping {name}")
            return True

        if self._is_cached(cache_key):
            log.info(f"✓ {name} (cached)")
            return True

        log.info(f"{'📦' if step == Step.PACKAGES else '🔧'} {name}...")
        success, error = self._run_ansible(task_generator(), cache_key)

        if success:
            self._mark_done(cache_key)
            log.info(f"✓ {name} complete")
        elif warn_only:
            log.warning(f"⚠ {name}: {error}")
            return True  # Continue despite failure
        else:
            log.error(f"✗ {name} failed: {error}")

        return success

    def run_packages(self) -> bool:
        return self._run_step(
            Step.PACKAGES,
            "System packages",
            "packages",
            generate_package_tasks,
            warn_only=True,
        )

    def run_rust(self) -> bool:
        return self._run_step(
            Step.RUST, "Rust toolchain", "rust", generate_rust_tasks
        )

    def run_build(self) -> bool:
        if Step.BUILD not in self.steps:
            log.info("⏭ Skipping Rust build")
            return True

        if self._is_rust_built() and not self.force:
            log.info("✓ Rust components (already built)")
            return True

        return self._run_step(
            Step.BUILD, "Rust components", "build", generate_build_tasks
        )

    def run_ruby(self) -> bool:
        return self._run_step(
            Step.RUBY,
            "Ruby environment",
            "ruby",
            generate_ruby_tasks,
            warn_only=True,
        )

    def run_msf(self) -> bool:
        if Step.MSF not in self.steps:
            log.info("⏭ Skipping MSF setup")
            return True

        if self._is_cached("msf"):
            log.info("✓ MSF configured (cached)")
            return True

        log.info("🏠 Setting up Metasploit Framework...")

        # Install or clone
        success, error = self._run_ansible(generate_msf_tasks(), "msf_install")
        if not success:
            log.warning(f"⚠ MSF install: {error}")

        # Find and bundle
        if msf_root := self._find_msf():
            log.info(f"  → Found: {msf_root}")
            if "/usr/share" in str(msf_root):
                log.info("  ✓ Package MSF (pre-bundled)")
            elif (msf_root / "Gemfile").exists():
                log.info("  → Installing gems (10-15 min)...")
                success, error = self._run_ansible(
                    generate_bundle_tasks(str(msf_root)), "msf_bundle"
                )
                if not success:
                    log.warning(f"  ⚠ Bundle: {error}")
                    return False
                log.info("  ✓ Gems installed")

            self._mark_done("msf")
            return True

        log.warning("⚠ MSF not found after installation")
        return False

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _find_msf(self) -> Path | None:
        """Find MSF installation location."""
        candidates = [
            os.environ.get("MSF_ROOT"),
            "/usr/share/metasploit-framework",
            MSF_CLONE_PATH,
            str(PROJECT_ROOT / "metasploit-framework"),
            str(Path.home() / "metasploit-framework"),
        ]
        for loc in filter(None, candidates):
            if (path := Path(loc)).exists() and (path / "Gemfile").exists():
                return path
        return None

    def _is_rust_built(self) -> bool:
        """Check if Rust components are built."""
        return any(
            (loc / "daemon").exists()
            for loc in [
                RUST_DIR / "daemon" / "target" / "release",
                Path(CONTAINER_TARGET) / "release",
            ]
        )

    def _check_binary(self, name: str, is_lib: bool = False) -> bool:
        """Check if a Rust binary/library exists."""
        for loc in [
            RUST_DIR / name / "target" / "release",
            Path(CONTAINER_TARGET) / "release",
        ]:
            if not loc.exists():
                continue
            if is_lib and (
                list(loc.glob(f"lib{name}.*")) or list(loc.glob("*.rlib"))
            ):
                return True
            if not is_lib and (loc / name).exists():
                return True
        return False

    # -------------------------------------------------------------------------
    # Main Entry Points
    # -------------------------------------------------------------------------

    def install(self) -> bool:
        """Run installation with selected steps."""
        print("\n" + "=" * 60)
        print("  ASSASSINATE INSTALLER")
        print(
            f"  Steps: {', '.join(s.name.lower() for s in sorted(self.steps, key=lambda x: x.value))}"
        )
        print("=" * 60 + "\n")

        runners = [
            (Step.PACKAGES, self.run_packages),
            (Step.RUST, self.run_rust),
            (Step.BUILD, self.run_build),
            (Step.RUBY, self.run_ruby),
            (Step.MSF, self.run_msf),
        ]

        success = all(run() for step, run in runners if step in self.steps)

        print("\n" + "=" * 60)
        print(
            f"  {'✓ INSTALLATION COMPLETE' if success else '⚠ INSTALLATION INCOMPLETE'}"
        )
        if success:
            print("  Assassinate is ready to use!")
        print("=" * 60 + "\n")

        return success

    def verify(self) -> dict[str, bool]:
        """Verify installation status."""
        return {
            "rustc": shutil.which("rustc") is not None,
            "cargo": shutil.which("cargo") is not None,
            "capnp": shutil.which("capnp") is not None,
            "ruby": shutil.which("ruby") is not None,
            "bundler": shutil.which("bundle") is not None,
            "daemon": self._check_binary("daemon"),
            "bridge": self._check_binary("bridge", is_lib=True),
            "msf": self._find_msf() is not None,
        }

    def print_status(self) -> None:
        """Print installation status."""
        status = self.verify()
        all_ok = all(status.values())

        print("\n📋 Installation Status:")
        print("-" * 40)
        for name, ok in status.items():
            print(f"  {'✓' if ok else '✗'} {name}")
        print("-" * 40)
        if all_ok:
            print("  All components installed ✓")
        else:
            missing = ", ".join(k for k, v in status.items() if not v)
            print(f"  Missing: {missing}")
        print()


# =============================================================================
# CLI Entry Points
# =============================================================================


def run_install(
    verbose: bool = False,
    dry_run: bool = False,
    force: bool = False,
    steps: set[Step] | None = None,
) -> int:
    """Run installation."""
    return (
        0
        if Installer(
            verbose=verbose,
            dry_run=dry_run,
            force=force,
            steps=steps or Step.all(),
        ).install()
        else 1
    )


def run_verify() -> int:
    """Verify installation status."""
    installer = Installer()
    installer.print_status()
    return 0 if all(installer.verify().values()) else 1
