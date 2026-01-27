"""Unified system operations for Assassinate.

Consolidates: MSF detection, Ruby environment, venv detection, build tools,
and Ansible-based dependency installation.

Usage:
    from assassinate.system import (
        detect_msf_root, detect_ruby_manager, get_ruby_env,
        find_tool, check_build_tools, Installer, Step,
    )
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import site
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Literal

from assassinate.console import console, Panel, Table, box

log = logging.getLogger("assassinate.system")

# =============================================================================
# Constants
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CACHE_DIR = PROJECT_ROOT / ".installer_cache"
CARGO_HOME = "/usr/local/cargo"
RUSTUP_HOME = "/usr/local/rustup"
MSF_CLONE_PATH = "/opt/metasploit-framework"
MSF_CLONE_URL = "https://github.com/rapid7/metasploit-framework.git"
SECURITY_DISTROS = ("Kali", "Parrot")

# Ansible condition helpers
OS_FAMILY = "ansible_facts['os_family']"
DISTRO = "ansible_facts['distribution']"

# Common MSF installation paths
MSF_SEARCH_PATHS = [
    Path("/opt/metasploit-framework"),
    Path("/opt/metasploit-framework/embedded/framework"),
    Path("/usr/share/metasploit-framework"),
    Path.home() / "Projects" / "metasploit-framework",
    Path.home() / "metasploit-framework",
    Path.home() / "git" / "metasploit-framework",
    Path.home() / "src" / "metasploit-framework",
    Path("/opt/homebrew/Cellar/metasploit"),
    Path("/usr/local/Cellar/metasploit"),
]

# =============================================================================
# MSF Detection
# =============================================================================

_msf_root_cache: Path | None | bool = False  # False = not cached


def detect_msf_root(use_cache: bool = True) -> Path | None:
    """Auto-detect MSF installation path. Results cached by default."""
    global _msf_root_cache
    if use_cache and _msf_root_cache is not False:
        return _msf_root_cache

    result = None

    # Check environment variables first
    for env_var in ["ASAS_METASPLOIT__ROOT", "MSF_ROOT"]:
        if loc := os.environ.get(env_var):
            path = Path(loc).expanduser()
            if is_valid_msf_root(path):
                result = path.resolve()
                break

    # Check common paths
    if not result:
        for path in MSF_SEARCH_PATHS:
            expanded = path.expanduser()
            if expanded.exists() and (expanded / "Gemfile").exists():
                result = expanded.resolve()
                break

    # Check msfconsole in PATH
    if not result and (msfconsole := shutil.which("msfconsole")):
        potential = Path(msfconsole).resolve().parent
        if (potential / "Gemfile").exists():
            result = potential

    _msf_root_cache = result
    return result


def is_valid_msf_root(path: Path | str) -> bool:
    """Check if path is a valid MSF installation."""
    p = Path(path).expanduser()
    return p.exists() and (p / "Gemfile").exists() and (p / "lib" / "msf").exists()


# =============================================================================
# Ruby Detection & Environment
# =============================================================================


def detect_ruby_manager() -> Literal["rvm", "rbenv", "system"]:
    """Detect Ruby version manager (rvm, rbenv, or system)."""
    rvm_path = Path.home() / ".rvm"
    if rvm_path.exists():
        if shutil.which("rvm") or (rvm_path / "bin" / "rvm").exists():
            return "rvm"
        if (rvm_path / "scripts" / "rvm").exists():
            return "rvm"

    rbenv_path = Path.home() / ".rbenv"
    if rbenv_path.exists() and (shutil.which("rbenv") or (rbenv_path / "bin" / "rbenv").exists()):
        return "rbenv"
    if shutil.which("rbenv"):
        return "rbenv"

    return "system"


def detect_ruby_version(msf_root: Path | str) -> str | None:
    """Read Ruby version from MSF's .ruby-version file."""
    ruby_file = Path(msf_root).expanduser() / ".ruby-version"
    if not ruby_file.exists():
        return None
    try:
        version = ruby_file.read_text().strip()
        return version[5:] if version.startswith("ruby-") else version
    except Exception:
        return None


def is_ruby_version_installed(version: str, manager: str = "auto") -> bool:
    """Check if a Ruby version is installed."""
    if manager == "auto":
        manager = detect_ruby_manager()

    if manager == "rvm":
        return (Path.home() / ".rvm" / "rubies" / f"ruby-{version}").exists()
    elif manager == "rbenv":
        return (Path.home() / ".rbenv" / "versions" / version).exists()
    else:
        if not shutil.which("ruby"):
            return False
        try:
            result = subprocess.run(["ruby", "--version"], capture_output=True, text=True, timeout=5)
            return version in result.stdout
        except Exception:
            return False


def get_ruby_env(
    manager: Literal["rvm", "rbenv", "system"],
    version: str | None = None,
    msf_root: Path | str | None = None,
) -> dict[str, str]:
    """Get environment variables for Ruby execution."""
    env = os.environ.copy()

    if manager == "rvm" and version:
        rvm = Path.home() / ".rvm"
        gem_home = rvm / "gems" / f"ruby-{version}"
        env.update({
            "GEM_HOME": str(gem_home),
            "GEM_PATH": f"{gem_home}:{rvm}/gems/ruby-{version}@global",
            "MY_RUBY_HOME": str(rvm / "rubies" / f"ruby-{version}"),
            "RUBY_VERSION": f"ruby-{version}",
            "PATH": f"{gem_home}/bin:{rvm}/rubies/ruby-{version}/bin:{rvm}/bin:{env.get('PATH', '')}",
        })
    elif manager == "rbenv" and version:
        rbenv = Path.home() / ".rbenv"
        env.update({
            "RBENV_VERSION": version,
            "RBENV_ROOT": str(rbenv),
            "PATH": f"{rbenv}/shims:{rbenv}/bin:{env.get('PATH', '')}",
        })
        ver_root = rbenv / "versions" / version
        if ver_root.exists():
            gem_dir = ver_root / "lib" / "ruby" / "gems"
            if gem_dir.exists() and (gems := list(gem_dir.glob("*"))):
                env["GEM_HOME"] = env["GEM_PATH"] = str(gems[0])

    if msf_root:
        gemfile = Path(msf_root).expanduser() / "Gemfile"
        if gemfile.exists():
            env["BUNDLE_GEMFILE"] = str(gemfile)
            env["BUNDLE_WITHOUT"] = "development:test"

    return env


def get_rvm_command(version: str) -> list[str]:
    """Get command prefix for RVM (e.g., ['rvm', '3.3.8', 'do'])."""
    return ["rvm", version, "do"]


def get_full_ruby_env(
    msf_root: Path | str | None = None,
    ruby_version: str | None = None,
    ruby_manager: Literal["rvm", "rbenv", "system", "auto"] = "auto",
) -> dict[str, str]:
    """Get complete Ruby environment with auto-detection."""
    if msf_root is None:
        msf_root = detect_msf_root()
    if ruby_manager == "auto":
        ruby_manager = detect_ruby_manager()
    if ruby_version is None and msf_root:
        ruby_version = detect_ruby_version(msf_root)
    return get_ruby_env(ruby_manager, ruby_version, msf_root)


# =============================================================================
# Virtual Environment & Tool Detection
# =============================================================================


@lru_cache(maxsize=1)
def get_venv_info() -> dict[str, Any]:
    """Detect virtual environment information. Cached."""
    venv_path = venv_type = None

    if hasattr(sys, "real_prefix"):
        venv_type, venv_path = "virtualenv", Path(sys.prefix)
    elif sys.base_prefix != sys.prefix:
        venv_type, venv_path = "venv", Path(sys.prefix)
    elif os.environ.get("CONDA_PREFIX"):
        venv_type, venv_path = "conda", Path(os.environ["CONDA_PREFIX"])
    elif os.environ.get("VIRTUAL_ENV"):
        venv_type, venv_path = "venv", Path(os.environ["VIRTUAL_ENV"])

    venv_bin = None
    if venv_path:
        for name in ["bin", "Scripts"]:
            if (d := venv_path / name).exists():
                venv_bin = d
                break

    return {"in_venv": venv_path is not None, "venv_path": venv_path, "venv_bin": venv_bin, "venv_type": venv_type}


def find_tool(name: str) -> Path | None:
    """Find a tool, checking venv bin first, then system PATH."""
    venv = get_venv_info()
    if venv["venv_bin"]:
        for suffix in ["", ".exe"]:
            if (tool := venv["venv_bin"] / f"{name}{suffix}").exists():
                return tool
    if path := shutil.which(name):
        return Path(path)
    return None


def _check_maturin_module() -> tuple[bool, str | None]:
    """Check maturin availability via python -m."""
    try:
        r = subprocess.run([sys.executable, "-m", "maturin", "--version"], capture_output=True, text=True, timeout=5)
        return (True, r.stdout.strip()) if r.returncode == 0 else (False, None)
    except Exception:
        return False, None


def check_build_tools() -> dict[str, bool]:
    """Check if rustc, cargo, and maturin are available."""
    maturin_ok = find_tool("maturin") is not None or _check_maturin_module()[0]
    return {"rustc": find_tool("rustc") is not None, "cargo": find_tool("cargo") is not None, "maturin": maturin_ok}


def get_tool_versions() -> dict[str, str | None]:
    """Get versions of build tools."""
    versions: dict[str, str | None] = {}
    for tool in ["rustc", "cargo"]:
        if path := find_tool(tool):
            try:
                r = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=5)
                versions[tool] = r.stdout.strip().split("\n")[0]
            except Exception:
                versions[tool] = "unknown"
        else:
            versions[tool] = None

    if path := find_tool("maturin"):
        try:
            r = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=5)
            versions["maturin"] = r.stdout.strip()
        except Exception:
            versions["maturin"] = "unknown"
    else:
        ok, ver = _check_maturin_module()
        versions["maturin"] = ver if ok else None
    return versions


# =============================================================================
# Build Environment & Module Status
# =============================================================================


def get_build_env() -> dict[str, str]:
    """Get environment for build (Ruby + bindgen flags)."""
    from assassinate.config import get_config
    config = get_config()
    env = os.environ.copy()
    env.update(get_ruby_env(config.ruby.manager, config.ruby.version, config.metasploit.root))
    env["BINDGEN_EXTRA_CLANG_ARGS"] = "-std=gnu11 -include stdbool.h"
    return env


def is_msf_module_installed() -> bool:
    """Check if the msf module is importable."""
    try:
        import msf
        return True
    except ImportError:
        return False


def get_so_path() -> Path | None:
    """Find the compiled .so file location."""
    for site_dir in site.getsitepackages() + [site.getusersitepackages()]:
        if site_dir and (p := Path(site_dir)).exists():
            for so in p.glob("msf.cpython-*.so"):
                return so
    for so in (PROJECT_ROOT / "python" / "msf").glob("msf.cpython-*.so"):
        return so
    return None


def clean_build() -> bool:
    """Remove build artifacts."""
    success = True
    for target in [PROJECT_ROOT / "target", PROJECT_ROOT / "rust/bridge/target", PROJECT_ROOT / ".maturin_build_cache"]:
        if target.exists():
            try:
                shutil.rmtree(target)
            except Exception:
                success = False
    for so in (PROJECT_ROOT / "python" / "msf").glob("*.so"):
        try:
            so.unlink()
        except Exception:
            success = False
    return success


def clear_detection_cache() -> None:
    """Clear all detection caches."""
    global _msf_root_cache
    _msf_root_cache = False
    get_venv_info.cache_clear()


# =============================================================================
# Installation Steps & Package Definitions
# =============================================================================


class Step(Enum):
    """Installation steps."""
    PACKAGES = auto()
    RUST = auto()
    PYTHON = auto()
    RUBY = auto()
    MSF = auto()
    BUILD = auto()

    @classmethod
    def all(cls) -> set[Step]:
        return set(cls)

    @classmethod
    def from_string(cls, s: str) -> Step:
        return cls[s.upper()]

    @classmethod
    def parse_list(cls, s: str) -> set[Step]:
        return {cls.from_string(x.strip()) for x in s.split(",") if x.strip()}


# Package definitions per distro family
DISTRO_PACKAGES: dict[str, dict[str, tuple[str, ...]]] = {
    "Debian": {
        "build": ("build-essential", "git", "curl", "cmake"),
        "rust_deps": ("libssl-dev", "pkg-config", "libclang-dev"),
        "ruby": ("ruby-full", "ruby-dev", "ruby-bundler"),
        "ruby_build": ("libyaml-dev", "libffi-dev", "libpq-dev"),
        "msf": ("metasploit-framework",),
    },
    "RedHat": {
        "build": ("gcc", "gcc-c++", "make", "git", "curl", "cmake"),
        "rust_deps": ("openssl-devel", "pkgconf-pkg-config", "clang-devel"),
        "ruby": ("ruby", "ruby-devel", "rubygem-bundler"),
        "ruby_build": ("libyaml-devel", "libffi-devel", "postgresql-devel"),
    },
    "Archlinux": {
        "build": ("base-devel", "git", "curl", "cmake"),
        "rust_deps": ("openssl", "pkgconf", "clang"),
        "ruby": ("ruby", "ruby-bundler"),
        "ruby_build": ("libyaml", "libffi", "postgresql-libs"),
        "rust": ("rust",),
    },
    "Suse": {
        "build": ("gcc", "gcc-c++", "make", "git", "curl", "cmake"),
        "rust_deps": ("libopenssl-devel", "pkg-config", "clang-devel"),
        "ruby": ("ruby", "ruby-devel"),
        "ruby_build": ("libyaml-devel", "libffi-devel", "postgresql-devel"),
    },
    "Darwin": {
        "build": ("git", "cmake"),
        "rust_deps": ("openssl", "pkg-config", "llvm"),
        "ruby": ("ruby",),
        "ruby_build": ("libyaml", "libffi", "postgresql"),
    },
}


def _all_packages(family: str) -> list[str]:
    """Get all packages for a distro family (excluding msf)."""
    pkgs = DISTRO_PACKAGES.get(family, {})
    return [p for k in ["build", "rust_deps", "ruby", "ruby_build", "rust"] for p in pkgs.get(k, ())]


# =============================================================================
# Ansible Task Helpers
# =============================================================================


def _task(module: str, name: str, args: dict[str, Any], **opts: Any) -> dict[str, Any]:
    """Create an Ansible task dict."""
    task: dict[str, Any] = {"name": name, f"ansible.builtin.{module}": args}
    for k, v in opts.items():
        if v is not None:
            task[k] = v
    return task


def _shell(name: str, cmd: str, **opts: Any) -> dict[str, Any]:
    """Create a shell task."""
    args: dict[str, Any] = {"cmd": cmd}
    if chdir := opts.pop("chdir", None):
        args["chdir"] = str(chdir)
    task = _task("shell", name, args, **opts)
    if env := opts.get("environment"):
        task["environment"] = env
    return task


def _package_task(name: str, packages: list[str], family: str, **opts: Any) -> dict[str, Any]:
    """Create a package installation task."""
    task: dict[str, Any] = {
        "name": name,
        "become": True,
        "when": f"{OS_FAMILY} == '{family}'",
        "ignore_errors": opts.get("ignore_errors", True),
    }
    if family == "Darwin":
        task["community.general.homebrew"] = {"name": packages, "state": "present"}
        task.pop("become")
    else:
        task["package"] = {"name": packages, "state": "present"}
    if when := opts.get("when"):
        task["when"] = when
    return task


# =============================================================================
# Ansible Task Generators
# =============================================================================


def generate_package_tasks() -> list[dict[str, Any]]:
    """Generate package installation tasks."""
    return [_package_task(f"Install packages ({f})", _all_packages(f), f) for f in DISTRO_PACKAGES]


def generate_rust_tasks() -> list[dict[str, Any]]:
    """Generate Rust installation tasks."""
    env = {"CARGO_HOME": CARGO_HOME, "RUSTUP_HOME": RUSTUP_HOME}
    not_arch = f"{OS_FAMILY} != 'Archlinux'"
    needs = f"{not_arch} and rustc_check.rc != 0"

    return [
        _package_task("Install Rust (Arch)", ["rust"], "Archlinux"),
        _task("command", "Check for existing rustc", {"cmd": "which rustc"},
              register="rustc_check", ignore_errors=True, changed_when=False, when=not_arch),
        _task("get_url", "Download rustup", {"url": "https://sh.rustup.rs", "dest": "/tmp/rustup.sh", "mode": "0755"}, when=needs),
        _shell("Install Rust via rustup", "/tmp/rustup.sh -y --default-toolchain stable --no-modify-path",
               environment=env, become=True, when=needs),
        _shell("Set Rust default toolchain", f"{CARGO_HOME}/bin/rustup default stable",
               environment=env, become=True, when=needs, ignore_errors=True),
        {"name": "Create Rust symlinks", "ansible.builtin.file": {
            "src": f"{CARGO_HOME}/bin/{{{{ item }}}}", "dest": "/usr/local/bin/{{ item }}", "state": "link", "force": True
        }, "loop": ["rustc", "cargo", "rustup"], "become": True, "when": not_arch, "ignore_errors": True},
        _task("copy", "Create Rust profile script", {
            "dest": "/etc/profile.d/rust.sh", "mode": "0644",
            "content": f'export CARGO_HOME="{CARGO_HOME}"\nexport RUSTUP_HOME="{RUSTUP_HOME}"\nexport PATH="{CARGO_HOME}/bin:$PATH"\n'
        }, become=True, when=not_arch),
    ]


def generate_python_tasks() -> list[dict[str, Any]]:
    """Generate Python tool (maturin) installation tasks."""
    return [_task("pip", "Install maturin", {"name": ["maturin"], "state": "present"}, ignore_errors=True)]


def generate_ruby_tasks() -> list[dict[str, Any]]:
    """Generate Ruby/Bundler setup tasks."""
    return [
        _task("copy", "Create Arch gem PATH script", {
            "dest": "/etc/profile.d/ruby-gems.sh", "mode": "0644",
            "content": 'if command -v ruby &>/dev/null; then\n  export PATH="$(ruby -e \'puts Gem.user_dir\')/bin:$PATH"\nfi\n'
        }, become=True, when=f"{OS_FAMILY} == 'Archlinux'"),
        _shell("Install xmlrpc gem", "gem install xmlrpc --no-document", become=True, ignore_errors=True),
        _shell("Install bundler gem", "gem install bundler --no-document", become=True, ignore_errors=True),
    ]


def generate_msf_tasks() -> list[dict[str, Any]]:
    """Generate MSF installation tasks."""
    is_sec = f"{DISTRO} in {list(SECURITY_DISTROS)}"
    not_sec = f"{DISTRO} not in {list(SECURITY_DISTROS)}"
    return [
        _task("stat", "Check for package MSF", {"path": "/usr/share/metasploit-framework/Gemfile"}, register="msf_pkg"),
        _task("stat", "Check for cloned MSF", {"path": f"{MSF_CLONE_PATH}/Gemfile"}, register="msf_cloned"),
        _package_task("Install MSF package (Kali/Parrot)", ["metasploit-framework"], "Debian",
                      when=f"{is_sec} and not msf_pkg.stat.exists"),
        {"name": "Clone Metasploit Framework", "ansible.builtin.git": {
            "repo": MSF_CLONE_URL, "dest": MSF_CLONE_PATH, "depth": 1, "force": False
        }, "become": True, "when": f"{not_sec} and not msf_pkg.stat.exists and not msf_cloned.stat.exists"},
    ]


def generate_bundle_tasks(msf_root: str) -> list[dict[str, Any]]:
    """Generate MSF bundle install tasks."""
    return [
        _shell("Check MSF bundle status", "bundle check", chdir=msf_root,
               register="bundle_check", ignore_errors=True, changed_when=False),
        _shell("Install MSF gems (10-15 minutes)", "bundle install --jobs 1 --retry 3",
               chdir=msf_root, become=True, when="bundle_check.rc != 0", timeout=1800),
    ]


def generate_build_tasks() -> list[dict[str, Any]]:
    """Generate maturin build tasks."""
    env = {
        "CARGO_HOME": CARGO_HOME, "RUSTUP_HOME": RUSTUP_HOME,
        "PATH": f"{CARGO_HOME}/bin:/usr/local/bin:/usr/bin:/bin",
        "BINDGEN_EXTRA_CLANG_ARGS": "-std=gnu11 -include stdbool.h",
    }
    try:
        env.update(get_full_ruby_env())
    except Exception:
        pass
    return [_shell("Build msf module with maturin", f"{sys.executable} -m maturin develop",
                   chdir=PROJECT_ROOT, environment=env, timeout=600)]


# =============================================================================
# Installer Class
# =============================================================================


@dataclass
class Installer:
    """Ansible-based dependency installer."""
    verbose: bool = False
    dry_run: bool = False
    force: bool = False
    steps: set[Step] = field(default_factory=Step.all)
    _cache: dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._load_cache()
        os.environ.setdefault("ANSIBLE_TIMEOUT", "300")

    def _load_cache(self) -> None:
        try:
            self._cache = json.loads((CACHE_DIR / "status.json").read_text())
        except Exception:
            self._cache = {}

    def _save_cache(self) -> None:
        (CACHE_DIR / "status.json").write_text(json.dumps(self._cache, indent=2))

    def _is_cached(self, key: str) -> bool:
        return self._cache.get(key, False) and not self.force

    def _mark_done(self, key: str) -> None:
        self._cache[key] = True
        self._save_cache()

    def _run_ansible(self, tasks: list[dict[str, Any]], name: str) -> tuple[bool, str]:
        """Execute Ansible tasks."""
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
                inventory={"all": {"hosts": {"localhost": {
                    "ansible_connection": "local", "ansible_python_interpreter": sys.executable
                }}}},
                quiet=not self.verbose,
                verbosity=2 if self.verbose else 0,
                envvars={**os.environ, "PATH": f"{Path(sys.executable).parent}:{os.environ.get('PATH', '')}"},
            )
            if result.status == "successful":
                return True, ""
            for event in result.events:
                if event.get("event") == "runner_on_failed":
                    return False, event.get("event_data", {}).get("res", {}).get("msg", "Unknown error")
            return False, "Unknown failure"
        except Exception as e:
            return False, str(e)
        finally:
            if not self.verbose:
                shutil.rmtree(data_dir, ignore_errors=True)

    def _run_step(self, step: Step, name: str, cache_key: str,
                  gen: Callable[[], list[dict[str, Any]]], warn_only: bool = False) -> bool:
        """Generic step runner."""
        if step not in self.steps:
            return True
        if self._is_cached(cache_key):
            log.info(f"{name} (cached)")
            return True

        log.info(f"Running {name}...")
        ok, err = self._run_ansible(gen(), cache_key)
        if ok:
            self._mark_done(cache_key)
            log.info(f"{name} complete")
        elif warn_only:
            log.warning(f"{name}: {err}")
            return True
        else:
            log.error(f"{name} failed: {err}")
        return ok

    def run_packages(self) -> bool:
        return self._run_step(Step.PACKAGES, "System packages", "packages", generate_package_tasks, warn_only=True)

    def run_rust(self) -> bool:
        return self._run_step(Step.RUST, "Rust toolchain", "rust", generate_rust_tasks)

    def run_python(self) -> bool:
        return self._run_step(Step.PYTHON, "Python build tools", "python", generate_python_tasks, warn_only=True)

    def run_ruby(self) -> bool:
        return self._run_step(Step.RUBY, "Ruby environment", "ruby", generate_ruby_tasks, warn_only=True)

    def run_build(self) -> bool:
        if Step.BUILD not in self.steps:
            return True
        if is_msf_module_installed() and not self.force:
            log.info("msf module (already built)")
            return True
        return self._run_step(Step.BUILD, "msf module", "build", generate_build_tasks)

    def run_msf(self) -> bool:
        if Step.MSF not in self.steps:
            return True
        if self._is_cached("msf"):
            log.info("MSF configured (cached)")
            return True

        log.info("Setting up Metasploit Framework...")
        ok, err = self._run_ansible(generate_msf_tasks(), "msf_install")
        if not ok:
            log.warning(f"MSF install: {err}")

        if msf_root := detect_msf_root():
            log.info(f"  Found: {msf_root}")
            if "/usr/share" in str(msf_root):
                log.info("  Package MSF (pre-bundled)")
            elif (msf_root / "Gemfile").exists():
                log.info("  Installing gems (10-15 min)...")
                ok, err = self._run_ansible(generate_bundle_tasks(str(msf_root)), "msf_bundle")
                if not ok:
                    log.warning(f"  Bundle: {err}")
                    return False
                log.info("  Gems installed")
            self._mark_done("msf")
            return True

        log.warning("MSF not found after installation")
        return False

    def install(self) -> bool:
        """Run installation."""
        step_names = ", ".join(s.name.lower() for s in sorted(self.steps, key=lambda x: x.value))
        console.print(Panel(f"Steps: [cyan]{step_names}[/cyan]", title="[bold]ASSASSINATE INSTALLER[/bold]", border_style="cyan"))

        runners = [
            (Step.PACKAGES, self.run_packages), (Step.RUST, self.run_rust),
            (Step.PYTHON, self.run_python), (Step.RUBY, self.run_ruby),
            (Step.MSF, self.run_msf), (Step.BUILD, self.run_build),
        ]
        success = all(run() for step, run in runners if step in self.steps)

        if success:
            console.print(Panel("[bold green]INSTALLATION COMPLETE[/bold green]\nAssassinate is ready to use!", border_style="green"))
        else:
            console.print(Panel("[bold yellow]INSTALLATION INCOMPLETE[/bold yellow]", border_style="yellow"))
        return success

    def verify(self) -> dict[str, bool]:
        """Verify installation status."""
        tools = check_build_tools()
        return {
            "rustc": tools["rustc"], "cargo": tools["cargo"], "maturin": tools["maturin"],
            "ruby": find_tool("ruby") is not None, "bundler": find_tool("bundle") is not None,
            "msf_module": is_msf_module_installed(), "msf": detect_msf_root() is not None,
        }

    def print_status(self) -> None:
        """Print installation status."""
        status = self.verify()
        table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
        table.add_column("Status", width=6)
        table.add_column("Component")

        for name, ok in status.items():
            icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
            table.add_row(icon, name)

        console.print(Panel(table, title="[bold]Installation Status[/bold]", border_style="cyan"))

        if all(status.values()):
            console.print("[green]All components installed[/green]")
        else:
            missing = ", ".join(k for k, v in status.items() if not v)
            console.print(f"[yellow]Missing: {missing}[/yellow]")


# =============================================================================
# CLI Entry Points
# =============================================================================


def run_install(verbose: bool = False, dry_run: bool = False, force: bool = False, steps: set[Step] | None = None) -> int:
    """Run installation."""
    return 0 if Installer(verbose=verbose, dry_run=dry_run, force=force, steps=steps or Step.all()).install() else 1


def run_verify() -> int:
    """Verify installation status."""
    installer = Installer()
    installer.print_status()
    return 0 if all(installer.verify().values()) else 1


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    "PROJECT_ROOT", "MSF_SEARCH_PATHS",
    "detect_msf_root", "is_valid_msf_root",
    "detect_ruby_manager", "detect_ruby_version", "is_ruby_version_installed",
    "get_ruby_env", "get_rvm_command", "get_full_ruby_env", "get_build_env",
    "get_venv_info", "find_tool", "check_build_tools", "get_tool_versions",
    "is_msf_module_installed", "get_so_path", "clean_build", "clear_detection_cache",
    "Step", "DISTRO_PACKAGES", "Installer", "run_install", "run_verify",
]
