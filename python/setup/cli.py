#!/usr/bin/env python3
"""CLI entry point for Assassinate setup operations.

Usage:
    assassinate-setup --install              # Full installation
    assassinate-setup --install --steps packages,rust,build
    assassinate-setup --install --skip-steps msf
    assassinate-setup --verify               # Check installation status
    assassinate-setup --recon-only           # Quick reconnaissance
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Terminal styling
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

CARGO_HOME = "/usr/local/cargo"
RUSTUP_HOME = "/usr/local/rustup"


def icon(ok: bool) -> str:
    return f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"


def warn_icon() -> str:
    return f"{YELLOW}○{RESET}"


def run_install(
    verbose: bool = False,
    dry_run: bool = False,
    force: bool = False,
    steps: str | None = None,
    skip_steps: str | None = None,
) -> int:
    """Run installation with optional step selection."""
    try:
        from setup.installer import Installer, Step
    except ImportError as e:
        print(f"{icon(False)} Failed to import installer: {e}")
        return 1

    # Parse steps
    selected_steps = Step.all()

    if steps:
        try:
            selected_steps = Step.parse_list(steps)
        except KeyError as e:
            print(f"{icon(False)} Invalid step: {e}")
            print(f"Valid steps: {', '.join(s.name.lower() for s in Step)}")
            return 1

    if skip_steps:
        try:
            for step in Step.parse_list(skip_steps):
                selected_steps.discard(step)
        except KeyError as e:
            print(f"{icon(False)} Invalid step to skip: {e}")
            print(f"Valid steps: {', '.join(s.name.lower() for s in Step)}")
            return 1

    installer = Installer(
        verbose=verbose,
        dry_run=dry_run,
        force=force,
        steps=selected_steps,
    )

    return 0 if installer.install() else 1


def run_verify() -> int:
    """Verify installation status."""
    try:
        from setup.installer import Installer
    except ImportError as e:
        print(f"{icon(False)} Failed to import installer: {e}")
        return 1

    installer = Installer()
    installer.print_status()
    return 0 if all(installer.verify().values()) else 1


def setup_rust_env() -> dict[str, str]:
    """Set up environment for system-wide Rust."""
    env = os.environ.copy()
    cargo_bin = Path(CARGO_HOME) / "bin"
    if cargo_bin.exists():
        env["CARGO_HOME"] = CARGO_HOME
        env["RUSTUP_HOME"] = RUSTUP_HOME
        env["PATH"] = f"{cargo_bin}:{env.get('PATH', '')}"
    return env


def run_config(save: bool = False, show: bool = False) -> int:
    """Run configuration wizard - detect environment and optionally save."""
    from pathlib import Path

    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  ASSASSINATE CONFIGURATION{RESET}")
    print(f"{'=' * 60}\n")

    # Import detection functions
    try:
        from assassinate.detection import (
            detect_msf_root,
            detect_ruby_manager,
            detect_ruby_version,
        )
    except ImportError as e:
        print(f"{icon(False)} Failed to import detection module: {e}")
        return 1

    print(f"{BOLD}[1/3] Detecting MSF installation...{RESET}")
    msf_root = detect_msf_root()
    if msf_root:
        print(f"  {icon(True)} Found MSF: {msf_root}")
    else:
        print(f"  {icon(False)} MSF not found")
        print(f"       Set ASAS_METASPLOIT__ROOT or install MSF")

    print(f"\n{BOLD}[2/3] Detecting Ruby environment...{RESET}")
    ruby_manager = detect_ruby_manager()
    print(f"  {icon(True)} Ruby manager: {ruby_manager}")

    ruby_version = None
    if msf_root:
        ruby_version = detect_ruby_version(msf_root)
        if ruby_version:
            print(f"  {icon(True)} Ruby version: {ruby_version} (from .ruby-version)")
        else:
            print(f"  {warn_icon()} Ruby version: not specified in MSF")

    print(f"\n{BOLD}[3/3] Configuration summary...{RESET}")

    # Build config dict
    config_data = {}
    if msf_root:
        config_data["metasploit"] = {"root": str(msf_root)}
    if ruby_manager != "system":
        config_data["ruby"] = {"manager": ruby_manager}
        if ruby_version:
            config_data["ruby"]["version"] = ruby_version

    if show or not save:
        print(f"\n{CYAN}# Current detected configuration:{RESET}")
        try:
            import yaml
            print(yaml.safe_dump(config_data, default_flow_style=False))
        except ImportError:
            print(f"  metasploit.root: {msf_root}")
            print(f"  ruby.manager: {ruby_manager}")
            print(f"  ruby.version: {ruby_version}")

    if save:
        config_path = Path.home() / ".config" / "assassinate" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            import yaml
            with open(config_path, "w") as f:
                yaml.safe_dump(config_data, f, default_flow_style=False)
            print(f"\n{icon(True)} Configuration saved to {config_path}")
        except ImportError:
            print(f"\n{icon(False)} PyYAML not installed, cannot save config")
            print(f"       Install with: pip install pyyaml")
            return 1
        except Exception as e:
            print(f"\n{icon(False)} Failed to save config: {e}")
            return 1

    print(f"\n{'=' * 60}")
    if msf_root:
        print(f"{BOLD}{GREEN}  CONFIGURATION COMPLETE{RESET}")
    else:
        print(f"{BOLD}{YELLOW}  CONFIGURATION INCOMPLETE{RESET}")
        print(f"  MSF installation not found")
    print(f"{'=' * 60}\n")

    return 0 if msf_root else 1


def run_recon(skip_msf: bool = False) -> int:
    """Quick reconnaissance - check what's installed without changes."""
    issues: list[str] = []
    env = setup_rust_env()

    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  HIDEOUT RECONNAISSANCE{RESET}")
    print(f"{'=' * 60}\n")

    # Phase 1: Armory (Build Tools)
    print(f"{BOLD}[1/4] Checking armory...{RESET}")

    for tool, install_hint in [
        ("rustc", "https://rustup.rs/"),
        ("cargo", "https://rustup.rs/"),
        ("capnp", "apt install capnproto / brew install capnp"),
    ]:
        path = shutil.which(tool, path=env.get("PATH"))
        if path:
            result = subprocess.run(
                [tool, "--version"], capture_output=True, text=True, env=env
            )
            version = result.stdout.strip().split("\n")[0]
            print(f"  {icon(True)} {version}")
        else:
            print(f"  {icon(False)} {tool} not found")
            issues.append(f"{tool} not found - {install_hint}")

    # Phase 2: Arsenal (Rust Components)
    print(f"\n{BOLD}[2/4] Checking arsenal...{RESET}")

    rust_dir = PROJECT_ROOT / "rust"
    for component in ["daemon", "bridge", "ipc"]:
        release_dir = rust_dir / component / "target" / "release"
        container_dir = Path("/tmp/cargo-target/release")

        found = False
        if component == "daemon":
            found = (release_dir / "daemon").exists() or (
                container_dir / "daemon"
            ).exists()
        else:
            for check_dir in [release_dir, container_dir]:
                if check_dir.exists() and (
                    list(check_dir.glob("*.rlib"))
                    or list(check_dir.glob(f"lib{component}.*"))
                ):
                    found = True
                    break

        if found:
            print(f"  {icon(True)} {component} built")
        else:
            print(f"  {warn_icon()} {component} needs building")

    # Phase 3: Ruby
    print(f"\n{BOLD}[3/4] Checking contacts...{RESET}")

    for tool in ["ruby", "bundle"]:
        if path := shutil.which(tool):
            result = subprocess.run(
                [tool, "--version"], capture_output=True, text=True
            )
            print(f"  {icon(True)} {result.stdout.strip().split(chr(10))[0]}")
        else:
            status = icon(False) if tool == "ruby" else warn_icon()
            print(f"  {status} {tool} not found")
            if tool == "ruby":
                issues.append("Ruby not installed")

    # Phase 4: MSF
    if not skip_msf:
        print(f"\n{BOLD}[4/4] Checking safehouse...{RESET}")

        msf_locations = [
            os.environ.get("MSF_ROOT"),
            "/usr/share/metasploit-framework",
            "/opt/metasploit-framework",
            str(PROJECT_ROOT / "metasploit-framework"),
            str(Path.home() / "metasploit-framework"),
        ]

        msf_found = None
        for loc in filter(None, msf_locations):
            path = Path(loc)
            if path.exists() and (path / "Gemfile").exists():
                msf_found = path
                break

        if msf_found:
            print(f"  {icon(True)} MSF found: {msf_found}")
        else:
            print(f"  {icon(False)} MSF not found")
            issues.append("Metasploit Framework not installed")
    else:
        print(f"\n{BOLD}[4/4] Safehouse check skipped{RESET}")

    # Summary
    print(f"\n{'=' * 60}")
    if issues:
        print(f"{BOLD}{RED}  ISSUES DETECTED{RESET}")
        print("=" * 60)
        for issue in issues:
            print(f"  {icon(False)} {issue}")
        return 1
    else:
        print(f"{BOLD}{GREEN}  ALL SYSTEMS OPERATIONAL{RESET}")
        print("=" * 60)
        return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Assassinate setup - install dependencies and configure environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Steps (for --steps and --skip-steps):
    packages    System package installation
    rust        Rust toolchain setup
    build       Rust component compilation
    ruby        Ruby/Bundler configuration
    msf         Metasploit Framework setup

Examples:
    assassinate-setup --install                    # Full installation
    assassinate-setup --install --steps rust,build # Only Rust
    assassinate-setup --install --skip-steps msf   # Skip MSF
    assassinate-setup --verify                     # Check status
    assassinate-setup --recon-only                 # Quick check
    assassinate-setup --config                     # Detect and show config
    assassinate-setup --config --save              # Detect and save config
    assassinate-setup --install --force            # Force reinstall
    assassinate-setup --install -v                 # Verbose output
        """,
    )

    # Primary commands (mutually exclusive)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--install",
        action="store_true",
        help="Run installation (recommended)",
    )
    group.add_argument(
        "--verify",
        action="store_true",
        help="Verify installation status",
    )
    group.add_argument(
        "--recon-only",
        "--check-only",
        action="store_true",
        help="Quick reconnaissance without changes",
    )
    group.add_argument(
        "--config",
        action="store_true",
        help="Auto-detect environment and show/save configuration",
    )

    # Step selection
    parser.add_argument(
        "--steps",
        metavar="LIST",
        help="Comma-separated list of steps to run (packages,rust,build,ruby,msf)",
    )
    parser.add_argument(
        "--skip-steps",
        metavar="LIST",
        help="Comma-separated list of steps to skip",
    )

    # Legacy compatibility (hidden)
    parser.add_argument(
        "--skip-msf",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--skip-rust-build",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    # Options
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force reinstallation even if cached",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without doing it",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save detected configuration to ~/.config/assassinate/config.yaml (use with --config)",
    )

    args = parser.parse_args()

    # Handle legacy flags
    skip_steps = args.skip_steps or ""
    if args.skip_msf:
        skip_steps = f"{skip_steps},msf" if skip_steps else "msf"
    if args.skip_rust_build:
        skip_steps = f"{skip_steps},build" if skip_steps else "build"

    # Route to handler
    if args.install:
        return run_install(
            verbose=args.verbose,
            dry_run=args.dry_run,
            force=args.force,
            steps=args.steps,
            skip_steps=skip_steps if skip_steps else None,
        )
    elif args.verify:
        return run_verify()
    elif args.recon_only:
        return run_recon(skip_msf=args.skip_msf)
    elif args.config:
        return run_config(save=args.save, show=True)
    else:
        # Default: run recon
        return run_recon()


if __name__ == "__main__":
    sys.exit(main())
