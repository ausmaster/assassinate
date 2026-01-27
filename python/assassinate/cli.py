"""Unified Assassinate CLI with auto-compilation support.

Usage:
    assassinate                    # Check status, auto-compile if needed
    assassinate status             # Detailed status check
    assassinate config [--save]    # Show/save configuration
    assassinate build [--force]    # Build Rust module
    assassinate install [--force]  # Install dependencies via Ansible
    assassinate demo               # Run the demo workflow
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

from assassinate.console import (
    console, icon, warn_icon, print_banner,
    Panel, Table, box,
)
from assassinate.system import (
    detect_msf_root, detect_ruby_manager, detect_ruby_version,
    check_build_tools, get_tool_versions, get_venv_info,
    is_msf_module_installed, Installer, Step,
)


def get_module_version() -> str | None:
    try:
        import msf
        return msf.framework_version()
    except Exception:
        return None


# =============================================================================
# Status Command
# =============================================================================


def cmd_status(args: argparse.Namespace) -> int:
    """Show detailed installation status."""
    issues: list[str] = []

    # Create status table
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Status", style="bold", width=3)
    table.add_column("Component", width=20)
    table.add_column("Details")

    # Python environment
    try:
        from assassinate import __version__
        table.add_row(icon(True), "assassinate", f"v{__version__}")
    except ImportError as e:
        table.add_row(icon(False), "assassinate", f"not installed: {e}")
        issues.append("assassinate package not installed")

    if is_msf_module_installed():
        version = get_module_version()
        table.add_row(icon(True), "msf module", f"MSF {version}" if version else "available")
    else:
        table.add_row(icon(False), "msf module", "not built")
        issues.append("msf module not built (run: assassinate build)")

    # Configuration
    try:
        from assassinate.config import get_config
        config = get_config()
        if config.metasploit.root:
            table.add_row(icon(True), "MSF path", str(config.metasploit.root))
        else:
            table.add_row(icon(False), "MSF path", "not configured")
            issues.append("MSF not found (run: assassinate config)")

        if config.ruby.version:
            table.add_row(icon(True), "Ruby", f"{config.ruby.manager} {config.ruby.version}")
        else:
            table.add_row(warn_icon(), "Ruby", "auto-detect")
    except Exception as e:
        table.add_row(icon(False), "Config", str(e))
        issues.append(f"Configuration error: {e}")

    # Ruby environment
    for tool in ["ruby", "bundle"]:
        if shutil.which(tool):
            try:
                r = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=5)
                ver = r.stdout.strip().split("\n")[0]
                table.add_row(icon(True), tool, ver)
            except Exception:
                table.add_row(warn_icon(), tool, "version unknown")
        else:
            if tool == "ruby":
                table.add_row(icon(False), tool, "not found")
                issues.append("Ruby not installed")
            else:
                table.add_row(warn_icon(), tool, "not found")

    # Venv info
    venv = get_venv_info()
    if venv["in_venv"]:
        table.add_row(icon(True), "venv", f"{venv['venv_type']} at {venv['venv_path']}")
    else:
        table.add_row(warn_icon(), "venv", "not in virtual environment")

    # Build tools
    versions = get_tool_versions()
    for tool, ver in versions.items():
        if ver:
            table.add_row(icon(True), tool, ver)
        else:
            table.add_row(warn_icon(), tool, "not found")

    # Display
    console.print(Panel(table, title="[bold]ASSASSINATE STATUS[/bold]", border_style="cyan"))

    if issues:
        console.print(Panel(
            "\n".join(f"[red]✗[/red] {issue}" for issue in issues),
            title="[bold yellow]ISSUES DETECTED[/bold yellow]",
            border_style="yellow"
        ))
        return 1
    else:
        console.print(Panel(
            "[bold green]All systems operational[/bold green]",
            border_style="green"
        ))
        return 0


# =============================================================================
# Default Command (auto-compile)
# =============================================================================


def cmd_default(args: argparse.Namespace) -> int:
    """Default command - check status, auto-compile if needed."""
    print_banner()

    if is_msf_module_installed():
        console.print(f"  {icon(True)} Assassinate is ready\n")
        return cmd_status(args)

    console.print(f"  {warn_icon()} msf module not built\n")

    tools = check_build_tools()
    missing = [t for t, ok in tools.items() if not ok]

    if missing:
        console.print(f"  {icon(False)} Missing build tools: [cyan]{', '.join(missing)}[/cyan]")
        console.print("\n  Run [cyan]assassinate install[/cyan] to install dependencies")
        return 1

    console.print("  [cyan]→[/cyan] Building msf module...\n")

    with console.status("[bold cyan]Compiling Rust module...[/bold cyan]"):
        start = time.time()
        installer = Installer(verbose=args.verbose, steps={Step.BUILD}, force=True)
        success = installer.run_build()
        elapsed = time.time() - start

    if success:
        console.print(f"\n  {icon(True)} Build complete ({elapsed:.1f}s)")
        console.print("\n  [bold green]Assassinate is ready![/bold green]\n")
        return 0
    else:
        console.print(f"\n  {icon(False)} Build failed")
        console.print("\n  Try running with [cyan]--verbose[/cyan] for details")
        console.print("  Or run [cyan]assassinate install[/cyan] to install dependencies")
        return 1


# =============================================================================
# Config Command
# =============================================================================


def cmd_config(args: argparse.Namespace) -> int:
    """Show and optionally save configuration."""
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Status", width=3)
    table.add_column("Setting", width=15)
    table.add_column("Value")

    msf_root = detect_msf_root()
    if msf_root:
        table.add_row(icon(True), "MSF path", str(msf_root))
    else:
        table.add_row(icon(False), "MSF path", "not found (set ASAS_METASPLOIT__ROOT)")

    ruby_manager = detect_ruby_manager()
    table.add_row(icon(True), "Ruby manager", ruby_manager)

    ruby_version = None
    if msf_root:
        ruby_version = detect_ruby_version(msf_root)
        if ruby_version:
            table.add_row(icon(True), "Ruby version", f"{ruby_version} (from .ruby-version)")
        else:
            table.add_row(warn_icon(), "Ruby version", "not specified in MSF")

    console.print(Panel(table, title="[bold]CONFIGURATION[/bold]", border_style="cyan"))

    # Build config dict
    config_data: dict = {}
    if msf_root:
        config_data["metasploit"] = {"root": str(msf_root)}
    if ruby_manager != "system":
        config_data["ruby"] = {"manager": ruby_manager}
        if ruby_version:
            config_data["ruby"]["version"] = ruby_version

    if config_data:
        try:
            import yaml
            console.print(Panel(
                yaml.safe_dump(config_data, default_flow_style=False).strip(),
                title="[bold]YAML Config[/bold]",
                border_style="dim"
            ))
        except ImportError:
            pass

    if args.save:
        config_path = Path.home() / ".config" / "assassinate" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            import yaml
            config_path.write_text(yaml.safe_dump(config_data, default_flow_style=False))
            console.print(f"\n{icon(True)} Saved to [cyan]{config_path}[/cyan]")
        except ImportError:
            console.print(f"\n{icon(False)} PyYAML not installed")
            return 1
        except Exception as e:
            console.print(f"\n{icon(False)} Failed to save: {e}")
            return 1

    return 0 if msf_root else 1


# =============================================================================
# Build Command
# =============================================================================


def cmd_build(args: argparse.Namespace) -> int:
    """Build the Rust msf module."""
    # Check build tools
    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1))
    table.add_column("Status", width=3)
    table.add_column("Tool", width=10)
    table.add_column("Status")

    tools = check_build_tools()
    all_ok = True
    for tool, ok in tools.items():
        table.add_row(icon(ok), tool, "available" if ok else "not found")
        if not ok:
            all_ok = False

    console.print(Panel(table, title="[bold]BUILD TOOLS[/bold]", border_style="cyan"))

    if not all_ok:
        console.print(f"\n{icon(False)} Missing build tools")
        console.print("Run [cyan]assassinate install[/cyan] to install dependencies")
        return 1

    if not args.force and is_msf_module_installed():
        console.print(f"\n{icon(True)} msf module already built")
        console.print("Use [cyan]--force[/cyan] to rebuild")
        return 0

    console.print("\n[cyan]→[/cyan] Running: maturin develop\n")

    with console.status("[bold cyan]Compiling...[/bold cyan]"):
        start = time.time()
        installer = Installer(verbose=args.verbose, steps={Step.BUILD}, force=args.force)
        success = installer.run_build()
        elapsed = time.time() - start

    if success:
        console.print(Panel(
            f"[bold green]BUILD SUCCESSFUL[/bold green] ({elapsed:.1f}s)",
            border_style="green"
        ))
    else:
        console.print(Panel(
            "[bold red]BUILD FAILED[/bold red]\n\nTry running with [cyan]--verbose[/cyan] for details",
            border_style="red"
        ))
    return 0 if success else 1


# =============================================================================
# Install Command
# =============================================================================


def cmd_install(args: argparse.Namespace) -> int:
    """Install system dependencies via Ansible."""
    steps = Step.all()
    if args.steps:
        steps = Step.parse_list(args.steps)
    if args.skip_steps:
        steps = steps - Step.parse_list(args.skip_steps)

    step_names = ", ".join(s.name.lower() for s in sorted(steps, key=lambda x: x.value))
    console.print(Panel(f"Steps: [cyan]{step_names}[/cyan]", title="[bold]INSTALLER[/bold]", border_style="cyan"))

    installer = Installer(verbose=args.verbose, dry_run=args.dry_run, force=args.force, steps=steps)
    return 0 if installer.install() else 1


# =============================================================================
# Demo Command
# =============================================================================


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the demo workflow."""
    if not is_msf_module_installed():
        console.print(f"{icon(False)} msf module not built")
        console.print("Run [cyan]assassinate build[/cyan] first")
        return 1
    from assassinate.demo import main as demo_main
    demo_main()
    return 0


# =============================================================================
# Main
# =============================================================================


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="assassinate",
        description="Precision exploitation framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    subparsers.add_parser("status", help="Check installation status")

    config_p = subparsers.add_parser("config", help="Show/save configuration")
    config_p.add_argument("--save", action="store_true", help="Save config to file")

    build_p = subparsers.add_parser("build", help="Build the Rust msf module")
    build_p.add_argument("--force", action="store_true", help="Force rebuild")

    install_p = subparsers.add_parser("install", help="Install dependencies via Ansible")
    install_p.add_argument("--force", action="store_true", help="Force reinstall")
    install_p.add_argument("--dry-run", action="store_true", help="Show what would be done")
    install_p.add_argument("--steps", type=str, help="Only run specified steps")
    install_p.add_argument("--skip-steps", type=str, help="Skip specified steps")

    subparsers.add_parser("demo", help="Run the demo workflow")

    args = parser.parse_args()

    commands = {
        None: cmd_default, "status": cmd_status, "config": cmd_config,
        "build": cmd_build, "install": cmd_install, "demo": cmd_demo,
    }

    try:
        return commands[args.command](args)
    except KeyboardInterrupt:
        console.print(f"\n{icon(False)} Interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
