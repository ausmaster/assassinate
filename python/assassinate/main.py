"""Main entry point for the assassination framework.

This module demonstrates basic hideout operations and framework connectivity.
"""

from assassinate.assassinate.hideout import Hideout


def main() -> None:
    """Initialize hideout and demonstrate framework capabilities."""
    # Establish the hideout (operational headquarters)
    with Hideout() as hideout:
        # Verify framework connection
        if hideout.framework is None:
            print("❌ Framework connection failed")
            return

        print(f"🎯 Hideout established - Framework v{hideout.version}")
        print()

        # Gather intel on available modules
        print("📋 Gathering intel on available modules...")
        exploits = hideout.framework.list_modules("exploits")
        auxiliary = hideout.framework.list_modules("auxiliary")
        payloads = hideout.framework.list_modules("payloads")

        print(f"  • Exploits:  {len(exploits)} available")
        print(f"  • Auxiliary: {len(auxiliary)} available")
        print(f"  • Payloads:  {len(payloads)} available")
        print()

        # Display sample exploits
        if exploits:
            print("🔫 Sample exploits in arsenal:")
            for exploit in exploits[:5]:
                print(f"  → {exploit}")
            if len(exploits) > 5:
                print(f"  ... and {len(exploits) - 5} more")
        print()

        print("✓ Mission briefing complete")


if __name__ == "__main__":
    main()
