from __future__ import annotations

import argparse
from assassinate.core.bullet import list_bullets, get_bullet

def main() -> None:
    """
    Command-line interface for loading and formatting bullet.
    """
    parser = argparse.ArgumentParser(description="Assassinate Bullet Loader")
    parser.add_argument("--list", action="store_true", help="List available bullet")
    parser.add_argument("--bullet", help="Bullet name")
    parser.add_argument("--lhost", help="Local host/IP")
    parser.add_argument("--lport", type=int, help="Local port")
    parser.add_argument("--format", default="raw", help="Output format")
    args = parser.parse_args()

    if args.list:
        for name, desc in list_bullets():
            print(f"{name}: {desc}")
        return

    bullet = get_bullet(args.bullet)
    if bullet is None:
        print("Invalid bullet name. Use --list to see available bullet.")
        return

    if args.lhost is None or args.lport is None:
        print("Both --lhost and --lport are required for this bullet.")
        return

    raw = bullet.load(lhost=args.lhost, lport=args.lport)
    formatted = bullet.chamber(raw, fmt=args.format)
    print(formatted)

if __name__ == "__main__":
    main()
