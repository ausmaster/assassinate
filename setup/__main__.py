"""Allow running setup as a module: python -m setup"""

from setup.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
