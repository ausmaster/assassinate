"""Entry point for `python -m assassinate` and the `assassinate` CLI command.

This module provides the main entry point for the unified Assassinate CLI,
which handles:
- Auto-detection of the compiled msf module
- Auto-compilation using maturin if the module is missing
- Installation of system dependencies via Ansible
- Status checks and configuration management

Usage:
    python -m assassinate              # Check status, auto-compile if needed
    python -m assassinate status       # Detailed status check
    python -m assassinate config       # Show detected configuration
    python -m assassinate build        # Build the Rust module
    python -m assassinate install      # Install system dependencies
    python -m assassinate demo         # Run the demo (requires msf module)

Example:
    $ python -m assassinate
    Checking Assassinate installation...
      ✓ Rust toolchain: rustc 1.88.0
      ✓ Ruby: rvm 3.3.8
      ✓ MSF: /home/user/Projects/metasploit-framework
      ○ msf module: not built

    Building Rust module...
      → Running: maturin develop
      ✓ Build complete (23.4s)

    Assassinate is ready!
"""

from __future__ import annotations

import sys


def main() -> int:
    """Main entry point - delegates to cli.main()."""
    from assassinate.cli import main as cli_main

    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
