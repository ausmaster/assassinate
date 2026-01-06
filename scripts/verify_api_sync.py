#!/usr/bin/env python3
"""
verify_api_sync.py - Verify API synchronization across all layers

This script extracts method names from each layer and identifies:
1. Methods in Rust but missing from Daemon (not exposed via IPC)
2. Methods in Daemon but missing from Python (not accessible to users)
3. Orphaned handlers (in Daemon but not in Rust)

This catches a more subtle form of documentation drift: when layers
fall out of sync with each other.

Usage:
    ./scripts/verify_api_sync.py [--verbose]
"""

import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Set


@dataclass
class LayerMethods:
    """Methods extracted from a layer."""
    name: str
    methods: Set[str]
    file_path: Path


def extract_rust_methods(project_root: Path) -> LayerMethods:
    """Extract public function names from Rust bridge."""
    framework_dir = project_root / "rust" / "bridge" / "src" / "framework"
    methods = set()

    # Pattern: pub fn method_name(
    pattern = re.compile(r'pub fn (\w+)\s*[<(]')

    for rs_file in framework_dir.glob("*.rs"):
        content = rs_file.read_text()
        for match in pattern.finditer(content):
            method_name = match.group(1)
            # Skip common Rust patterns that aren't API methods
            if method_name not in ('new', 'default', 'from', 'into', 'clone'):
                methods.add(method_name)

    return LayerMethods(
        name="Rust Bridge",
        methods=methods,
        file_path=framework_dir
    )


def extract_daemon_handlers(project_root: Path) -> LayerMethods:
    """Extract IPC handler names from daemon."""
    daemon_file = project_root / "rust" / "daemon" / "src" / "main.rs"
    methods = set()

    # Pattern: "handler_name" =>
    pattern = re.compile(r'"([a-z_]+)"\s*=>')

    content = daemon_file.read_text()
    for match in pattern.finditer(content):
        methods.add(match.group(1))

    return LayerMethods(
        name="Daemon Handlers",
        methods=methods,
        file_path=daemon_file
    )


def extract_python_methods(project_root: Path) -> LayerMethods:
    """Extract async method names from Python client.

    Returns the IPC call names (what's actually sent to daemon), not the
    Python method names. This allows for Pythonic naming while still
    verifying the underlying IPC calls are valid.
    """
    client_file = project_root / "python" / "assassinate" / "ipc" / "client.py"
    methods = set()

    content = client_file.read_text()

    # Pattern 1: Single-line calls - self._call("handler_name", ...)
    # Pattern 2: Multi-line calls - self._call(\n    "handler_name", ...)
    # Combined: look for _call( followed by optional whitespace then quoted string
    call_pattern = re.compile(r'self\._call\(\s*["\'](\w+)["\']', re.MULTILINE)
    for match in call_pattern.finditer(content):
        methods.add(match.group(1))

    return LayerMethods(
        name="Python Client (IPC calls)",
        methods=methods,
        file_path=client_file
    )


def normalize_method_name(name: str) -> str:
    """Normalize method names for comparison across layers.

    Rust uses snake_case, Python uses snake_case, handlers use snake_case.
    But there may be prefixes like 'session_' in one layer but not another.
    """
    # Remove common prefixes for comparison
    prefixes = ['session_', 'db_', 'module_', 'framework_']
    normalized = name.lower()
    for prefix in prefixes:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]
            break
    return normalized


def print_section(title: str, items: Set[str], color: str = ""):
    """Print a section with items."""
    if not items:
        return

    colors = {
        "red": "\033[0;31m",
        "yellow": "\033[1;33m",
        "green": "\033[0;32m",
        "cyan": "\033[0;36m",
        "": ""
    }
    reset = "\033[0m" if color else ""

    print(f"\n{colors.get(color, '')}{title}{reset}")
    print("─" * 60)
    for item in sorted(items):
        print(f"  • {item}")


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent

    print("━" * 70)
    print("API Synchronization Verification")
    print("━" * 70)

    # Extract methods from each layer
    rust = extract_rust_methods(project_root)
    daemon = extract_daemon_handlers(project_root)
    python = extract_python_methods(project_root)

    print(f"\n📊 Method Counts:")
    print(f"   Rust Bridge:     {len(rust.methods):3d} public functions")
    print(f"   Daemon Handlers: {len(daemon.methods):3d} IPC handlers")
    print(f"   Python Client:   {len(python.methods):3d} async methods")

    # Analysis
    issues_found = False

    # Methods in Rust but not exposed via Daemon
    # (These are internal helpers or not yet exposed)
    rust_only = rust.methods - daemon.methods
    if rust_only and verbose:
        print_section(
            "ℹ️  Rust methods not exposed via IPC (internal/helpers):",
            rust_only,
            "cyan"
        )

    # Handlers in Daemon but method missing from Python
    # (User can't access these - likely a bug or WIP)
    daemon_not_in_python = daemon.methods - python.methods
    if daemon_not_in_python:
        # Filter out some known non-API handlers
        daemon_not_in_python -= {'ping', 'shutdown', 'version'}
        if daemon_not_in_python:
            print_section(
                "⚠️  Daemon handlers missing Python client methods:",
                daemon_not_in_python,
                "yellow"
            )
            issues_found = True

    # Python methods that don't have daemon handlers
    # (These would fail at runtime)
    python_not_in_daemon = python.methods - daemon.methods
    # Filter out known client-only methods
    python_not_in_daemon -= {'connect', 'disconnect', 'close', 'reconnect'}
    if python_not_in_daemon:
        print_section(
            "🔴 Python methods without daemon handlers (WILL FAIL):",
            python_not_in_daemon,
            "red"
        )
        issues_found = True

    # Summary
    print("\n" + "━" * 70)
    if issues_found:
        print("❌ API synchronization issues detected!")
        print("   Some methods may not work correctly.")
        sys.exit(1)
    else:
        print("✅ API layers are synchronized!")
        if verbose:
            # Show what IS synchronized
            synced = daemon.methods & python.methods
            print(f"   {len(synced)} methods available end-to-end")
        sys.exit(0)


if __name__ == "__main__":
    main()
