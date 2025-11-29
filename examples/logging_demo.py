#!/usr/bin/env python3
"""Demo script showing comprehensive logging in action.

This demonstrates both Python and Rust logging working together
to provide full visibility into the IPC communication.

Usage:
    # Run with INFO level (default)
    python logging_demo.py

    # Run with DEBUG level for detailed tracing
    ASSASSINATE_LOG_LEVEL=DEBUG python logging_demo.py
"""

import asyncio
import os
import sys

# Setup logging before importing assassinate
os.environ.setdefault("ASSASSINATE_LOG_LEVEL", "INFO")

from assassinate.ipc.client import MsfClient


async def main():
    """Demonstrate logging capabilities."""
    print("=" * 70)
    print("Assassinate Logging Demo")
    print("=" * 70)
    print(f"Log Level: {os.getenv('ASSASSINATE_LOG_LEVEL', 'INFO')}")
    print()

    async with MsfClient() as client:
        print("\n1. Getting framework version...")
        version = await client.framework_version()
        print(f"   MSF Version: {version['version']}\n")

        print("2. Listing exploit modules...")
        exploits = await client.list_modules("exploit")
        print(f"   Found {len(exploits)} exploits\n")

        print("3. Searching for 'vsftpd'...")
        results = await client.search("vsftpd")
        print(f"   Found {len(results)} modules\n")

        print("4. Creating a module instance...")
        if results:
            module_id = await client.create_module(results[0])
            print(f"   Created module: {module_id}")

            print("5. Getting module info...")
            info = await client.module_info(module_id)
            print(f"   Module name: {info['name']}")
            print(f"   Module type: {info['type']}")

            print("\n6. Cleaning up module...")
            deleted = await client.delete_module(module_id)
            print(f"   Module deleted: {deleted}\n")

    print("\n" + "=" * 70)
    print("Demo completed successfully!")
    print("=" * 70)
    print("\nLogging Features:")
    print("  ✓ Connection/disconnection tracking")
    print("  ✓ Request/response lifecycle")
    print("  ✓ Performance metrics (timing)")
    print("  ✓ Error handling and context")
    print("  ✓ Call ID tracking for correlation")
    print("\nTry running with DEBUG level:")
    print("  ASSASSINATE_LOG_LEVEL=DEBUG python examples/logging_demo.py")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
