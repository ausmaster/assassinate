"""Example usage of the assassinate bridge API.

This demonstrates usage of the Metasploit Framework bridge through the
IPC architecture. Shows both synchronous and asynchronous APIs.

Requirements:
    - Metasploit Framework installed (e.g., /opt/metasploit-framework)
    - assassinate daemon running (see README.md)
    - PostgreSQL running (for full MSF functionality)
"""

from __future__ import annotations


def sync_example() -> None:
    """Demonstrate synchronous API usage."""
    from assassinate.bridge import Framework, initialize

    print("=== Synchronous API Example ===\n")

    # Connect to daemon (no MSF path needed - daemon handles that)
    print("Connecting to assassinate daemon...")
    initialize()

    # Create framework instance
    print("Creating framework...")
    fw = Framework()
    print(f"MSF Version: {fw.version()}\n")

    # List available modules
    print("Listing modules...")
    exploits = fw.list_modules("exploit")
    print(f"  Exploits: {len(exploits)}")

    # Show first 5 exploits
    print("\nSample exploits:")
    for exploit in exploits[:5]:
        print(f"  - {exploit}")
    print()

    # Create and configure a module
    module_name = "exploit/unix/ftp/vsftpd_234_backdoor"
    print(f"Creating module: {module_name}")
    mod = fw.create_module(module_name)
    print(f"  Module type: {mod.module_type()}")
    print()

    # Configure module options via datastore
    print("Configuring module options...")
    ds = mod.datastore()
    ds.set("RHOSTS", "192.168.1.100")
    ds.set("RPORT", "21")

    print(f"  RHOSTS: {ds.get('RHOSTS')}")
    print(f"  RPORT: {ds.get('RPORT')}")
    print()

    # Session management
    print("Session manager...")
    sm = fw.sessions()
    session_ids = sm.list()
    print(f"  Active sessions: {len(session_ids)}")
    print()

    print("Synchronous example complete!\n")


async def async_example() -> None:
    """Demonstrate asynchronous API usage."""
    from assassinate.bridge.async_api import AsyncFramework, initialize

    print("=== Asynchronous API Example ===\n")

    # Connect to daemon
    print("Connecting to assassinate daemon...")
    await initialize()

    # Create framework instance
    print("Creating framework...")
    fw = AsyncFramework()
    version = await fw.version()
    print(f"MSF Version: {version}\n")

    # List available modules
    print("Listing modules...")
    exploits = await fw.list_modules("exploit")
    print(f"  Exploits: {len(exploits)}")

    # Show first 5 exploits
    print("\nSample exploits:")
    for exploit in exploits[:5]:
        print(f"  - {exploit}")
    print()

    # Create and configure a module
    module_name = "exploit/unix/ftp/vsftpd_234_backdoor"
    print(f"Creating module: {module_name}")
    mod = await fw.create_module(module_name)
    mod_type = await mod.module_type()
    print(f"  Module type: {mod_type}")
    print()

    # Configure module options via datastore
    print("Configuring module options...")
    ds = await mod.datastore()
    await ds.set("RHOSTS", "192.168.1.100")
    await ds.set("RPORT", "21")

    rhosts = await ds.get("RHOSTS")
    rport = await ds.get("RPORT")
    print(f"  RHOSTS: {rhosts}")
    print(f"  RPORT: {rport}")
    print()

    # Session management
    print("Session manager...")
    sm = await fw.sessions()
    session_ids = await sm.list()
    print(f"  Active sessions: {len(session_ids)}")
    print()

    print("Asynchronous example complete!\n")


def main() -> None:
    """Run both synchronous and asynchronous examples."""
    import asyncio

    # Run synchronous example
    sync_example()

    # Run asynchronous example
    asyncio.run(async_example())


if __name__ == "__main__":
    main()
