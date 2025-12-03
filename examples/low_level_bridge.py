"""Example usage of the low-level assassinate.bridge API.

This demonstrates direct usage of the Metasploit Framework bridge without
the high-level Python interface. Use this when you need full control or
the high-level API doesn't provide necessary functionality.

Requirements:
    - Metasploit Framework installed (e.g., /opt/metasploit-framework)
    - assassinate_bridge Rust module compiled
    - PostgreSQL running (for full MSF functionality)
"""

from __future__ import annotations

from assassinate.bridge import (
    DataStore,
    Framework,
    Module,
    PayloadGenerator,
    Session,
    SessionManager,
    get_version,
    initialize,
)


def main() -> None:
    """Demonstrate low-level bridge API usage."""
    # Initialize MSF (required before any operations)
    msf_path = "/opt/metasploit-framework"
    print(f"Initializing Metasploit from {msf_path}...")  # noqa: T201
    initialize(msf_path)

    # Get MSF version without creating framework
    version = get_version()
    print(f"MSF Version: {version}\n")  # noqa: T201

    # Create framework instance
    print("Creating framework...")  # noqa: T201
    fw = Framework()
    print(f"Framework: {fw}\n")  # noqa: T201

    # List available modules
    print("Listing modules...")  # noqa: T201
    exploits = fw.list_modules("exploits")
    auxiliary = fw.list_modules("auxiliary")
    payloads = fw.list_modules("payloads")

    print(f"  Exploits:  {len(exploits)}")  # noqa: T201
    print(f"  Auxiliary: {len(auxiliary)}")  # noqa: T201
    print(f"  Payloads:  {len(payloads)}\n")  # noqa: T201

    # Show first 5 exploits
    print("Sample exploits:")  # noqa: T201
    for exploit in exploits[:5]:
        print(f"  - {exploit}")  # noqa: T201
    print()  # noqa: T201

    # Create and configure a module
    module_name = "exploit/unix/ftp/vsftpd_234_backdoor"
    print(f"Creating module: {module_name}")  # noqa: T201
    mod: Module = fw.create_module(module_name)

    print(f"  Name:        {mod.name()}")  # noqa: T201
    print(f"  Full name:   {mod.fullname()}")  # noqa: T201
    print(f"  Type:        {mod.module_type()}")  # noqa: T201
    print(f"  Description: {mod.description()[:100]}...")  # noqa: T201
    print()  # noqa: T201

    # Configure module options via datastore
    print("Configuring module options...")  # noqa: T201
    ds: DataStore = mod.datastore()
    ds.set("RHOSTS", "192.168.1.100")
    ds.set("RPORT", "21")

    print(f"  RHOSTS: {ds.get('RHOSTS')}")  # noqa: T201
    print(f"  RPORT:  {ds.get('RPORT')}")  # noqa: T201
    print(f"  Case-insensitive: rhosts = {ds.get('rhosts')}\n")  # noqa: T201

    # Module validation and execution
    print("Module validation and execution...")  # noqa: T201
    is_valid = mod.validate()
    print(f"  Module valid: {is_valid}")  # noqa: T201

    if mod.has_check():
        print(f"  Module supports check: {mod.has_check()}")  # noqa: T201

    compatible = mod.compatible_payloads()
    print(f"  Compatible payloads: {len(compatible)}")  # noqa: T201
    if compatible:
        print(f"    First payload: {compatible[0]}")  # noqa: T201
    print()  # noqa: T201

    # DataStore to dictionary
    print("DataStore to dictionary...")  # noqa: T201
    ds_dict = ds.to_dict()
    print(f"  DataStore as dict: {ds_dict}\n")  # noqa: T201

    # Global framework datastore
    print("Framework global datastore...")  # noqa: T201
    global_ds: DataStore = fw.datastore()
    global_ds.set("WORKSPACE", "default")
    print(f"  WORKSPACE: {global_ds.get('WORKSPACE')}\n")  # noqa: T201

    # Session management
    print("Session manager...")  # noqa: T201
    sm: SessionManager = fw.sessions()
    session_ids = sm.list()
    print(f"  Active sessions: {len(session_ids)}")  # noqa: T201

    if session_ids:
        sess: Session | None = sm.get(session_ids[0])
        if sess:
            print(f"  Session info: {sess.info()}")  # noqa: T201
            print(f"  Alive: {sess.alive()}")  # noqa: T201
            print(f"  Session type: {sess.session_type()}")  # noqa: T201
            print(f"  Description: {sess.desc()}")  # noqa: T201
            print(f"  Target host: {sess.target_host()}")  # noqa: T201
            print(f"  Tunnel peer: {sess.tunnel_peer()}")  # noqa: T201

            if sess.alive():
                try:
                    output = sess.execute("whoami")
                    print(f"  Command output: {output}")  # noqa: T201
                except RuntimeError as e:
                    print(f"  Command failed: {e}")  # noqa: T201
    print()  # noqa: T201

    # Demonstrate module types
    print("Creating different module types...")  # noqa: T201

    # Auxiliary module
    aux_mod = fw.create_module("auxiliary/scanner/http/title")
    print(f"  Auxiliary: {aux_mod.name()}")  # noqa: T201
    aux_ds: DataStore = aux_mod.datastore()
    aux_ds.set("RHOSTS", "192.168.1.100")

    # Payload module
    payload_mod = fw.create_module("payload/linux/x86/shell_reverse_tcp")
    print(f"  Payload: {payload_mod.name()}\n")  # noqa: T201

    # Payload generation
    print("Payload generation...")  # noqa: T201
    pg: PayloadGenerator = PayloadGenerator(fw)

    available_payloads = pg.list_payloads()
    print(f"  Total payloads: {len(available_payloads)}")  # noqa: T201
    print("  Sample payloads:")  # noqa: T201
    for p in available_payloads[:3]:
        print(f"    - {p}")  # noqa: T201
    print()  # noqa: T201

    print("\nLow-level bridge example complete!")  # noqa: T201


if __name__ == "__main__":
    main()
