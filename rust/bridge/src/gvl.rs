//! GVL (Global VM Lock) utilities for Ruby thread interop
//!
//! Ruby's GVL means only one thread can execute Ruby code at a time.
//! When embedding Ruby in Rust/Python, background Ruby threads (like MSF jobs)
//! cannot run while we hold the GVL.
//!
//! This module provides utilities to temporarily release the GVL, allowing
//! Ruby background threads to execute.

use log::trace;
use std::time::Duration;

/// Default polling interval: 100ms
/// Balances responsiveness with CPU efficiency.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 100;

/// Default timeout: 60 seconds
/// Standard timeout for exploit operations.
pub const DEFAULT_POLL_TIMEOUT_MS: u64 = 60_000;

/// Poll for a condition while releasing the GVL between checks.
///
/// This is the primary GVL release mechanism. It repeatedly:
/// 1. Checks the condition with `check_fn` (GVL held)
/// 2. If true, returns immediately
/// 3. If false, releases GVL and sleeps for `interval_ms`
/// 4. Repeats until condition met or timeout reached
///
/// Uses Ruby's native `rb_thread_wait_for` which properly releases the GVL
/// during sleep, allowing background Ruby threads (like MSF jobs) to execute.
///
/// # Arguments
/// * `check_fn` - Function to check condition (called WITH GVL held)
/// * `interval_ms` - Sleep interval between checks (default: 100ms)
/// * `timeout_ms` - Total timeout (default: 60s, 0 = no timeout)
///
/// # Returns
/// `true` if condition was met, `false` if timeout
///
/// # Example
/// ```ignore
/// // Wait for a session to appear
/// let found = poll_releasing_gvl(
///     || !framework.sessions().unwrap().list().unwrap().is_empty(),
///     None,  // Use default 100ms interval
///     None,  // Use default 60s timeout
/// );
/// ```
pub fn poll_releasing_gvl<F>(
    mut check_fn: F,
    interval_ms: Option<u64>,
    timeout_ms: Option<u64>,
) -> bool
where
    F: FnMut() -> bool,
{
    let interval = Duration::from_millis(interval_ms.unwrap_or(DEFAULT_POLL_INTERVAL_MS));
    let timeout_ms = timeout_ms.unwrap_or(DEFAULT_POLL_TIMEOUT_MS);
    let timeout = if timeout_ms == 0 {
        None // No timeout
    } else {
        Some(Duration::from_millis(timeout_ms))
    };

    trace!(target: "msf::gvl", "poll_releasing_gvl starting (interval: {:?}, timeout: {:?})", interval, timeout);

    let start = std::time::Instant::now();
    let mut iterations = 0u64;

    loop {
        iterations += 1;

        // Check condition (with GVL held)
        if check_fn() {
            trace!(target: "msf::gvl", "poll_releasing_gvl: condition met after {} iterations ({:?})", iterations, start.elapsed());
            return true;
        }

        // Check timeout (if set)
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                trace!(target: "msf::gvl", "poll_releasing_gvl: timeout after {} iterations ({:?})", iterations, start.elapsed());
                return false;
            }
        }

        // Calculate sleep time
        let sleep_duration = if let Some(t) = timeout {
            let remaining = t.saturating_sub(start.elapsed());
            interval.min(remaining)
        } else {
            interval
        };

        if sleep_duration.is_zero() {
            trace!(target: "msf::gvl", "poll_releasing_gvl: sleep_duration is zero, returning false");
            return false;
        }

        // Release GVL and sleep (Ruby threads can run!)
        // CRITICAL: Must wrap in protect() to handle Ruby exceptions/signals safely.
        // Without this, signals from killed sessions cause segfaults.
        trace!(target: "msf::gvl", "poll_releasing_gvl: releasing GVL for {:?} (iteration {})", sleep_duration, iterations);
        let tv = rb_sys::timeval {
            tv_sec: sleep_duration.as_secs() as _,
            tv_usec: sleep_duration.subsec_micros() as _,
        };
        let _ = magnus::rb_sys::protect(|| {
            unsafe { rb_sys::rb_thread_wait_for(tv) };
            rb_sys::Qnil as rb_sys::VALUE
        });
    }
}

/// Simple sleep while releasing the GVL.
///
/// This is a convenience wrapper around `poll_releasing_gvl` for when you
/// just need to sleep without checking a condition.
///
/// # Arguments
/// * `duration_ms` - How long to sleep in milliseconds
///
/// # Example
/// ```ignore
/// // Sleep for 1 second, allowing Ruby background threads to run
/// sleep_releasing_gvl(1000);
/// ```
#[inline]
pub fn sleep_releasing_gvl(duration_ms: u64) {
    poll_releasing_gvl(|| false, Some(duration_ms), Some(duration_ms));
}

// Note: GC control functions (gc_disable, gc_enable, with_gc_disabled) were removed
// in favor of BoxValue<T> which properly registers Ruby values with the GC.
// See: https://github.com/matsadler/magnus for BoxValue documentation.
