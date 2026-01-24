//! GVL (Global VM Lock) utilities for Ruby thread interop
//!
//! Ruby's GVL means only one thread can execute Ruby code at a time.
//! When embedding Ruby in Rust/Python, background Ruby threads (like MSF jobs)
//! cannot run while we hold the GVL.
//!
//! This module provides utilities to temporarily release the GVL, allowing
//! Ruby background threads to execute.

use std::ffi::c_void;
use std::time::Duration;

/// Callback function that runs WITHOUT the GVL held.
/// This allows other Ruby threads to execute while we sleep.
unsafe extern "C" fn sleep_callback(data: *mut c_void) -> *mut c_void {
    let duration_ms = data as u64;
    std::thread::sleep(Duration::from_millis(duration_ms));
    std::ptr::null_mut()
}

/// Sleep while releasing the Ruby GVL, allowing background Ruby threads to run.
///
/// This is essential for MSF's job system to work when Ruby is embedded.
/// Without releasing the GVL, background jobs (created with RunAsJob=true)
/// can never execute because they can't acquire the GVL.
///
/// # Safety
/// This function is safe to call from Ruby thread context.
/// Do NOT call Ruby APIs during the sleep - the GVL is not held.
///
/// # Arguments
/// * `duration_ms` - How long to sleep in milliseconds
///
/// # Example
/// ```ignore
/// // Create a background job
/// let job_id = module.exploit_job(payload)?;
///
/// // Release GVL so the job can run
/// sleep_releasing_gvl(1000); // Sleep 1 second, job can execute
///
/// // Check for sessions (GVL re-acquired automatically)
/// let sessions = framework.sessions()?.list()?;
/// ```
pub fn sleep_releasing_gvl(duration_ms: u64) {
    unsafe {
        rb_sys::bindings::uncategorized::rb_thread_call_without_gvl(
            Some(sleep_callback),
            duration_ms as *mut c_void,
            None, // No unblock function needed for simple sleep
            std::ptr::null_mut(),
        );
    }
}

/// Poll for a condition while releasing the GVL between checks.
///
/// This repeatedly:
/// 1. Releases GVL and sleeps for `interval_ms`
/// 2. Re-acquires GVL and calls `check_fn`
/// 3. Returns if `check_fn` returns true or timeout reached
///
/// # Arguments
/// * `check_fn` - Function to check condition (called WITH GVL held)
/// * `interval_ms` - Sleep interval between checks
/// * `timeout_ms` - Total timeout in milliseconds
///
/// # Returns
/// `true` if condition was met, `false` if timeout
pub fn poll_releasing_gvl<F>(mut check_fn: F, interval_ms: u64, timeout_ms: u64) -> bool
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(timeout_ms);

    loop {
        // Check condition (with GVL held)
        if check_fn() {
            return true;
        }

        // Check timeout
        if start.elapsed() >= timeout {
            return false;
        }

        // Calculate remaining time
        let remaining = timeout.saturating_sub(start.elapsed());
        let sleep_time = Duration::from_millis(interval_ms).min(remaining);

        if sleep_time.is_zero() {
            return false;
        }

        // Release GVL and sleep (Ruby threads can run!)
        sleep_releasing_gvl(sleep_time.as_millis() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_releasing_gvl() {
        // This test just verifies the function doesn't crash
        // Real testing requires Ruby VM to be initialized
        let start = std::time::Instant::now();
        sleep_releasing_gvl(100);
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(90)); // Allow some tolerance
    }
}
