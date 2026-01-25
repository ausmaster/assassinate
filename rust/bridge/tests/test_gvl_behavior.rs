//! Test to verify Ruby GVL behavior during I/O operations
//!
//! This test determines if Ruby releases the GVL during network I/O,
//! which is critical for understanding our parallelism options.
//!
//! Run with: ./run_tests.sh --test test_gvl_behavior -- --nocapture

mod common;

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use magnus::value::ReprValue;
use magnus::Value;

/// Test 1: Single-threaded GVL release verification
///
/// This tests that our `rb_thread_call_without_gvl` actually releases the GVL
/// by checking if Ruby's internal operations can proceed during the release.
#[test]
fn test_gvl_release_allows_ruby_threads() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: GVL release allows Ruby threads ===");

    let ruby = unsafe { magnus::Ruby::get_unchecked() };

    // Create a Ruby thread that will set a flag after 0.5 seconds
    // This thread can only run if we release the GVL
    let setup_code = r#"
        $gvl_test_flag = false
        $gvl_test_thread = Thread.new do
            sleep(0.5)
            $gvl_test_flag = true
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup Ruby thread");

    println!("  Created Ruby background thread (will set flag after 0.5s)");

    // Now sleep for 1 second WHILE RELEASING THE GVL
    // If GVL is properly released, the Ruby thread can run and set the flag
    println!("  Releasing GVL and sleeping for 1 second...");
    let start = Instant::now();
    msf::gvl::sleep_releasing_gvl(1000);
    let elapsed = start.elapsed();

    println!("  Sleep completed in {:.2}s", elapsed.as_secs_f64());

    // Check if the Ruby thread was able to run
    let flag_value: bool = ruby
        .eval("$gvl_test_flag")
        .expect("Failed to read flag");

    // Cleanup
    let _: Value = ruby.eval("$gvl_test_thread.join").unwrap_or_else(|_| ruby.qnil().as_value());

    if flag_value {
        println!("✓ GVL RELEASE WORKS! Ruby thread ran during our sleep");
        println!("  This confirms rb_thread_call_without_gvl works correctly");
    } else {
        println!("✗ GVL release did NOT work - Ruby thread couldn't run");
    }

    assert!(flag_value, "Ruby thread should have run during GVL release");
}

/// Test 2: Verify that WITHOUT GVL release, Ruby threads are blocked
///
/// This is the control test - if we DON'T release the GVL, Ruby threads
/// should NOT be able to run.
#[test]
fn test_without_gvl_release_blocks_ruby_threads() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: Without GVL release, Ruby threads are blocked ===");

    let ruby = unsafe { magnus::Ruby::get_unchecked() };

    // Create a Ruby thread that will set a flag after 0.2 seconds
    let setup_code = r#"
        $gvl_test_flag2 = false
        $gvl_test_thread2 = Thread.new do
            sleep(0.2)
            $gvl_test_flag2 = true
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup Ruby thread");

    println!("  Created Ruby background thread (will set flag after 0.2s)");

    // Sleep WITHOUT releasing GVL (Rust sleep, not Ruby sleep)
    // The Ruby thread should NOT be able to run
    println!("  Sleeping for 0.5s WITHOUT releasing GVL...");
    let start = Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let elapsed = start.elapsed();

    println!("  Sleep completed in {:.2}s", elapsed.as_secs_f64());

    // Check if the Ruby thread was able to run (it shouldn't have)
    let flag_value: bool = ruby
        .eval("$gvl_test_flag2")
        .expect("Failed to read flag");

    if !flag_value {
        println!("✓ Confirmed: Ruby thread was BLOCKED while we held GVL");
        println!("  This proves GVL release is necessary for parallelism");
    } else {
        println!("? Unexpected: Ruby thread ran despite us holding GVL");
        println!("  This might indicate Ruby is doing something clever");
    }

    // Cleanup - release GVL briefly so thread can complete
    msf::gvl::sleep_releasing_gvl(300);
    let _: Value = ruby.eval("$gvl_test_thread2.join rescue nil").unwrap_or_else(|_| ruby.qnil().as_value());

    // We expect the flag to be false (thread blocked), but don't fail if Ruby was clever
    println!("  Final flag value: {}", flag_value);
}

/// Test 3: Test polling pattern for background jobs
///
/// This simulates how we'd monitor MSF jobs - polling for completion
/// while periodically releasing the GVL.
#[test]
fn test_poll_releasing_gvl_pattern() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: Polling with GVL release ===");

    let ruby = unsafe { magnus::Ruby::get_unchecked() };

    // Create a Ruby thread that will set a flag after 1 second
    let setup_code = r#"
        $poll_test_done = false
        $poll_test_thread = Thread.new do
            sleep(1)
            $poll_test_done = true
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup");

    println!("  Created background task (completes in 1 second)");
    println!("  Polling every 100ms with GVL release...");

    let start = Instant::now();
    let mut poll_count = 0;

    // Use our poll_releasing_gvl utility
    let completed = msf::gvl::poll_releasing_gvl(
        || {
            poll_count += 1;
            let done: bool = ruby.eval("$poll_test_done").unwrap_or(false);
            done
        },
        100,  // Poll every 100ms
        5000, // 5 second timeout
    );

    let elapsed = start.elapsed();

    // Cleanup
    let _: Value = ruby.eval("$poll_test_thread.join rescue nil").unwrap_or_else(|_| ruby.qnil().as_value());

    println!("  Polling completed:");
    println!("    - Total time: {:.2}s", elapsed.as_secs_f64());
    println!("    - Poll iterations: {}", poll_count);
    println!("    - Task completed: {}", completed);

    if completed && elapsed.as_secs_f64() < 2.0 {
        println!("✓ Polling pattern works! Task completed in reasonable time");
    } else if !completed {
        println!("✗ Task did not complete - GVL release might not be working");
    } else {
        println!("? Task completed but took longer than expected");
    }

    assert!(completed, "Background task should complete during polling");
    assert!(
        elapsed.as_secs_f64() < 2.0,
        "Should complete in ~1 second, took {:.2}s",
        elapsed.as_secs_f64()
    );
}

/// Test 4: Test with actual MSF job simulation
///
/// This creates a simple MSF-like background job and verifies we can
/// monitor it using the GVL release pattern.
#[test]
fn test_msf_job_simulation() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: MSF Job Simulation ===");

    let ruby = unsafe { magnus::Ruby::get_unchecked() };

    // Simulate MSF's job pattern:
    // 1. Create a "handler" that listens for connections
    // 2. Background thread simulates incoming connection
    // 3. Monitor for "session" creation
    let setup_code = r#"
        $msf_sessions = []
        $msf_job_running = true

        # Simulate exploit handler waiting for connection
        $msf_handler_thread = Thread.new do
            # Simulate network delay
            sleep(0.8)
            # "Connection received" - create session
            $msf_sessions << { id: 1, host: "192.168.1.100", type: "shell" }
            $msf_job_running = false
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup MSF simulation");

    println!("  Started simulated MSF handler job");
    println!("  Waiting for 'session' with GVL-releasing poll...");

    let start = Instant::now();
    let mut session_found = false;

    // Poll for session
    let completed = msf::gvl::poll_releasing_gvl(
        || {
            let count: i64 = ruby.eval("$msf_sessions.length").unwrap_or(0);
            if count > 0 {
                session_found = true;
                true
            } else {
                false
            }
        },
        100,  // Poll every 100ms
        5000, // 5 second timeout
    );

    let elapsed = start.elapsed();

    // Get session info
    let session_info: String = ruby
        .eval("$msf_sessions.first&.to_s || 'none'")
        .unwrap_or_else(|_| "error".to_string());

    // Cleanup
    let _: Value = ruby.eval("$msf_handler_thread.join rescue nil").unwrap_or_else(|_| ruby.qnil().as_value());

    println!("  Results:");
    println!("    - Time elapsed: {:.2}s", elapsed.as_secs_f64());
    println!("    - Session found: {}", session_found);
    println!("    - Session info: {}", session_info);

    if session_found && elapsed.as_secs_f64() < 1.5 {
        println!("✓ MSF job simulation SUCCESS!");
        println!("  This pattern will work for real MSF exploit jobs");
    } else {
        println!("✗ MSF job simulation FAILED");
    }

    assert!(session_found, "Should have found session");
    assert!(
        elapsed.as_secs_f64() < 1.5,
        "Should complete quickly, took {:.2}s",
        elapsed.as_secs_f64()
    );
}

/// Test 5: Verify thread-based parallelism won't work directly
///
/// This demonstrates WHY we can't just spawn native threads - they
/// don't have Ruby context.
#[test]
fn test_native_threads_cannot_access_ruby() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: Native threads cannot access Ruby directly ===");
    println!("  This test confirms the limitation we discovered.");

    let can_access = Arc::new(AtomicBool::new(false));
    let error_msg = Arc::new(std::sync::Mutex::new(String::new()));

    let can_access_clone = Arc::clone(&can_access);
    let error_msg_clone = Arc::clone(&error_msg);

    let handle = thread::spawn(move || {
        // Try to get Ruby handle from a native thread
        match magnus::Ruby::get() {
            Ok(_ruby) => {
                can_access_clone.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                *error_msg_clone.lock().unwrap() = format!("{:?}", e);
            }
        }
    });

    handle.join().expect("Thread panicked");

    let accessed = can_access.load(Ordering::SeqCst);
    let err = error_msg.lock().unwrap().clone();

    if !accessed {
        println!("✓ Confirmed: Native threads cannot access Ruby");
        println!("  Error: {}", err);
        println!("  This is expected and explains our earlier test failures");
    } else {
        println!("? Unexpected: Native thread could access Ruby");
    }

    assert!(
        !accessed,
        "Native threads should NOT be able to access Ruby directly"
    );
}

/// Test 6: Explore rb_thread_call_with_gvl possibility
///
/// This tests if we can use rb_thread_call_with_gvl to access Ruby
/// from a native thread (the "correct" way to do cross-thread Ruby access).
#[test]
fn test_native_thread_with_gvl_acquisition() {
    let _cleanup = common::init_msf();

    println!("\n=== Test: Native thread with GVL acquisition ===");
    println!("  Testing if rb_thread_call_with_gvl allows native thread Ruby access...");

    // This is a more advanced test - we'll spawn a native thread and try
    // to use rb_thread_call_with_gvl to safely access Ruby

    let result = Arc::new(AtomicBool::new(false));
    let result_clone = Arc::clone(&result);

    // First, we need to be sure Ruby is fully initialized on main thread
    let ruby = unsafe { magnus::Ruby::get_unchecked() };
    let _: Value = ruby.eval("true").expect("Ruby not working");

    // Now spawn a thread that will try to access Ruby via rb_thread_call_with_gvl
    let handle = thread::spawn(move || {
        // Callback that will run WITH the GVL
        unsafe extern "C" fn ruby_callback(_arg: *mut c_void) -> *mut c_void {
            // Try to access Ruby
            let ruby = magnus::Ruby::get_unchecked();
            match ruby.eval::<Value>("1 + 1") {
                Ok(_) => 1 as *mut c_void,
                Err(_) => std::ptr::null_mut(),
            }
        }

        // Try to acquire GVL and run Ruby code
        let ret = unsafe {
            rb_sys::bindings::uncategorized::rb_thread_call_with_gvl(
                Some(ruby_callback),
                std::ptr::null_mut(),
            )
        };

        result_clone.store(!ret.is_null(), Ordering::SeqCst);
    });

    handle.join().expect("Thread panicked");

    let success = result.load(Ordering::SeqCst);

    if success {
        println!("✓ rb_thread_call_with_gvl WORKS!");
        println!("  Native threads CAN access Ruby by acquiring the GVL");
        println!("  This opens up Tokio-based parallelism possibilities!");
    } else {
        println!("✗ rb_thread_call_with_gvl did not work");
        println!("  Native threads cannot acquire GVL from outside");
    }

    // This test is informational - we want to know the result either way
    println!("\n  Result: Native thread GVL acquisition = {}", success);
}
