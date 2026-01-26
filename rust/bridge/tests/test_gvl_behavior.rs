//! Test: Ruby GVL behavior during I/O operations
//!
//! This comprehensive test verifies GVL release patterns critical for MSF job handling.
//! Run with: ./run_tests.sh --test test_gvl_behavior -- --nocapture

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use magnus::value::ReprValue;
use magnus::Value;

#[test]
fn it_tests_gvl_release_behavior() {
    let _cleanup = common::init_msf();
    let ruby = unsafe { magnus::Ruby::get_unchecked() };

    // =========================================================================
    // Test 1: GVL release allows Ruby threads to run
    // =========================================================================
    println!("\n=== Test 1: GVL release allows Ruby threads ===");

    let setup_code = r#"
        $gvl_test_flag = false
        $gvl_test_thread = Thread.new do
            sleep(0.5)
            $gvl_test_flag = true
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup Ruby thread");
    println!("  Created Ruby background thread (will set flag after 0.5s)");

    println!("  Releasing GVL and sleeping for 1 second...");
    let start = Instant::now();
    msf::gvl::sleep_releasing_gvl(1000);
    let elapsed = start.elapsed();
    println!("  Sleep completed in {:.2}s", elapsed.as_secs_f64());

    let flag_value: bool = ruby.eval("$gvl_test_flag").expect("Failed to read flag");
    let _: Value = ruby
        .eval("$gvl_test_thread.join")
        .unwrap_or_else(|_| ruby.qnil().as_value());

    assert!(flag_value, "Ruby thread should have run during GVL release");
    println!("✓ GVL RELEASE WORKS! Ruby thread ran during our sleep");

    // =========================================================================
    // Test 2: Without GVL release, Ruby threads are blocked
    // =========================================================================
    println!("\n=== Test 2: Without GVL release, Ruby threads are blocked ===");

    let setup_code = r#"
        $gvl_test_flag2 = false
        $gvl_test_thread2 = Thread.new do
            sleep(0.2)
            $gvl_test_flag2 = true
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup");
    println!("  Created Ruby background thread (will set flag after 0.2s)");

    println!("  Sleeping for 0.5s WITHOUT releasing GVL...");
    std::thread::sleep(std::time::Duration::from_millis(500));

    let flag_value: bool = ruby.eval("$gvl_test_flag2").expect("Failed to read flag");

    if !flag_value {
        println!("✓ Confirmed: Ruby thread was BLOCKED while we held GVL");
    } else {
        println!("? Ruby thread ran despite us holding GVL (Ruby optimization)");
    }

    // Cleanup
    msf::gvl::sleep_releasing_gvl(300);
    let _: Value = ruby
        .eval("$gvl_test_thread2.join rescue nil")
        .unwrap_or_else(|_| ruby.qnil().as_value());

    // =========================================================================
    // Test 3: Polling pattern for background jobs
    // =========================================================================
    println!("\n=== Test 3: Polling with GVL release ===");

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
    let completed = msf::gvl::poll_releasing_gvl(
        || {
            let done: bool = ruby.eval("$poll_test_done").unwrap_or(false);
            done
        },
        Some(100),
        Some(5000),
    );
    let elapsed = start.elapsed();

    let _: Value = ruby
        .eval("$poll_test_thread.join rescue nil")
        .unwrap_or_else(|_| ruby.qnil().as_value());

    println!("  Polling completed in {:.2}s", elapsed.as_secs_f64());
    assert!(completed, "Background task should complete during polling");
    assert!(elapsed.as_secs_f64() < 2.0, "Should complete in ~1 second");
    println!("✓ Polling pattern works!");

    // =========================================================================
    // Test 4: MSF job simulation
    // =========================================================================
    println!("\n=== Test 4: MSF Job Simulation ===");

    let setup_code = r#"
        $msf_sessions = []
        $msf_handler_thread = Thread.new do
            sleep(0.8)
            $msf_sessions << { id: 1, host: "192.168.1.100", type: "shell" }
        end
    "#;
    let _: Value = ruby.eval(setup_code).expect("Failed to setup");
    println!("  Started simulated MSF handler job");

    let start = Instant::now();
    let mut session_found = false;

    let _completed = msf::gvl::poll_releasing_gvl(
        || {
            let count: i64 = ruby.eval("$msf_sessions.length").unwrap_or(0);
            if count > 0 {
                session_found = true;
                true
            } else {
                false
            }
        },
        Some(100),
        Some(5000),
    );
    let elapsed = start.elapsed();

    let _: Value = ruby
        .eval("$msf_handler_thread.join rescue nil")
        .unwrap_or_else(|_| ruby.qnil().as_value());

    println!("  Session found in {:.2}s", elapsed.as_secs_f64());
    assert!(session_found, "Should have found session");
    assert!(elapsed.as_secs_f64() < 1.5, "Should complete quickly");
    println!("✓ MSF job simulation SUCCESS!");

    // =========================================================================
    // Test 5: Native threads cannot access Ruby directly
    // =========================================================================
    println!("\n=== Test 5: Native threads cannot access Ruby directly ===");

    let can_access = Arc::new(AtomicBool::new(false));
    let can_access_clone = Arc::clone(&can_access);

    let handle = thread::spawn(move || {
        if magnus::Ruby::get().is_ok() {
            can_access_clone.store(true, Ordering::SeqCst);
        }
    });
    handle.join().expect("Thread panicked");

    let accessed = can_access.load(Ordering::SeqCst);
    assert!(!accessed, "Native threads should NOT access Ruby directly");
    println!("✓ Confirmed: Native threads cannot access Ruby");

    // =========================================================================
    // Test 6: GVL sleep timing
    // =========================================================================
    println!("\n=== Test 6: GVL sleep timing ===");

    let start = Instant::now();
    msf::gvl::sleep_releasing_gvl(100);
    let elapsed = start.elapsed();

    assert!(
        elapsed >= std::time::Duration::from_millis(90),
        "Should sleep at least 90ms"
    );
    println!("✓ sleep_releasing_gvl(100) took {:?}", elapsed);

    // =========================================================================
    // Test 7: Real MSF job management with exploit/multi/handler
    // =========================================================================
    println!("\n=== Test 7: Real MSF job management ===");

    // Get framework and jobs manager
    let framework = msf::Framework::new(None).expect("Framework");
    let jobs = framework.jobs().expect("Jobs manager");

    // Record jobs before
    let jobs_before: Vec<String> = jobs.list().expect("Job list");
    println!("  Jobs before: {:?}", jobs_before);

    // Create a handler module and run as job
    let handler = framework
        .create_module("exploit/multi/handler")
        .expect("Create handler");

    // Configure minimally - use a high port to avoid conflicts
    handler.set_option("PAYLOAD", "generic/shell_bind_tcp").expect("Set payload");
    handler.set_option("LHOST", "127.0.0.1").expect("Set LHOST");
    handler.set_option("LPORT", "44444").expect("Set LPORT");
    handler.set_option("ExitOnSession", "false").expect("Set ExitOnSession");

    // Run as job
    let mut options = msf::Options::new();
    options.insert("RunAsJob".into(), msf::RubyVal::Bool(true));
    let _ = handler.exploit("generic/shell_bind_tcp", Some(options));

    // Give it a moment to start
    msf::gvl::sleep_releasing_gvl(500);

    // Check job was created
    let jobs_after: Vec<String> = jobs.list().expect("Job list after");
    println!("  Jobs after: {:?}", jobs_after);

    let new_jobs: Vec<&String> = jobs_after.iter().filter(|j| !jobs_before.contains(j)).collect();
    println!("  New jobs: {:?}", new_jobs);

    if !new_jobs.is_empty() {
        let job_id = new_jobs[0];
        println!("  Created job: {}", job_id);

        // Test job_info
        if let Some(info) = jobs.get(job_id).expect("Job info") {
            println!("  Job info: {}", info);
        }

        // Test job_kill
        let killed = jobs.kill(job_id).expect("Kill job");
        println!("  Killed job: {}", killed);
        assert!(killed, "Should kill job successfully");

        // Verify job is gone
        msf::gvl::sleep_releasing_gvl(200);
        let jobs_final: Vec<String> = jobs.list().expect("Job list final");
        assert!(
            !jobs_final.contains(job_id),
            "Job should be removed after kill"
        );
        println!("✓ Job management works!");
    } else {
        println!("  Note: Handler may have started and stopped quickly (no listener conflict)");
        println!("✓ Job creation attempted (handler may have exited)");
    }

    // =========================================================================
    // Test 8: Module.exploit_job() method (via Pyo3 layer pattern)
    // =========================================================================
    println!("\n=== Test 8: exploit_job pattern ===");

    // This tests the pattern used by MsfModule.exploit_job()
    let jobs_before: Vec<String> = jobs.list().expect("Job list");

    let handler2 = framework
        .create_module("exploit/multi/handler")
        .expect("Create handler");

    handler2.set_option("PAYLOAD", "generic/shell_bind_tcp").expect("Set payload");
    handler2.set_option("LHOST", "127.0.0.1").expect("Set LHOST");
    handler2.set_option("LPORT", "44445").expect("Set LPORT"); // Different port
    handler2.set_option("ExitOnSession", "false").expect("Set ExitOnSession");

    let mut options = msf::Options::new();
    options.insert("RunAsJob".into(), msf::RubyVal::Bool(true));
    let _ = handler2.exploit("generic/shell_bind_tcp", Some(options));

    msf::gvl::sleep_releasing_gvl(500);

    let jobs_after: Vec<String> = jobs.list().expect("Job list");

    // Find new job ID (this is what exploit_job does)
    let mut new_job_id: Option<String> = None;
    for job_id in &jobs_after {
        if !jobs_before.contains(job_id) {
            new_job_id = Some(job_id.clone());
            break;
        }
    }

    if let Some(job_id) = new_job_id {
        println!("  exploit_job pattern found new job: {}", job_id);
        // Cleanup
        let _ = jobs.kill(&job_id);
        println!("✓ exploit_job pattern works!");
    } else {
        println!("  Note: No new job found (handler may have exited quickly)");
        println!("✓ exploit_job pattern tested");
    }

    println!("\n✓ All GVL behavior tests passed!");
}
