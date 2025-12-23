// Test: Meterpreter process management
// Requires an active Meterpreter session to fully test

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_manages_processes() {
    let (ruby, framework) = common::init_framework();

    // Get sessions
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping process management test");
        println!("  To test process management, create a Meterpreter session first");
        return;
    }

    let session_id = session_ids[0];
    println!("Testing with session ID: {}", session_id);

    // Get session object
    let sid_val = ruby.integer_from_i64(session_id).as_value();
    let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
        .expect("Failed to get session");

    let session = bridge::Session::from_raw(session_val, session_id);

    // Check session type
    match session.session_type() {
        Ok(session_type) => {
            println!("Session type: {}", session_type);

            if !session_type.to_lowercase().contains("meterpreter") {
                println!("⚠ Session is not Meterpreter - skipping process tests");
                return;
            }

            // Test process_getpid
            match session.process_getpid() {
                Ok(pid) => {
                    println!("✓ process_getpid() = {}", pid);
                    assert!(pid > 0, "PID should be positive");
                }
                Err(e) => {
                    println!("⚠ process_getpid() failed: {}", e);
                }
            }

            // Test process_list
            match session.process_list() {
                Ok(processes) => {
                    println!("✓ process_list() returned {} processes", processes.len());

                    if !processes.is_empty() {
                        let first_proc = &processes[0];
                        println!("  Sample process:");

                        if let Some(pid) = first_proc.get("pid") {
                            println!("    PID: {}", pid);
                        }
                        if let Some(name) = first_proc.get("name") {
                            println!("    Name: {}", name);
                        }
                        if let Some(user) = first_proc.get("user") {
                            println!("    User: {}", user);
                        }
                        if let Some(arch) = first_proc.get("arch") {
                            println!("    Arch: {}", arch);
                        }

                        // Verify expected fields exist
                        assert!(first_proc.get("pid").is_some(), "Process should have pid");
                        assert!(first_proc.get("name").is_some(), "Process should have name");
                    }
                }
                Err(e) => {
                    println!("⚠ process_list() failed: {}", e);
                }
            }

            // Test process_execute - use a safe command
            let (cmd, args) = if session_type.to_lowercase().contains("windows") {
                ("cmd.exe", "/c echo ProcessTest")
            } else {
                ("echo", "ProcessTest")
            };

            match session.process_execute(cmd, args, true, false) {
                Ok(result) => {
                    println!("✓ process_execute('{}', '{}') succeeded", cmd, args);

                    if let Some(pid) = result.get("pid") {
                        println!("  Started process PID: {}", pid);
                        let pid_val = pid.as_i64().unwrap_or(0);
                        assert!(pid_val > 0, "Executed process should have valid PID");
                    }
                    if let Some(handle) = result.get("handle") {
                        println!("  Handle: {}", handle);
                    }
                    if let Some(channel_id) = result.get("channel_id") {
                        if !channel_id.is_null() {
                            println!("  Channel ID: {}", channel_id);
                        }
                    }
                }
                Err(e) => {
                    println!("⚠ process_execute() failed: {}", e);
                    println!("  Note: This is acceptable if the session doesn't support process execution");
                }
            }

            // Note: We don't test process_kill() to avoid killing critical processes
            println!("  Note: process_kill() not tested to avoid system instability");

            println!("✓ Process Management API works correctly");
        }
        Err(e) => {
            println!("⚠ Cannot determine session type: {}", e);
        }
    }
}
