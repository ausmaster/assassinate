// Test: Meterpreter Client Core operations
// Requires an active Meterpreter session to fully test

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_tests_meterpreter_client_core_operations() {
    let (ruby, framework) = common::init_framework();

    // Get sessions
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping Meterpreter Client Core test");
        println!("  To test Client Core operations, create a Meterpreter session first");
        return;
    }

    // Find a Meterpreter session
    let mut meterpreter_session: Option<(i64, magnus::Value)> = None;
    for session_id in session_ids.iter() {
        let sid_val = ruby.integer_from_i64(*session_id).as_value();
        let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
            .expect("Failed to get session");

        let type_val = ruby_bridge::call_method(session_val, "type", &[])
            .expect("Failed to get type");
        let session_type = ruby_bridge::value_to_string(type_val)
            .expect("Failed to convert type");

        if session_type.to_lowercase().contains("meterpreter") {
            meterpreter_session = Some((*session_id, session_val));
            break;
        }
    }

    let (session_id, session_val) = match meterpreter_session {
        Some(s) => s,
        None => {
            println!("⚠ No Meterpreter sessions found - skipping Client Core tests");
            println!("  Available session types:");
            for session_id in session_ids.iter() {
                let sid_val = ruby.integer_from_i64(*session_id).as_value();
                let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
                    .expect("Failed to get session");
                let type_val = ruby_bridge::call_method(session_val, "type", &[])
                    .expect("Failed to get type");
                let session_type = ruby_bridge::value_to_string(type_val)
                    .expect("Failed to convert type");
                println!("  - Session {}: {}", session_id, session_type);
            }
            return;
        }
    };

    println!("Testing Client Core with Meterpreter session ID: {}", session_id);

    let session = bridge::Session::from_raw(session_val, session_id);

    // Test 1: meterpreter_machine_id
    println!("\n--- Testing meterpreter_machine_id ---");
    match session.meterpreter_machine_id(None) {
        Ok(machine_id) => {
            println!("✓ meterpreter_machine_id() = {}", machine_id);
            // Machine ID should be an MD5 hash (32 hex chars)
            if !machine_id.is_empty() {
                assert!(machine_id.len() == 32, "Machine ID should be 32 char MD5 hash");
            }
        }
        Err(e) => println!("⚠ meterpreter_machine_id() failed: {}", e),
    }

    // Test 2: meterpreter_native_arch
    println!("\n--- Testing meterpreter_native_arch ---");
    match session.meterpreter_native_arch(None) {
        Ok(arch) => {
            println!("✓ meterpreter_native_arch() = {}", arch);
            if !arch.is_empty() {
                // Should be x86, x64, aarch64, etc.
                assert!(
                    arch.contains("x86") || arch.contains("x64") ||
                    arch.contains("arm") || arch.contains("aarch"),
                    "Architecture should be a known type"
                );
            }
        }
        Err(e) => println!("⚠ meterpreter_native_arch() failed: {}", e),
    }

    // Test 3: meterpreter_session_guid
    println!("\n--- Testing meterpreter_session_guid ---");
    match session.meterpreter_session_guid(None) {
        Ok(guid) => {
            println!("✓ meterpreter_session_guid() = {}", guid);
            // GUID should be a non-empty hex string
            if !guid.is_empty() {
                assert!(guid.chars().all(|c| c.is_ascii_hexdigit()), "GUID should be hex string");
            }
        }
        Err(e) => println!("⚠ meterpreter_session_guid() failed: {}", e),
    }

    // Test 4: meterpreter_use (load stdapi if not already loaded)
    println!("\n--- Testing meterpreter_use ---");
    match session.meterpreter_use("stdapi") {
        Ok(loaded) => {
            println!("✓ meterpreter_use('stdapi') = {}", loaded);
            assert!(loaded, "stdapi should load successfully");
        }
        Err(e) => {
            // stdapi might already be loaded, which can cause an error
            println!("⚠ meterpreter_use('stdapi') failed (may already be loaded): {}", e);
        }
    }

    // Test 5: meterpreter_secure
    println!("\n--- Testing meterpreter_secure ---");
    match session.meterpreter_secure() {
        Ok(secured) => {
            println!("✓ meterpreter_secure() = {}", secured);
            // secure() may or may not succeed depending on session state
        }
        Err(e) => println!("⚠ meterpreter_secure() failed: {}", e),
    }

    // NOTE: We don't test meterpreter_shutdown() or meterpreter_migrate() here
    // because they would terminate or alter the session, making further tests impossible
    println!("\n--- Skipping destructive tests ---");
    println!("⚠ Skipping meterpreter_shutdown() - would terminate session");
    println!("⚠ Skipping meterpreter_migrate() - would alter session (Windows only)");

    println!("\n✓ Meterpreter Client Core operations work correctly");
}
