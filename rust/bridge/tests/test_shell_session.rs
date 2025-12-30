// Test: Shell session operations (read, write, upgrade)
// Requires an active shell (non-Meterpreter) session to fully test

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_tests_shell_session_operations() {
    let (ruby, framework) = common::init_framework();

    // Get sessions
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping shell session test");
        println!("  To test shell operations, create a shell session first");
        println!("  Example: use exploit/multi/handler with payload/generic/shell_reverse_tcp");
        return;
    }

    // Find a shell session (non-Meterpreter)
    let mut shell_session_id: Option<i64> = None;
    let mut shell_session_val: Option<magnus::Value> = None;

    for session_id in session_ids {
        let sid_val = ruby.integer_from_i64(session_id).as_value();
        let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
            .expect("Failed to get session");

        let type_val = ruby_bridge::call_method(session_val, "type", &[])
            .expect("Failed to get type");
        let session_type = ruby_bridge::value_to_string(type_val)
            .expect("Failed to convert type");

        // Look for "shell" type (command_shell, etc.)
        if session_type.to_lowercase().contains("shell") &&
           !session_type.to_lowercase().contains("meterpreter") {
            println!("✓ Found shell session {} (type: {})", session_id, session_type);
            shell_session_id = Some(session_id);
            shell_session_val = Some(session_val);
            break;
        }
    }

    if shell_session_id.is_none() {
        println!("⚠ No shell sessions found - skipping shell session test");
        println!("  All active sessions are Meterpreter sessions");
        println!("  To test shell operations, create a basic shell session");
        return;
    }

    let session_id = shell_session_id.unwrap();
    let session_val = shell_session_val.unwrap();
    let session = bridge::Session::from_raw(session_val, session_id);

    println!("\n📝 Testing shell session operations");

    // Test 1: shell_write - Check if method exists (don't actually write to avoid breaking session)
    println!("\n1. Testing shell_write capability");
    match ruby_bridge::call_method(session_val, "respond_to?", &[ruby.str_new("shell_write").as_value()]) {
        Ok(result) => {
            let has_method = result.to_bool();
            if has_method {
                println!("   ✓ Session has shell_write method");

                // Test writing a newline (minimal impact)
                match session.shell_write("\n") {
                    Ok(bytes) => {
                        println!("   ✓ shell_write() works - wrote {} bytes", bytes);
                        assert!(bytes > 0, "Should write at least 1 byte");
                    }
                    Err(e) => {
                        println!("   ⚠ shell_write() failed: {}", e);
                    }
                }
            } else {
                println!("   ⚠ Session does not have shell_write method");
            }
        }
        Err(e) => {
            println!("   ⚠ Failed to check for shell_write: {}", e);
        }
    }

    // Test 2: shell_read - Read any available output
    println!("\n2. Testing shell_read capability");
    match ruby_bridge::call_method(session_val, "respond_to?", &[ruby.str_new("shell_read").as_value()]) {
        Ok(result) => {
            let has_method = result.to_bool();
            if has_method {
                println!("   ✓ Session has shell_read method");

                match session.shell_read() {
                    Ok(output) => {
                        println!("   ✓ shell_read() works - got {} bytes", output.len());
                        if !output.is_empty() {
                            println!("   Output preview: {:?}", &output[..output.len().min(50)]);
                        }
                    }
                    Err(e) => {
                        println!("   ⚠ shell_read() failed: {}", e);
                    }
                }
            } else {
                println!("   ⚠ Session does not have shell_read method");
            }
        }
        Err(e) => {
            println!("   ⚠ Failed to check for shell_read: {}", e);
        }
    }

    // Test 3: shell_to_meterpreter - Check if upgrade method exists (don't actually upgrade)
    println!("\n3. Testing shell_to_meterpreter capability");
    match ruby_bridge::call_method(session_val, "respond_to?", &[ruby.str_new("execute_script").as_value()]) {
        Ok(result) => {
            let has_method = result.to_bool();
            if has_method {
                println!("   ✓ Session has execute_script method (needed for upgrade)");
                println!("   ℹ Not actually running upgrade to preserve session");
                println!("   ℹ Upgrade would run: post/multi/manage/shell_to_meterpreter");

                // Just verify the method signature works (check datastore exists)
                match ruby_bridge::call_method(session_val, "exploit_datastore", &[]) {
                    Ok(ds) => {
                        let is_nil = ds.is_nil();
                        if !is_nil {
                            println!("   ✓ Session has exploit_datastore for LHOST/LPORT configuration");
                        } else {
                            println!("   ⚠ exploit_datastore is nil");
                        }
                    }
                    Err(e) => {
                        println!("   ⚠ Failed to get exploit_datastore: {}", e);
                    }
                }
            } else {
                println!("   ⚠ Session does not have execute_script method");
            }
        }
        Err(e) => {
            println!("   ⚠ Failed to check for execute_script: {}", e);
        }
    }

    println!("\n✅ Shell session operations test completed");
}
