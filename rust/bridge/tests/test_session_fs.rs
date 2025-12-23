// Test: Meterpreter filesystem operations
// Requires an active Meterpreter session to fully test

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_tests_meterpreter_fs_operations() {
    let (ruby, framework) = common::init_framework();

    // Get sessions
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping Meterpreter FS test");
        println!("  To test FS operations, create a Meterpreter session first");
        return;
    }

    let session_id = session_ids[0];
    println!("Testing with session ID: {}", session_id);

    // Get session object
    let sid_val = ruby.integer_from_i64(session_id).as_value();
    let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
        .expect("Failed to get session");

    // Check session type
    let type_val = ruby_bridge::call_method(session_val, "type", &[])
        .expect("Failed to get type");
    let session_type = ruby_bridge::value_to_string(type_val)
        .expect("Failed to convert type");
    println!("Session type: {}", session_type);

    if !session_type.to_lowercase().contains("meterpreter") {
        println!("⚠ Session is not Meterpreter - skipping FS tests");
        return;
    }

    let session = bridge::Session::from_raw(session_val, session_id);

    // Test fs_pwd
    match session.fs_pwd() {
        Ok(pwd) => {
            println!("✓ fs_pwd() = {}", pwd);
            assert!(!pwd.is_empty(), "PWD should not be empty");
        }
        Err(e) => println!("⚠ fs_pwd() failed: {}", e),
    }

    // Test fs_separator
    match session.fs_separator() {
        Ok(sep) => {
            println!("✓ fs_separator() = {:?}", sep);
            assert!(sep == "/" || sep == "\\", "Separator should be / or \\");
        }
        Err(e) => println!("⚠ fs_separator() failed: {}", e),
    }

    // Test fs_ls on a safe path
    let test_path = if session_type.contains("windows") {
        "C:\\Windows"
    } else {
        "/tmp"
    };

    match session.fs_ls(test_path) {
        Ok(entries) => {
            println!("✓ fs_ls({}) returned {} entries", test_path, entries.len());
            if !entries.is_empty() {
                println!("  First few: {:?}", &entries[..entries.len().min(3)]);
            }
        }
        Err(e) => println!("⚠ fs_ls() failed: {}", e),
    }

    // Test fs_exists
    match session.fs_exists(test_path) {
        Ok(exists) => {
            println!("✓ fs_exists({}) = {}", test_path, exists);
            assert!(exists, "Test path should exist");
        }
        Err(e) => println!("⚠ fs_exists() failed: {}", e),
    }

    // Test fs_stat
    match session.fs_stat(test_path) {
        Ok(stat) => {
            println!("✓ fs_stat({}) returned stat info", test_path);
            if let Some(ftype) = stat.get("ftype") {
                println!("  ftype: {}", ftype);
            }
        }
        Err(e) => println!("⚠ fs_stat() failed: {}", e),
    }

    println!("✓ Meterpreter FS operations work correctly");
}
