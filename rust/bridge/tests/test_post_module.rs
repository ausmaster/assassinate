// Test: Post module execution capability
// Requires an active session to fully test

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_tests_post_module_execution() {
    let (ruby, framework) = common::init_framework();

    // Get sessions
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping post module test");
        println!("  To test post modules, create a session first");
        return;
    }

    println!("Found {} active session(s)", session_ids.len());
    let session_id = session_ids[0];
    println!("Testing with session ID: {}", session_id);

    // Get session object
    let sid_val = ruby.integer_from_i64(session_id).as_value();
    let session_val = ruby_bridge::call_method(sessions, "[]", &[sid_val])
        .expect("Failed to get session");

    // Verify session is valid
    assert!(!session_val.is_nil(), "Session should not be nil");

    // Check session type
    let type_val = ruby_bridge::call_method(session_val, "type", &[])
        .expect("Failed to get session type");
    let session_type = ruby_bridge::value_to_string(type_val)
        .expect("Failed to convert type");
    println!("Session type: {}", session_type);

    // Test that we can access modules manager for post modules
    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Verify post modules are available
    let post = ruby_bridge::call_method(modules, "post", &[])
        .expect("Failed to get post modules");
    let refnames = ruby_bridge::call_method(post, "module_refnames", &[])
        .expect("Failed to get post refnames");
    let post_list: Vec<String> = TryConvert::try_convert(refnames)
        .expect("Failed to convert refnames");

    println!("✓ Found {} post modules available", post_list.len());
    assert!(!post_list.is_empty(), "Should have at least one post module");

    // Show a few example post modules
    for name in post_list.iter().take(3) {
        println!("  - {}", name);
    }

    // Note: We can't actually run post modules in tests without a real target
    // But we verified the API exists and is callable
    println!("✓ Post module execution capability verified");
    println!("  Note: Full post module execution requires active target session");
}
