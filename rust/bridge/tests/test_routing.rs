// =============================================================================
// Integration Test: Route Management
// =============================================================================
//
// This test verifies the Rex::Socket::SwitchBoard routing functionality.
//
// Run with:
//   docker exec dev cargo test --manifest-path rust/bridge/Cargo.toml \
//     --test test_routing -- --nocapture
//
// =============================================================================

mod common;

use bridge::ruby_bridge::{self, call_method};
use magnus::{value::ReprValue, TryConvert, Value};
use std::{thread, time::Duration};

/// Get current session IDs from the framework
fn get_session_ids(framework: Value) -> Vec<i64> {
    let sessions =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");
    let session_keys =
        ruby_bridge::call_method(sessions, "keys", &[]).expect("Failed to get session keys");
    TryConvert::try_convert(session_keys).unwrap_or_else(|_| Vec::new())
}

/// Wait for a new session to appear
fn wait_for_new_session(
    framework: Value,
    existing_sessions: &[i64],
    timeout_secs: u64,
) -> Option<i64> {
    for _ in 0..timeout_secs {
        thread::sleep(Duration::from_secs(1));

        let current_sessions = get_session_ids(framework);
        for sid in &current_sessions {
            if !existing_sessions.contains(sid) {
                return Some(*sid);
            }
        }
    }
    None
}

#[test]
#[ntest::timeout(60_000)]
fn it_tests_route_management() {
    // Check if we're in integration environment
    let env = match common::require_integration_env() {
        Some(env) => env,
        None => return,
    };

    println!("\n{}", "=".repeat(60));
    println!(" Integration Test: Route Management");
    println!("{}\n", "=".repeat(60));

    let (ruby, framework) = common::init_framework();

    // Step 1: Create a session by exploiting target-linux
    println!("📍 Step 1: Creating session via vsftpd exploit...");

    let existing_sessions = get_session_ids(framework);

    // Create and run the exploit
    let fw = bridge::Framework::from_raw(framework);
    let exploit = fw
        .create_module("exploit/unix/ftp/vsftpd_234_backdoor")
        .expect("Failed to create exploit module");

    exploit
        .set_option("RHOSTS", &env.target_host)
        .expect("Failed to set RHOSTS");
    exploit
        .set_option("RPORT", &env.ftp_port.to_string())
        .expect("Failed to set RPORT");

    // Run exploit
    let _ = exploit.exploit("cmd/unix/interact", None);

    // Wait for session
    let session_id = wait_for_new_session(framework, &existing_sessions, 10)
        .expect("No session created from exploit");

    println!("   ✓ Got session: {}", session_id);

    // Step 2: Test routing operations
    println!("\n📍 Step 2: Testing route operations...");

    // Test route_add
    println!("\n--- Testing route_add ---");
    let result = fw
        .route_add("10.10.10.0", "255.255.255.0", session_id)
        .expect("Failed to add route");
    println!("route_add('10.10.10.0', '255.255.255.0', {}) = {}", session_id, result);
    assert!(result, "Route should be added successfully");

    // Test route_list
    println!("\n--- Testing route_list ---");
    let routes = fw.route_list().expect("Failed to list routes");
    println!("Routes ({} total):", routes.len());
    for route in &routes {
        println!(
            "  {}/{} via {}",
            route.subnet, route.netmask, route.comm_name
        );
    }
    assert!(!routes.is_empty(), "Should have at least one route");

    // Test route_exists
    println!("\n--- Testing route_exists ---");
    let exists = fw
        .route_exists("10.10.10.0", "255.255.255.0")
        .expect("Failed to check route exists");
    println!("route_exists('10.10.10.0', '255.255.255.0') = {}", exists);
    assert!(exists, "Route should exist");

    // Test route_get (best_comm)
    println!("\n--- Testing route_get ---");
    let best = fw.route_get("10.10.10.5").expect("Failed to get best comm");
    println!("route_get('10.10.10.5') = {:?}", best);
    assert_eq!(best, Some(session_id), "Should route through our session");

    let no_route = fw.route_get("192.168.1.1").expect("Failed to get best comm");
    println!("route_get('192.168.1.1') = {:?}", no_route);
    assert!(no_route.is_none(), "Should not have route for 192.168.1.1");

    // Test route_remove
    println!("\n--- Testing route_remove ---");
    let removed = fw
        .route_remove("10.10.10.0", "255.255.255.0", session_id)
        .expect("Failed to remove route");
    println!("route_remove('10.10.10.0', '255.255.255.0', {}) = {}", session_id, removed);
    assert!(removed, "Route should be removed");

    // Verify removal
    let exists_after = fw
        .route_exists("10.10.10.0", "255.255.255.0")
        .expect("Failed to check route exists");
    println!("route_exists after remove = {}", exists_after);
    assert!(!exists_after, "Route should not exist after removal");

    // Test adding multiple routes then flush
    println!("\n--- Testing route_flush ---");
    fw.route_add("172.16.0.0", "255.255.0.0", session_id)
        .expect("Failed to add route 1");
    fw.route_add("192.168.100.0", "255.255.255.0", session_id)
        .expect("Failed to add route 2");

    let routes_before = fw.route_list().expect("Failed to list routes");
    println!("Routes before flush: {}", routes_before.len());

    fw.route_flush().expect("Failed to flush routes");

    let routes_after = fw.route_list().expect("Failed to list routes");
    println!("Routes after flush: {}", routes_after.len());
    assert!(routes_after.is_empty(), "All routes should be flushed");

    // Cleanup
    println!("\n📍 Step 3: Cleanup...");
    let sessions_manager =
        ruby_bridge::call_method(framework, "sessions", &[]).expect("Failed to get sessions");
    let sid_val = ruby.integer_from_i64(session_id).as_value();
    let session = ruby_bridge::call_method(sessions_manager, "[]", &[sid_val])
        .expect("Failed to get session");
    let _ = ruby_bridge::call_method(session, "kill", &[]);

    println!("\n{}", "=".repeat(60));
    println!(" ✅ Route Management Test PASSED");
    println!("{}\n", "=".repeat(60));
}
