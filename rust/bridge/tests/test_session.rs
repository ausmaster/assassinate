// Consolidated test: All session operations
// Run with: ./run_tests.sh --test test_session
//
// This consolidates:
//   - test_session_metadata.rs (session manager operations)
//   - test_create_shell_session.rs (create session from raw bind shell)
//
// Magnus pattern: Ruby VM can only init once per process, so all session tests
// are combined into a single test function with multiple sub-tests.

mod common;

use msf::Framework;
use std::env;

#[test]
fn it_tests_session_operations_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // =========================================================================
    // Sub-test 1: Session manager basic operations
    // =========================================================================
    println!("\n=== Testing Session Manager Operations ===");

    // Get session manager
    let session_manager = framework.sessions().expect("Failed to get session manager");

    // List sessions (should be empty initially)
    let sessions = session_manager.list().expect("Failed to list sessions");
    println!("✓ Got {} sessions", sessions.len());

    // Try to get non-existent session
    let no_session = session_manager.get(99999).expect("Failed to call get");
    assert!(
        no_session.is_none(),
        "Non-existent session should return None"
    );
    println!("✓ get(99999) returned None as expected");

    // Try to kill non-existent session
    let killed = session_manager.kill(99999).expect("Failed to call kill");
    assert!(!killed, "Killing non-existent session should return false");
    println!("✓ kill(99999) returned false as expected");

    println!("✓ Session manager operations tests passed");

    // =========================================================================
    // Sub-test 2: Create shell session from bind shell (requires Docker)
    // =========================================================================
    println!("\n=== Testing Shell Session Creation ===");

    // Skip if not in integration test environment
    if env::var("INTEGRATION_TESTS").unwrap_or_default().to_lowercase() != "true" {
        println!("⏭ Skipping integration test (set INTEGRATION_TESTS=true to run)");
        println!("  Prerequisites: cd docker && docker compose up -d test-shell");
        println!("✓ Session tests passed (basic only, integration skipped)");
        return;
    }

    // The test-shell container runs a socat bind shell on port 4444
    // It's exposed to the host, so we can connect to localhost:4444
    let host = "127.0.0.1";
    let port = 4444u16;
    let timeout = 10u32;

    println!("[*] Connecting to bind shell at {}:{}...", host, port);

    // Create a session from the bind shell
    let session_id = session_manager.create_shell_session(host, port, timeout)
        .expect("Failed to create shell session");

    println!("✓ Created session: {}", session_id);

    // Verify session exists
    let session = session_manager.get(session_id).expect("Failed to get session");
    assert!(session.is_some(), "Session should exist");

    let session = session.unwrap();
    println!("✓ Session type: {:?}", session.session_type());

    // Run a command through the session
    let output = session.run_cmd("id", Some(5)).expect("Failed to run command");
    println!("✓ Command output: {}", output.trim());
    assert!(output.contains("uid="), "Should get uid output");

    // Test additional session metadata
    let host_info = session.tunnel_peer().unwrap_or_default();
    println!("✓ Tunnel peer: {}", host_info);

    let alive = session.alive().expect("Failed to check alive");
    println!("✓ Session alive: {}", alive);
    assert!(alive, "Session should be alive");

    // Clean up
    session_manager.kill(session_id).expect("Failed to kill session");
    println!("✓ Cleaned up session");

    // Verify session is gone
    let gone_session = session_manager.get(session_id).expect("Failed to check session");
    assert!(gone_session.is_none(), "Session should be gone after kill");
    println!("✓ Verified session killed");

    println!("✓ Shell session creation tests passed");

    // =========================================================================
    println!("\n✓ All session tests passed!");
}
