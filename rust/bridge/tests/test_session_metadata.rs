// Test: Session metadata and session manager operations
// Run with: ./run_tests.sh --test test_session_metadata

mod common;

use bridge::Framework;

#[test]
fn it_gets_session_manager() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

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

    println!("✓ All session manager tests passed");
}
