// Test: Framework creation and basic operations
// Run with: ./run_tests.sh --test test_framework_create

mod common;

use msf::Framework;

#[test]
fn it_creates_framework_and_gets_version() {
    let _ruby = common::init_msf();

    // Create framework
    let framework = Framework::new(None).expect("Failed to create framework");

    // Get version
    let version = framework.version().expect("Failed to get version");
    println!("✓ Framework version: {}", version);
    assert!(!version.is_empty(), "Version should not be empty");
    assert!(version.contains('.'), "Version should contain dots (e.g., 6.4.104)");

    // Verify we can create modules through the framework
    let module = framework
        .create_module("exploit/multi/handler")
        .expect("Failed to create module");

    let fullname = module.fullname().expect("Failed to get fullname");
    println!("✓ Created module: {}", fullname);
    assert_eq!(fullname, "exploit/multi/handler");

    println!("✓ Framework creation test passed");
}
