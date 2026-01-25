// Consolidated test: Framework creation, version, and search operations
// Run with: ./run_tests.sh --test test_framework
//
// This consolidates:
//   - test_framework_create.rs (framework creation, version, module creation)
//   - test_framework_search.rs (search functionality)
//
// Magnus pattern: Ruby VM can only init once per process, so all framework tests
// are combined into a single test function with multiple sub-tests.

mod common;

use msf::Framework;

#[test]
fn it_tests_framework_operations_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // =========================================================================
    // Sub-test 1: Framework creation and version
    // =========================================================================
    println!("\n=== Testing Framework Creation and Version ===");

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

    println!("✓ Framework creation tests passed");

    // =========================================================================
    // Sub-test 2: Module search functionality
    // =========================================================================
    println!("\n=== Testing Module Search ===");

    // Search for samba modules
    let results = framework.search("samba").expect("Failed to search");
    println!("✓ Found {} modules matching 'samba'", results.len());
    assert!(!results.is_empty(), "Should find samba modules");

    // Check that results contain expected module
    let has_pipename = results.iter().any(|r| r.contains("is_known_pipename"));
    println!("✓ Found is_known_pipename: {}", has_pipename);
    assert!(has_pipename, "Should find SambaCry exploit");

    // Search for CVE
    let cve_results = framework.search("CVE-2017-7494").expect("Failed CVE search");
    println!("✓ Found {} modules for CVE-2017-7494", cve_results.len());
    // This CVE is SambaCry
    assert!(!cve_results.is_empty(), "Should find CVE-2017-7494 modules");

    // Search with no results
    let no_results = framework
        .search("xyznonexistent123")
        .expect("Failed empty search");
    assert!(no_results.is_empty(), "Nonsense query should return empty");
    println!("✓ Nonsense query returned empty as expected");

    // Search for exploit type
    let eternal_results = framework.search("eternalblue").expect("Failed eternalblue search");
    println!("✓ Found {} modules for 'eternalblue'", eternal_results.len());

    println!("✓ Search tests passed");

    // =========================================================================
    println!("\n✓ All framework tests passed!");
}
