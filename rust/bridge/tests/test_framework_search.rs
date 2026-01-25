// Test: Framework search functionality
// Run with: ./run_tests.sh --test test_framework_search

mod common;

use msf::Framework;

#[test]
fn it_searches_modules() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

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

    println!("✓ All search tests passed");
}
