// Test: Module references() method returns proper string array
// Verifies fix for Magnus TryConvert issue with Msf::Ref objects
// Run with: ./run_tests.sh test_module_references

mod common;

use bridge::Framework;

#[test]
fn it_gets_module_references_as_strings() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Use a module with known CVE references
    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    let refs = module.references().expect("Failed to get references");

    println!("✓ Got {} references", refs.len());
    assert!(!refs.is_empty(), "Module should have references");

    for reference in &refs {
        println!("  Reference: {}", reference);
        assert!(!reference.is_empty(), "Reference string should not be empty");
    }

    // This module has CVE-2017-7494 - verify it's present
    let has_cve = refs.iter().any(|r| r.contains("CVE-2017-7494") || r.contains("2017-7494"));
    assert!(has_cve, "Should contain CVE-2017-7494 reference");

    println!("✓ All reference strings valid");
}
