// Test: Module author() method returns proper string array
// Verifies fix for Magnus TryConvert issue with Msf::Author objects
// Run with: ./run_tests.sh test_module_author

mod common;

use msf::Framework;

#[test]
fn it_gets_module_authors_as_strings() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Use a well-known module with multiple authors
    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    let authors = module.author().expect("Failed to get authors");

    println!("✓ Got {} authors", authors.len());
    assert!(!authors.is_empty(), "Module should have at least one author");

    for author in &authors {
        println!("  Author: {}", author);
        // Authors should contain email or name info
        assert!(!author.is_empty(), "Author string should not be empty");
    }

    // This module has known authors - verify at least one contains expected text
    let has_expected = authors.iter().any(|a| a.contains("steelo") || a.contains("hdm"));
    assert!(has_expected, "Should contain known authors (steelo or hdm)");

    println!("✓ All author strings valid");
}
