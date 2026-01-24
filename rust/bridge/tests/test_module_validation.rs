// Test: Module validation (validate, has_check)
// Run with: ./run_tests.sh --test test_module_validation

mod common;

use bridge::Framework;

#[test]
fn it_validates_module_options() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    // Test has_check - this module should have a check method
    let has_check = module.has_check().expect("Failed to call has_check");
    println!("✓ Has check method: {}", has_check);
    assert!(has_check, "Samba exploit should have check capability");

    // Test validate with missing required options - should fail or return false
    // First test without setting RHOSTS
    let valid_before = module.validate();
    println!("✓ Validate before setting options: {:?}", valid_before);
    // Validation might return error or false when required options missing

    // Set required options
    module.set_option("RHOSTS", "192.168.1.100").expect("Failed to set RHOSTS");

    // Now validate should pass
    let valid_after = module.validate().expect("Failed to validate");
    println!("✓ Validate after setting RHOSTS: {}", valid_after);
    assert!(valid_after, "Module should validate after setting required options");

    // Test with auxiliary module that has different requirements
    let scanner = framework
        .create_module("auxiliary/scanner/portscan/tcp")
        .expect("Failed to create scanner");

    let scanner_has_check = scanner.has_check().expect("Failed to call has_check on scanner");
    println!("✓ Scanner has check: {}", scanner_has_check);
    // Scanners typically don't have check methods
    assert!(!scanner_has_check, "Port scanner should not have check capability");

    println!("✓ All validation tests passed");
}
