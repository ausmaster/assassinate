// Test: Module options (get, set, structured, missing_required)
// Run with: ./run_tests.sh --test test_module_options

mod common;

use bridge::Framework;

#[test]
fn it_manages_module_options() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    // Test options_structured - get all options with metadata
    let options = module.options_structured().expect("Failed to get structured options");
    println!("✓ Got {} options", options.len());
    assert!(!options.is_empty(), "Module should have options");

    // Check that RHOSTS exists and has expected fields
    assert!(options.contains_key("RHOSTS"), "Should have RHOSTS option");
    let rhosts_opt = &options["RHOSTS"];
    println!("  RHOSTS schema: {}", rhosts_opt);
    assert!(rhosts_opt.get("required").is_some(), "RHOSTS should have 'required' field");
    assert!(rhosts_opt.get("desc").is_some(), "RHOSTS should have 'desc' field");

    // Test set_option and get_option
    module.set_option("RHOSTS", "192.168.1.100").expect("Failed to set RHOSTS");
    let value = module.get_option("RHOSTS").expect("Failed to get RHOSTS");
    println!("✓ Set RHOSTS = {:?}", value);
    assert_eq!(value, Some("192.168.1.100".to_string()));

    // Test setting RPORT
    module.set_option("RPORT", "445").expect("Failed to set RPORT");
    let rport = module.get_option("RPORT").expect("Failed to get RPORT");
    println!("✓ Set RPORT = {:?}", rport);
    assert_eq!(rport, Some("445".to_string()));

    // Test get_option for non-existent option returns None
    let nonexistent = module.get_option("NONEXISTENT_OPTION_XYZ").expect("Failed to get nonexistent");
    assert!(nonexistent.is_none(), "Non-existent option should return None");

    // Test missing_required before setting all required options
    // First, clear RHOSTS to test missing detection
    let module2 = framework
        .create_module("auxiliary/scanner/portscan/tcp")
        .expect("Failed to create scanner module");

    let missing = module2.missing_required().expect("Failed to get missing required");
    println!("✓ Missing required options: {:?}", missing);
    // RHOSTS is typically required for scanners
    assert!(missing.contains(&"RHOSTS".to_string()), "RHOSTS should be missing");

    // Set RHOSTS and check missing again
    module2.set_option("RHOSTS", "192.168.1.0/24").expect("Failed to set RHOSTS");
    let missing_after = module2.missing_required().expect("Failed to get missing after set");
    println!("✓ Missing after setting RHOSTS: {:?}", missing_after);
    assert!(!missing_after.contains(&"RHOSTS".to_string()), "RHOSTS should not be missing after set");

    println!("✓ All options tests passed");
}
