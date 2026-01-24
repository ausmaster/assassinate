// Test: Module platform() method returns proper string array
// Verifies fix for Msf::Module::PlatformList.names conversion
// Run with: ./run_tests.sh test_module_platform

mod common;

use bridge::Framework;

#[test]
fn it_gets_module_platforms_as_strings() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Use a Linux-specific exploit
    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    let platforms = module.platform().expect("Failed to get platforms");

    println!("✓ Got {} platforms", platforms.len());
    assert!(!platforms.is_empty(), "Module should have platform info");

    for platform in &platforms {
        println!("  Platform: {}", platform);
        assert!(!platform.is_empty(), "Platform string should not be empty");
    }

    // This is a Linux exploit - verify Linux is listed
    let has_linux = platforms.iter().any(|p| p.to_lowercase().contains("linux"));
    assert!(has_linux, "Linux module should list Linux platform");

    println!("✓ Platform strings valid");
}
