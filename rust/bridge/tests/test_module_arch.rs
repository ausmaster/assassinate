// Test: Module arch() method returns proper string array
// Verifies architecture list conversion
// Run with: ./run_tests.sh test_module_arch

mod common;

use bridge::Framework;

#[test]
fn it_gets_module_architectures() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Use a module with architecture constraints (EternalBlue supports x64)
    let module = framework
        .create_module("exploit/windows/smb/ms17_010_eternalblue")
        .expect("Failed to create module");

    let archs = module.arch().expect("Failed to get architectures");

    println!("✓ Got {} architectures", archs.len());

    for arch in &archs {
        println!("  Architecture: {}", arch);
        assert!(!arch.is_empty(), "Architecture string should not be empty");
    }

    // Verify architectures are valid MSF arch types
    let valid_archs = ["x86", "x64", "x86_64", "cmd", "php", "java", "python", "ruby", "nodejs", "armle", "aarch64"];
    for arch in &archs {
        let is_valid = valid_archs.iter().any(|v| arch.to_lowercase().contains(v));
        assert!(is_valid, "Unknown architecture type: {}", arch);
    }

    println!("✓ Architecture strings valid");
}
