// Test: Module type detection for all 7 MSF module types
// Run with: ./run_tests.sh --test test_module_type
//
// Magnus pattern: Ruby VM can only init once per process, so all module type
// tests are combined into a single test function.

mod common;

use msf::Framework;

#[test]
fn it_detects_all_module_types() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Test module type detection for all 7 MSF module types
    let test_cases = vec![
        ("auxiliary", "auxiliary/scanner/smb/smb_version"),
        ("encoder", "encoder/x86/shikata_ga_nai"),
        ("exploit", "exploit/linux/samba/is_known_pipename"),
        ("nop", "nop/x86/single_byte"),
        ("payload", "payload/cmd/unix/reverse_bash"),
        ("post", "post/multi/gather/env"),
    ];

    for (expected_type, module_path) in test_cases {
        let module = framework
            .create_module(module_path)
            .expect(&format!("Failed to create {} module", expected_type));

        let module_type = module.module_type().expect("Failed to get module_type");
        println!("✓ {} -> module_type(): {}", module_path, module_type);
        assert_eq!(
            module_type, expected_type,
            "Module {} should have type '{}' but got '{}'",
            module_path, expected_type, module_type
        );
    }

    // Test evasion separately (may not exist in all MSF installations)
    let evasion_result = framework.create_module("evasion/windows/applocker_evasion_msbuild");
    if let Ok(module) = evasion_result {
        let module_type = module.module_type().expect("Failed to get module_type");
        println!("✓ evasion/windows/applocker_evasion_msbuild -> module_type(): {}", module_type);
        assert_eq!(module_type, "evasion");
    } else {
        println!("⚠ Skipping evasion test - module not found in this MSF installation");
    }

    println!("\n✓ All module type detection tests passed!");
}
