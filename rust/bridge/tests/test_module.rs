// Consolidated test: All module operations
// Run with: ./run_tests.sh --test test_module
//
// This consolidates:
//   - test_module_type.rs (module type detection)
//   - test_module_metadata.rs (fullname, description, rank, etc.)
//   - test_module_author.rs (author string array)
//   - test_module_arch.rs (architecture array)
//   - test_module_platform.rs (platform array)
//   - test_module_references.rs (CVE/reference array)
//   - test_module_options.rs (get, set, structured, missing_required)
//   - test_module_validation.rs (validate, has_check)
//   - test_module_actions.rs (actions, default_action)
//   - test_module_payloads.rs (compatible_payloads)
//
// Magnus pattern: Ruby VM can only init once per process, so all module tests
// are combined into a single test function with multiple sub-tests.

mod common;

use msf::Framework;

#[test]
fn it_tests_module_operations_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // =========================================================================
    // Sub-test 1: Module type detection for all 7 MSF module types
    // =========================================================================
    println!("\n=== Testing Module Type Detection ===");

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

    println!("✓ Module type detection tests passed");

    // =========================================================================
    // Sub-test 2: Module metadata (fullname, description, rank, license, etc.)
    // =========================================================================
    println!("\n=== Testing Module Metadata ===");

    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    // Test fullname
    let fullname = module.fullname().expect("Failed to get fullname");
    println!("✓ Fullname: {}", fullname);
    assert_eq!(fullname, "exploit/linux/samba/is_known_pipename");

    // Test name
    let name = module.name().expect("Failed to get name");
    println!("✓ Name: {}", name);
    assert!(!name.is_empty());

    // Test description
    let description = module.description().expect("Failed to get description");
    println!("✓ Description: {}...", &description[..description.len().min(80)]);
    assert!(!description.is_empty());
    assert!(description.to_lowercase().contains("samba") || description.to_lowercase().contains("smb"));

    // Test rank
    let rank = module.rank().expect("Failed to get rank");
    println!("✓ Rank: {}", rank);
    assert!(!rank.is_empty());

    // Test license
    let license = module.license().expect("Failed to get license");
    println!("✓ License: {}", license);
    assert!(license.contains("Metasploit") || license.contains("BSD"));

    // Test disclosure_date
    let disclosure = module.disclosure_date().expect("Failed to get disclosure_date");
    println!("✓ Disclosure date: {:?}", disclosure);
    if let Some(date) = disclosure {
        assert!(date.contains("2017"), "CVE-2017-7494 should have 2017 disclosure date");
    }

    // Test privileged
    let privileged = module.privileged().expect("Failed to get privileged");
    println!("✓ Privileged: {}", privileged);
    assert!(privileged, "Samba exploit should be privileged");

    // Test targets
    let targets = module.targets().expect("Failed to get targets");
    println!("✓ Targets ({}):", targets.len());
    for (i, target) in targets.iter().take(3).enumerate() {
        println!("    {}: {}", i, target);
    }
    assert!(!targets.is_empty(), "Module should have targets");

    println!("✓ Metadata tests passed");

    // =========================================================================
    // Sub-test 3: Author array (Magnus TryConvert fix)
    // =========================================================================
    println!("\n=== Testing Module Authors ===");

    let authors = module.author().expect("Failed to get authors");
    println!("✓ Got {} authors", authors.len());
    assert!(!authors.is_empty(), "Module should have at least one author");

    for author in &authors {
        println!("  Author: {}", author);
        assert!(!author.is_empty(), "Author string should not be empty");
    }

    let has_expected = authors.iter().any(|a| a.contains("steelo") || a.contains("hdm"));
    assert!(has_expected, "Should contain known authors (steelo or hdm)");

    println!("✓ Author tests passed");

    // =========================================================================
    // Sub-test 4: Architecture array
    // =========================================================================
    println!("\n=== Testing Module Architectures ===");

    // Use EternalBlue for architecture test (has x64)
    let arch_module = framework
        .create_module("exploit/windows/smb/ms17_010_eternalblue")
        .expect("Failed to create module");

    let archs = arch_module.arch().expect("Failed to get architectures");
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

    println!("✓ Architecture tests passed");

    // =========================================================================
    // Sub-test 5: Platform array
    // =========================================================================
    println!("\n=== Testing Module Platforms ===");

    let platforms = module.platform().expect("Failed to get platforms");
    println!("✓ Got {} platforms", platforms.len());
    assert!(!platforms.is_empty(), "Module should have platform info");

    for platform in &platforms {
        println!("  Platform: {}", platform);
        assert!(!platform.is_empty(), "Platform string should not be empty");
    }

    let has_linux = platforms.iter().any(|p| p.to_lowercase().contains("linux"));
    assert!(has_linux, "Linux module should list Linux platform");

    println!("✓ Platform tests passed");

    // =========================================================================
    // Sub-test 6: References array (CVE, etc.)
    // =========================================================================
    println!("\n=== Testing Module References ===");

    let refs = module.references().expect("Failed to get references");
    println!("✓ Got {} references", refs.len());
    assert!(!refs.is_empty(), "Module should have references");

    for reference in &refs {
        println!("  Reference: {}", reference);
        assert!(!reference.is_empty(), "Reference string should not be empty");
    }

    let has_cve = refs.iter().any(|r| r.contains("CVE-2017-7494") || r.contains("2017-7494"));
    assert!(has_cve, "Should contain CVE-2017-7494 reference");

    println!("✓ Reference tests passed");

    // =========================================================================
    // Sub-test 7: Module options (get, set, structured, missing_required)
    // =========================================================================
    println!("\n=== Testing Module Options ===");

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

    // Test missing_required with scanner module
    let module2 = framework
        .create_module("auxiliary/scanner/portscan/tcp")
        .expect("Failed to create scanner module");

    let missing = module2.missing_required().expect("Failed to get missing required");
    println!("✓ Missing required options: {:?}", missing);
    assert!(missing.contains(&"RHOSTS".to_string()), "RHOSTS should be missing");

    module2.set_option("RHOSTS", "192.168.1.0/24").expect("Failed to set RHOSTS");
    let missing_after = module2.missing_required().expect("Failed to get missing after set");
    println!("✓ Missing after setting RHOSTS: {:?}", missing_after);
    assert!(!missing_after.contains(&"RHOSTS".to_string()), "RHOSTS should not be missing after set");

    println!("✓ Options tests passed");

    // =========================================================================
    // Sub-test 8: Module validation (validate, has_check)
    // =========================================================================
    println!("\n=== Testing Module Validation ===");

    // Recreate samba module for validation test
    let val_module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    // Test has_check
    let has_check = val_module.has_check().expect("Failed to call has_check");
    println!("✓ Has check method: {}", has_check);
    assert!(has_check, "Samba exploit should have check capability");

    // Test validate before setting options
    let valid_before = val_module.validate();
    println!("✓ Validate before setting options: {:?}", valid_before);

    // Set required options
    val_module.set_option("RHOSTS", "192.168.1.100").expect("Failed to set RHOSTS");

    // Now validate should pass
    let valid_after = val_module.validate().expect("Failed to validate");
    println!("✓ Validate after setting RHOSTS: {}", valid_after);
    assert!(valid_after, "Module should validate after setting required options");

    // Test scanner - should not have check method
    let scanner = framework
        .create_module("auxiliary/scanner/portscan/tcp")
        .expect("Failed to create scanner");

    let scanner_has_check = scanner.has_check().expect("Failed to call has_check on scanner");
    println!("✓ Scanner has check: {}", scanner_has_check);
    assert!(!scanner_has_check, "Port scanner should not have check capability");

    println!("✓ Validation tests passed");

    // =========================================================================
    // Sub-test 9: Module actions (for auxiliary/post modules)
    // =========================================================================
    println!("\n=== Testing Module Actions ===");

    // Test exploit module - typically no actions
    let exploit = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create exploit");

    let exploit_actions = exploit.actions().expect("Failed to get exploit actions");
    println!("✓ Exploit actions: {:?}", exploit_actions);
    assert!(exploit_actions.is_empty(), "Exploit should have no actions");

    let exploit_default = exploit.default_action().expect("Failed to get default action");
    println!("✓ Exploit default action: {:?}", exploit_default);
    assert!(exploit_default.is_none(), "Exploit should have no default action");

    // Test auxiliary module with actions
    let gather = framework
        .create_module("auxiliary/gather/enum_dns")
        .expect("Failed to create DNS enum module");

    let actions = gather.actions().expect("Failed to get gather actions");
    println!("✓ DNS enum actions ({}):", actions.len());
    for action in &actions {
        println!("    {}", action);
    }

    if !actions.is_empty() {
        let default = gather.default_action().expect("Failed to get default action");
        println!("✓ Default action: {:?}", default);

        if let Some(def) = default {
            assert!(actions.contains(&def), "Default action should be in actions list");
        }
    }

    // Test scanner module
    let scanner_actions = scanner.actions().expect("Failed to get scanner actions");
    println!("✓ Scanner actions: {:?}", scanner_actions);

    println!("✓ Actions tests passed");

    // =========================================================================
    // Sub-test 10: Compatible payloads
    // =========================================================================
    println!("\n=== Testing Compatible Payloads ===");

    // Test with Samba exploit - should have cmd/unix payloads
    let samba = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create samba module");

    let payloads = samba.compatible_payloads().expect("Failed to get compatible payloads");
    println!("✓ Samba exploit has {} compatible payloads", payloads.len());

    for payload in payloads.iter().take(5) {
        println!("    {}", payload);
    }

    assert!(!payloads.is_empty(), "Should have compatible payloads");
    let has_cmd_unix = payloads.iter().any(|p| p.contains("cmd/unix"));
    assert!(has_cmd_unix, "Should have cmd/unix payloads");

    // Test with EternalBlue - should have Windows payloads
    let eternalblue = framework
        .create_module("exploit/windows/smb/ms17_010_eternalblue")
        .expect("Failed to create eternalblue module");

    let win_payloads = eternalblue.compatible_payloads().expect("Failed to get payloads");
    println!("✓ EternalBlue has {} compatible payloads", win_payloads.len());

    for payload in win_payloads.iter().take(5) {
        println!("    {}", payload);
    }

    assert!(!win_payloads.is_empty(), "Should have compatible payloads");
    let has_windows = win_payloads.iter().any(|p| p.contains("windows"));
    assert!(has_windows, "Should have windows payloads");

    // Test multi/handler - should have MANY payloads (it's generic)
    let handler = framework
        .create_module("exploit/multi/handler")
        .expect("Failed to create handler");

    let handler_payloads = handler.compatible_payloads().expect("Failed to get handler payloads");
    println!("✓ Multi/handler has {} compatible payloads", handler_payloads.len());
    assert!(handler_payloads.len() > 100, "Handler should support many payloads");

    println!("✓ Compatible payloads tests passed");

    // =========================================================================
    // Sub-test 11: NOP Sled Generation
    // =========================================================================
    println!("\n=== Testing NOP Sled Generation ===");

    let nop_module = framework
        .create_module("nop/x86/single_byte")
        .expect("Failed to create nop module");

    // Test basic NOP sled generation
    let sled = nop_module
        .generate_sled(100, None, None)
        .expect("Failed to generate NOP sled");
    println!("✓ Generated NOP sled of {} bytes", sled.len());
    assert_eq!(sled.len(), 100, "NOP sled should be exactly 100 bytes");

    // Test with different length
    let short_sled = nop_module
        .generate_sled(16, None, None)
        .expect("Failed to generate short NOP sled");
    println!("✓ Generated short NOP sled of {} bytes", short_sled.len());
    assert_eq!(short_sled.len(), 16, "Short NOP sled should be 16 bytes");

    // Test with badchars (null byte)
    let badchars = vec![0x00u8];
    let clean_sled = nop_module
        .generate_sled(50, Some(&badchars), None)
        .expect("Failed to generate NOP sled with badchars");
    println!("✓ Generated clean NOP sled of {} bytes (avoiding null)", clean_sled.len());
    assert_eq!(clean_sled.len(), 50, "Clean NOP sled should be 50 bytes");
    assert!(!clean_sled.contains(&0x00), "NOP sled should not contain null bytes");

    // Test opty2 NOP generator (more complex, polymorphic)
    let opty_module = framework
        .create_module("nop/x86/opty2")
        .expect("Failed to create opty2 nop module");

    let opty_sled = opty_module
        .generate_sled(32, None, None)
        .expect("Failed to generate opty2 NOP sled");
    println!("✓ Generated opty2 NOP sled of {} bytes", opty_sled.len());
    assert_eq!(opty_sled.len(), 32, "Opty2 NOP sled should be 32 bytes");

    println!("✓ NOP sled generation tests passed");

    // =========================================================================
    println!("\n✓ All module tests passed!");
}
