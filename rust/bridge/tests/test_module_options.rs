// Test: Module options, actions, and validation

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_reads_module_options_and_actions() {
    let (ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Create an auxiliary module to test options
    let module_name = ruby.str_new("auxiliary/scanner/portscan/tcp").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    println!("✓ Created auxiliary/scanner/portscan/tcp");

    // Test options
    let options = ruby_bridge::call_method(module, "options", &[])
        .expect("Failed to get options");
    assert!(!ruby_bridge::is_nil(options), "Options should not be nil");

    let option_keys = ruby_bridge::call_method(options, "keys", &[])
        .expect("Failed to get option keys");
    let keys: Vec<String> = TryConvert::try_convert(option_keys)
        .expect("Failed to convert keys");
    println!("✓ Module has {} options", keys.len());
    assert!(!keys.is_empty(), "Should have options");

    // Check for common options
    let has_rhosts = keys.iter().any(|k| k == "RHOSTS");
    let has_ports = keys.iter().any(|k| k == "PORTS");
    println!("  RHOSTS option: {}", has_rhosts);
    println!("  PORTS option: {}", has_ports);

    // Test module rank and privileged
    let rank = ruby_bridge::call_method(module, "rank", &[])
        .expect("Failed to get rank");
    let rank_val: i64 = TryConvert::try_convert(rank)
        .expect("Failed to convert rank");
    println!("✓ Rank: {}", rank_val);

    // Test license
    if let Ok(license) = ruby_bridge::call_method(module, "license", &[]) {
        if let Ok(lic_str) = ruby_bridge::value_to_string(license) {
            println!("✓ License: {}", lic_str);
        }
    }

    // Test aliases
    if let Ok(aliases) = ruby_bridge::call_method(module, "aliases", &[]) {
        if !ruby_bridge::is_nil(aliases) {
            let alias_vec: Vec<String> = TryConvert::try_convert(aliases)
                .unwrap_or_else(|_| Vec::new());
            println!("✓ Aliases: {:?}", alias_vec);
        }
    }

    // Now test a module with actions (auxiliary/scanner/smb/smb_ms17_010)
    let action_module_name = ruby.str_new("auxiliary/scanner/smb/smb_ms17_010").as_value();
    if let Ok(action_module) = ruby_bridge::call_method(modules, "create", &[action_module_name]) {
        if !ruby_bridge::is_nil(action_module) {
            println!("✓ Created auxiliary/scanner/smb/smb_ms17_010");

            // Test actions
            if let Ok(actions) = ruby_bridge::call_method(action_module, "actions", &[]) {
                let actions_len = ruby_bridge::ruby_array_len(actions).unwrap_or(0);
                println!("✓ Module has {} actions", actions_len);
            }

            // Test default_action
            if let Ok(default_action) = ruby_bridge::call_method(action_module, "default_action", &[]) {
                if !ruby_bridge::is_nil(default_action) {
                    if let Ok(action_str) = ruby_bridge::value_to_string(default_action) {
                        println!("✓ Default action: {}", action_str);
                    }
                }
            }
        }
    }
}
