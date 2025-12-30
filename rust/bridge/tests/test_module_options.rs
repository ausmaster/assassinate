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
    assert!(!options.is_nil(), "Options should not be nil");

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
        if !aliases.is_nil() {
            let alias_vec: Vec<String> = TryConvert::try_convert(aliases)
                .unwrap_or_else(|_| Vec::new());
            println!("✓ Aliases: {:?}", alias_vec);
        }
    }

    // Now test a module with actions (auxiliary/scanner/smb/smb_ms17_010)
    let action_module_name = ruby.str_new("auxiliary/scanner/smb/smb_ms17_010").as_value();
    if let Ok(action_module) = ruby_bridge::call_method(modules, "create", &[action_module_name]) {
        if !action_module.is_nil() {
            println!("✓ Created auxiliary/scanner/smb/smb_ms17_010");

            // Test actions
            if let Ok(actions) = ruby_bridge::call_method(action_module, "actions", &[]) {
                let actions_len = ruby_bridge::ruby_array_len(actions).unwrap_or(0);
                println!("✓ Module has {} actions", actions_len);
            }

            // Test default_action
            if let Ok(default_action) = ruby_bridge::call_method(action_module, "default_action", &[]) {
                if !default_action.is_nil() {
                    if let Ok(action_str) = ruby_bridge::value_to_string(default_action) {
                        println!("✓ Default action: {}", action_str);
                    }
                }
            }
        }
    }
}

#[test]
fn it_gets_structured_options() {
    let (ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Create a module with known required options
    let module_name = ruby.str_new("auxiliary/scanner/portscan/tcp").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");

    // Get options as hash
    let options = ruby_bridge::call_method(module, "options", &[])
        .expect("Failed to get options");
    let options_hash = ruby_bridge::call_method(options, "to_h", &[])
        .expect("Failed to convert options to hash");

    // Convert to JSON to inspect structure
    let json = ruby_bridge::hash_to_json(options_hash)
        .expect("Failed to convert options hash to JSON");

    println!("✓ Structured options JSON has {} keys", json.as_object().map(|o| o.len()).unwrap_or(0));

    // Check that we can extract option details
    if let Some(opts_obj) = json.as_object() {
        for (opt_name, opt_val) in opts_obj {
            if opt_name == "RHOSTS" || opt_name == "RHOST" {
                println!("  {} option details: {}", opt_name, opt_val);
                // Should have required, desc, type fields
                if let Some(opt_obj) = opt_val.as_object() {
                    assert!(opt_obj.contains_key("required") || opt_obj.contains_key("desc"),
                        "Option should have metadata");
                }
                break;
            }
        }
    }
}

#[test]
fn it_detects_missing_required_options() {
    let (ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Create a module with required options
    let module_name = ruby.str_new("auxiliary/scanner/portscan/tcp").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");

    // Get options
    let options = ruby_bridge::call_method(module, "options", &[])
        .expect("Failed to get options");
    let options_hash = ruby_bridge::call_method(options, "to_h", &[])
        .expect("Failed to convert options to hash");
    let json = ruby_bridge::hash_to_json(options_hash)
        .expect("Failed to convert to JSON");

    // Check for missing required options
    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .expect("Failed to get datastore");

    let mut missing = Vec::new();

    if let Some(opts_obj) = json.as_object() {
        for (opt_name, opt_val) in opts_obj {
            if let Some(opt_obj) = opt_val.as_object() {
                let is_required = opt_obj
                    .get("required")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if is_required {
                    let opt_name_val = ruby.str_new(opt_name).as_value();
                    let current_val = ruby_bridge::call_method(datastore, "[]", &[opt_name_val])
                        .expect("Failed to get datastore value");

                    if current_val.is_nil() {
                        missing.push(opt_name.clone());
                    } else if let Ok(val_str) = ruby_bridge::value_to_string(current_val) {
                        if val_str.is_empty() {
                            missing.push(opt_name.clone());
                        }
                    }
                }
            }
        }
    }

    println!("✓ Missing required options: {:?}", missing);
    assert!(!missing.is_empty(), "Module should have missing required options when unconfigured");
}
