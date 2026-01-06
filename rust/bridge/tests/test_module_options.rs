// Test: Module structured options
// Note: Other tests split to separate files - Magnus requires one test per file

mod common;

use bridge::ruby_bridge;
use magnus::value::ReprValue;

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
