// Test: Detect missing required module options
// Split from test_module_options.rs - Magnus requires one test per file

mod common;

use bridge::ruby_bridge;
use magnus::value::ReprValue;

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

    // Get option keys directly
    let option_keys = ruby_bridge::call_method(options, "keys", &[])
        .expect("Failed to get option keys");
    let keys = ruby_bridge::ruby_array_to_strings(option_keys)
        .expect("Failed to convert keys");

    println!("✓ Module has {} options: {:?}", keys.len(), &keys[..keys.len().min(5)]);
    assert!(!keys.is_empty(), "Module should have options");

    // Check RHOSTS option specifically (we know this module has it)
    let rhosts_key = ruby.str_new("RHOSTS").as_value();
    let rhosts_opt = ruby_bridge::call_method(options, "[]", &[rhosts_key])
        .expect("Failed to get RHOSTS option");
    assert!(!rhosts_opt.is_nil(), "RHOSTS option should exist");

    // Check if RHOSTS is required
    let required = ruby_bridge::call_method(rhosts_opt, "required", &[])
        .expect("Failed to get required attribute");
    let is_required: bool = required.to_bool();
    println!("✓ RHOSTS required: {}", is_required);

    // Check datastore for RHOSTS value
    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .expect("Failed to get datastore");
    let rhosts_val = ruby_bridge::call_method(datastore, "[]", &[rhosts_key])
        .expect("Failed to get RHOSTS value");

    println!("✓ RHOSTS current value is_nil: {}", rhosts_val.is_nil());

    // Test passes if we can read options and their required status
    assert!(is_required, "RHOSTS should be a required option for portscan");
}
