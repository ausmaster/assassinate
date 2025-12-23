// Test: Module enumeration (exploits, auxiliary, payloads)

mod common;

use bridge::ruby_bridge;
use magnus::TryConvert;

#[test]
fn it_enumerates_modules() {
    let (_ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Test exploits enumeration
    let exploits = ruby_bridge::call_method(modules, "exploits", &[])
        .expect("Failed to get exploits");
    let refnames = ruby_bridge::call_method(exploits, "module_refnames", &[])
        .expect("Failed to get exploit refnames");
    let exploit_list: Vec<String> = TryConvert::try_convert(refnames)
        .expect("Failed to convert refnames");
    println!("✓ Found {} exploits", exploit_list.len());
    assert!(!exploit_list.is_empty(), "Should have at least one exploit");

    // Test auxiliary enumeration
    let auxiliary = ruby_bridge::call_method(modules, "auxiliary", &[])
        .expect("Failed to get auxiliary");
    let refnames = ruby_bridge::call_method(auxiliary, "module_refnames", &[])
        .expect("Failed to get auxiliary refnames");
    let aux_list: Vec<String> = TryConvert::try_convert(refnames)
        .expect("Failed to convert refnames");
    println!("✓ Found {} auxiliary modules", aux_list.len());
    assert!(!aux_list.is_empty(), "Should have at least one auxiliary");

    // Test payload enumeration
    let payloads = ruby_bridge::call_method(modules, "payloads", &[])
        .expect("Failed to get payloads");
    let refnames = ruby_bridge::call_method(payloads, "module_refnames", &[])
        .expect("Failed to get payload refnames");
    let payload_list: Vec<String> = TryConvert::try_convert(refnames)
        .expect("Failed to convert refnames");
    println!("✓ Found {} payloads", payload_list.len());
    assert!(!payload_list.is_empty(), "Should have at least one payload");
}
