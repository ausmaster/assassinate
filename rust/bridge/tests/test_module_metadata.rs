// Test: Module creation and metadata access

mod common;

use bridge::ruby_bridge;
use magnus::value::ReprValue;

#[test]
fn it_creates_module_and_reads_metadata() {
    let (ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Create an exploit module
    let module_name = ruby.str_new("exploit/multi/handler").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    assert!(!module.is_nil(), "Module is nil");
    println!("✓ Module created: exploit/multi/handler");

    // Test module metadata
    let name = ruby_bridge::call_method(module, "name", &[])
        .expect("Failed to get name");
    let name_str = ruby_bridge::value_to_string(name).expect("Failed to convert name");
    println!("  Name: {}", name_str);
    assert!(!name_str.is_empty(), "Name should not be empty");

    let fullname = ruby_bridge::call_method(module, "fullname", &[])
        .expect("Failed to get fullname");
    let fullname_str = ruby_bridge::value_to_string(fullname).expect("Failed to convert fullname");
    println!("  Fullname: {}", fullname_str);
    assert!(fullname_str.contains("handler"), "Fullname should contain 'handler'");

    let description = ruby_bridge::call_method(module, "description", &[])
        .expect("Failed to get description");
    let desc_str = ruby_bridge::value_to_string(description).expect("Failed to convert description");
    println!("  Description: {}...", &desc_str[..desc_str.len().min(50)]);
    assert!(!desc_str.is_empty(), "Description should not be empty");

    // Test rank
    let rank = ruby_bridge::call_method(module, "rank", &[])
        .expect("Failed to get rank");
    let rank_val: i64 = magnus::TryConvert::try_convert(rank)
        .expect("Failed to convert rank");
    println!("  Rank: {}", rank_val);
    assert!(rank_val >= 0, "Rank should be non-negative");

    println!("✓ All metadata accessible");
}
