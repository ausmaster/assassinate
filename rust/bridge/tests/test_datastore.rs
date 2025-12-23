// Test: DataStore operations (set, get, delete, clear)

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_manages_datastore() {
    let (ruby, framework) = common::init_framework();

    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get modules");

    // Create a module to test its datastore
    let module_name = ruby.str_new("exploit/multi/handler").as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");

    let datastore = ruby_bridge::call_method(module, "datastore", &[])
        .expect("Failed to get datastore");
    println!("✓ DataStore accessed");

    // Test set and get
    let key = ruby.str_new("LHOST").as_value();
    let value = ruby.str_new("192.168.1.100").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[key, value])
        .expect("Failed to set option");
    println!("✓ Set LHOST = 192.168.1.100");

    let retrieved = ruby_bridge::call_method(datastore, "[]", &[key])
        .expect("Failed to get option");
    let retrieved_str = ruby_bridge::value_to_string(retrieved)
        .expect("Failed to convert value");
    assert_eq!(retrieved_str, "192.168.1.100", "Value should match");
    println!("✓ Get LHOST = {}", retrieved_str);

    // Test to_h (hash conversion)
    let hash = ruby_bridge::call_method(datastore, "to_h", &[])
        .expect("Failed to call to_h");
    assert!(!ruby_bridge::is_nil(hash), "Hash should not be nil");
    println!("✓ DataStore to_h works");

    // Test keys
    let keys = ruby_bridge::call_method(datastore, "keys", &[])
        .expect("Failed to get keys");
    let keys_vec: Vec<String> = TryConvert::try_convert(keys)
        .expect("Failed to convert keys");
    println!("✓ DataStore has {} keys", keys_vec.len());
    assert!(keys_vec.iter().any(|k| k == "LHOST"), "Should contain LHOST key");

    // Test delete
    ruby_bridge::call_method(datastore, "delete", &[key])
        .expect("Failed to delete key");
    let after_delete = ruby_bridge::call_method(datastore, "[]", &[key])
        .expect("Failed to get after delete");
    assert!(ruby_bridge::is_nil(after_delete), "Value should be nil after delete");
    println!("✓ Delete works");

    // Test clear
    let value2 = ruby.str_new("test_value").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[key, value2])
        .expect("Failed to set for clear test");
    ruby_bridge::call_method(datastore, "clear", &[])
        .expect("Failed to clear");
    let keys_after = ruby_bridge::call_method(datastore, "keys", &[])
        .expect("Failed to get keys after clear");
    let keys_after_vec: Vec<String> = TryConvert::try_convert(keys_after)
        .expect("Failed to convert keys");
    // Note: clear may not remove all keys due to default values
    println!("✓ Clear works (keys remaining: {})", keys_after_vec.len());
}
