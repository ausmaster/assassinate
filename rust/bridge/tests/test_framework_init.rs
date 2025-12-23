// Test: Framework initialization and version
// Tests Ruby VM init, Metasploit loading, and framework creation

mod common;

use bridge::ruby_bridge;
use magnus::value::ReprValue;

#[test]
fn it_initializes_framework_and_gets_version() {
    // Use the common initialization helper
    // This properly initializes Ruby VM and Metasploit in one go
    let (ruby, framework) = common::init_framework();

    println!("✓ Ruby VM initialized");
    println!("✓ Metasploit loaded");
    println!("✓ Framework created");

    // Verify framework is not nil
    assert!(!ruby_bridge::is_nil(framework), "Framework is nil");

    // Get version
    let version = ruby_bridge::call_method(framework, "version", &[])
        .expect("Failed to get version");
    let version_str = ruby_bridge::value_to_string(version)
        .expect("Failed to convert version");
    println!("✓ Framework version: {}", version_str);
    assert!(version_str.contains("."), "Version should contain '.'");

    // Access module manager
    let modules = ruby_bridge::call_method(framework, "modules", &[])
        .expect("Failed to get module manager");
    assert!(!ruby_bridge::is_nil(modules), "Module manager is nil");
    println!("✓ Module manager accessible");

    // Verify we can get the Ruby handle (confirms VM is working)
    let _ = ruby.str_new("test").as_value();
    println!("✓ Ruby value creation works");
}
