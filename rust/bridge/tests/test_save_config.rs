// Test: Framework save_config
// Split from test_framework_features.rs - Magnus requires one test per file

mod common;

use bridge::ruby_bridge;

#[test]
fn it_saves_config() {
    let (_ruby, framework) = common::init_framework();

    // Test save_config - should not error
    let result = ruby_bridge::call_method(framework, "save_config", &[]);
    assert!(result.is_ok(), "save_config should not error: {:?}", result.err());

    println!("✓ Framework config saved successfully");
}
