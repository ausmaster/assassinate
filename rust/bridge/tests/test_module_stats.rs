// Test: Module statistics
// Split from test_framework_features.rs - Magnus requires one test per file

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_gets_module_stats() {
    let (_ruby, framework) = common::init_framework();

    // Get stats object
    let stats = ruby_bridge::call_method(framework, "stats", &[])
        .expect("Failed to get stats");
    assert!(!stats.is_nil(), "Stats should not be nil");

    // Test each stat method
    let exploits = ruby_bridge::call_method(stats, "num_exploits", &[])
        .expect("Failed to get num_exploits");
    let exploits_count: i64 = TryConvert::try_convert(exploits).unwrap_or(0);

    let auxiliary = ruby_bridge::call_method(stats, "num_auxiliary", &[])
        .expect("Failed to get num_auxiliary");
    let auxiliary_count: i64 = TryConvert::try_convert(auxiliary).unwrap_or(0);

    let payloads = ruby_bridge::call_method(stats, "num_payloads", &[])
        .expect("Failed to get num_payloads");
    let payloads_count: i64 = TryConvert::try_convert(payloads).unwrap_or(0);

    println!("✓ Module stats: {} exploits, {} auxiliary, {} payloads",
        exploits_count, auxiliary_count, payloads_count);

    assert!(exploits_count > 0, "Should have exploits");
    assert!(auxiliary_count > 0, "Should have auxiliary");
    assert!(payloads_count > 0, "Should have payloads");
}
