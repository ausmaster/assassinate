// Test: Framework features (threads, search, jobs, database)

mod common;

use bridge::ruby_bridge;
use magnus::{TryConvert, value::ReprValue};

#[test]
fn it_accesses_framework_features() {
    let (ruby, framework) = common::init_framework();

    // Test threads
    let threads = ruby_bridge::call_method(framework, "threads", &[])
        .expect("Failed to get threads");
    assert!(!threads.is_nil(), "Threads should not be nil");
    println!("✓ Threads accessible");

    // Test search
    let query = ruby.str_new("smb").as_value();
    let results = ruby_bridge::call_method(framework, "search", &[query])
        .expect("Failed to search");
    let results_len = ruby_bridge::ruby_array_len(results).unwrap_or(0);
    println!("✓ Search 'smb' returned {} results", results_len);

    // Test jobs
    let jobs = ruby_bridge::call_method(framework, "jobs", &[])
        .expect("Failed to get jobs");
    assert!(!jobs.is_nil(), "Jobs should not be nil");
    let job_keys = ruby_bridge::call_method(jobs, "keys", &[])
        .expect("Failed to get job keys");
    let job_keys_vec: Vec<String> = TryConvert::try_convert(job_keys)
        .unwrap_or_else(|_| Vec::new());
    println!("✓ Jobs accessible ({} active)", job_keys_vec.len());

    // Test database
    let db = ruby_bridge::call_method(framework, "db", &[])
        .expect("Failed to get db");
    assert!(!db.is_nil(), "DB should not be nil");
    println!("✓ Database accessible");

    // Test session manager
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    assert!(!sessions.is_nil(), "Sessions should not be nil");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());
    println!("✓ SessionManager accessible ({} sessions)", session_ids.len());
}

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

#[test]
fn it_saves_config() {
    let (_ruby, framework) = common::init_framework();

    // Test save_config - should not error
    let result = ruby_bridge::call_method(framework, "save_config", &[]);
    assert!(result.is_ok(), "save_config should not error: {:?}", result.err());

    println!("✓ Framework config saved successfully");
}
