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
    assert!(!ruby_bridge::is_nil(threads), "Threads should not be nil");
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
    assert!(!ruby_bridge::is_nil(jobs), "Jobs should not be nil");
    let job_keys = ruby_bridge::call_method(jobs, "keys", &[])
        .expect("Failed to get job keys");
    let job_keys_vec: Vec<String> = TryConvert::try_convert(job_keys)
        .unwrap_or_else(|_| Vec::new());
    println!("✓ Jobs accessible ({} active)", job_keys_vec.len());

    // Test database
    let db = ruby_bridge::call_method(framework, "db", &[])
        .expect("Failed to get db");
    assert!(!ruby_bridge::is_nil(db), "DB should not be nil");
    println!("✓ Database accessible");

    // Test session manager
    let sessions = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");
    assert!(!ruby_bridge::is_nil(sessions), "Sessions should not be nil");
    let session_keys = ruby_bridge::call_method(sessions, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = TryConvert::try_convert(session_keys)
        .unwrap_or_else(|_| Vec::new());
    println!("✓ SessionManager accessible ({} sessions)", session_ids.len());
}
