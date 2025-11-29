// Integration tests for Assassinate Rust FFI Bridge
// Tests against actual Metasploit Framework installation
//
// NOTE: All tests run in a single test function to ensure they execute
// on the same thread. This is required because the Ruby VM is not thread-safe
// and modern Rust (post-1.66.1) doesn't provide a way to force tests on the same thread.

use magnus::{value::ReprValue, TryConvert};
use std::env;

// Get MSF path from environment variable or use default
// CI/CD uses /tmp/metasploit-framework, local dev may use different path
fn get_msf_path() -> String {
    env::var("MSF_ROOT").unwrap_or_else(|_| "/tmp/metasploit-framework".to_string())
}

// Re-export functions we need for testing
use assassinate_bridge::ruby_bridge;

/// All-in-one integration test that runs sequentially on a single thread
#[test]
fn test_all_metasploit_integration() {
    // Test 01: Ruby VM initialization
    println!("\n=== Test 01: Ruby VM initialization ===");
    let result = ruby_bridge::init_ruby();
    assert!(result.is_ok(), "Failed to initialize Ruby VM");
    println!("✓ Ruby VM initialized successfully");

    // Test 02: Metasploit loading
    println!("\n=== Test 02: Metasploit loading ===");
    let msf_path = get_msf_path();
    let result = ruby_bridge::init_metasploit(&msf_path);
    assert!(
        result.is_ok(),
        "Failed to load Metasploit: {:?}",
        result.err()
    );
    println!("✓ Metasploit loaded successfully");

    // Test 03: Framework creation
    println!("\n=== Test 03: Framework creation ===");
    let framework = ruby_bridge::create_framework(None);
    assert!(
        framework.is_ok(),
        "Failed to create framework: {:?}",
        framework.err()
    );
    let fw = framework.unwrap();
    assert!(!ruby_bridge::is_nil(fw), "Framework is nil");
    println!("✓ Framework created successfully");

    // Test 04: Framework version retrieval
    println!("\n=== Test 04: Framework version ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let version = ruby_bridge::call_method(framework, "version", &[]);
    assert!(
        version.is_ok(),
        "Failed to get version: {:?}",
        version.err()
    );
    let version_str = ruby_bridge::value_to_string(version.unwrap());
    assert!(
        version_str.is_ok(),
        "Failed to convert version: {:?}",
        version_str.err()
    );
    let ver = version_str.unwrap();
    println!("✓ Framework version: {}", ver);
    assert!(ver.contains("."), "Version doesn't contain '.'");

    // Test 05: Module Manager access
    println!("\n=== Test 05: Module Manager access ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules = ruby_bridge::call_method(framework, "modules", &[]);
    assert!(
        modules.is_ok(),
        "Failed to get module manager: {:?}",
        modules.err()
    );
    assert!(
        !ruby_bridge::is_nil(modules.unwrap()),
        "Module manager is nil"
    );
    println!("✓ Module manager accessible");

    // Test 06: List exploits
    println!("\n=== Test 06: Exploit enumeration ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let exploits = ruby_bridge::call_method(modules, "exploits", &[]);
    assert!(
        exploits.is_ok(),
        "Failed to get exploits: {:?}",
        exploits.err()
    );
    let exploit_set = exploits.unwrap();
    let refnames = ruby_bridge::call_method(exploit_set, "module_refnames", &[]);
    assert!(
        refnames.is_ok(),
        "Failed to get refnames: {:?}",
        refnames.err()
    );
    let names: Result<Vec<String>, _> = TryConvert::try_convert(refnames.unwrap());
    assert!(names.is_ok(), "Failed to convert names: {:?}", names.err());
    let name_list = names.unwrap();
    println!("✓ Found {} exploits", name_list.len());
    assert!(!name_list.is_empty(), "No exploits found");
    for (i, name) in name_list.iter().take(5).enumerate() {
        println!("  {}. {}", i + 1, name);
    }

    // Test 07: List auxiliary modules
    println!("\n=== Test 07: Auxiliary module enumeration ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let auxiliary = ruby_bridge::call_method(modules, "auxiliary", &[]);
    assert!(
        auxiliary.is_ok(),
        "Failed to get auxiliary: {:?}",
        auxiliary.err()
    );
    let aux_set = auxiliary.unwrap();
    let refnames =
        ruby_bridge::call_method(aux_set, "module_refnames", &[]).expect("Failed to get refnames");
    let names: Vec<String> = TryConvert::try_convert(refnames).expect("Failed to convert names");
    println!("✓ Found {} auxiliary modules", names.len());
    assert!(!names.is_empty(), "No auxiliary modules found");

    // Test 08: List payloads
    println!("\n=== Test 08: Payload enumeration ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let payloads = ruby_bridge::call_method(modules, "payloads", &[]);
    assert!(
        payloads.is_ok(),
        "Failed to get payloads: {:?}",
        payloads.err()
    );
    let payload_set = payloads.unwrap();
    let refnames = ruby_bridge::call_method(payload_set, "module_refnames", &[])
        .expect("Failed to get refnames");
    let names: Vec<String> = TryConvert::try_convert(refnames).expect("Failed to convert names");
    println!("✓ Found {} payloads", names.len());
    assert!(!names.is_empty(), "No payloads found");

    // Test 09: Create exploit module
    println!("\n=== Test 09: Exploit module creation ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name]);
    assert!(
        module.is_ok(),
        "Failed to create module: {:?}",
        module.err()
    );
    let mod_instance = module.unwrap();
    assert!(!ruby_bridge::is_nil(mod_instance), "Module instance is nil");
    let name = ruby_bridge::call_method(mod_instance, "name", &[]).expect("Failed to get name");
    let name_str = ruby_bridge::value_to_string(name).expect("Failed to convert name");
    println!("✓ Created module: {}", name_str);

    // Test 10: Module metadata access
    println!("\n=== Test 10: Module metadata ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let name = ruby_bridge::call_method(module, "name", &[]).expect("Failed to get name");
    let name_str = ruby_bridge::value_to_string(name).expect("Failed to convert name");
    println!("  Name: {}", name_str);
    let fullname =
        ruby_bridge::call_method(module, "fullname", &[]).expect("Failed to get fullname");
    let fullname_str = ruby_bridge::value_to_string(fullname).expect("Failed to convert fullname");
    println!("  Fullname: {}", fullname_str);
    let description =
        ruby_bridge::call_method(module, "description", &[]).expect("Failed to get description");
    let desc_str =
        ruby_bridge::value_to_string(description).expect("Failed to convert description");
    println!("  Description: {}", desc_str);
    let mod_type = ruby_bridge::call_method(module, "type", &[]).expect("Failed to get type");
    let type_str = ruby_bridge::value_to_string(mod_type).expect("Failed to convert type");
    println!("  Type: {}", type_str);
    assert_eq!(type_str, "exploit");
    println!("✓ Module metadata accessible");

    // Test 11: DataStore operations
    println!("\n=== Test 11: DataStore operations ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let datastore =
        ruby_bridge::call_method(module, "datastore", &[]).expect("Failed to get datastore");
    let key = ruby.str_new("RHOSTS").as_value();
    let value = ruby.str_new("192.168.1.100").as_value();
    ruby_bridge::call_method(datastore, "[]=", &[key, value]).expect("Failed to set value");
    println!("  Set RHOSTS = 192.168.1.100");
    let key2 = ruby.str_new("RHOSTS").as_value();
    let result = ruby_bridge::call_method(datastore, "[]", &[key2]).expect("Failed to get value");
    let result_str = ruby_bridge::value_to_string(result).expect("Failed to convert result");
    println!("  Get RHOSTS = {}", result_str);
    assert_eq!(result_str, "192.168.1.100");
    let key3 = ruby.str_new("rhosts").as_value();
    let result2 = ruby_bridge::call_method(datastore, "[]", &[key3]).expect("Failed to get value");
    let result2_str = ruby_bridge::value_to_string(result2).expect("Failed to convert result");
    println!("  Get rhosts = {}", result2_str);
    assert_eq!(result2_str, "192.168.1.100");
    println!("✓ DataStore is case-insensitive");

    // Test 12: DataStore to_h conversion
    println!("\n=== Test 12: DataStore to_h ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let datastore =
        ruby_bridge::call_method(module, "datastore", &[]).expect("Failed to get datastore");
    ruby_bridge::call_method(
        datastore,
        "[]=",
        &[
            ruby.str_new("RHOSTS").as_value(),
            ruby.str_new("192.168.1.100").as_value(),
        ],
    )
    .expect("Failed to set RHOSTS");
    ruby_bridge::call_method(
        datastore,
        "[]=",
        &[
            ruby.str_new("RPORT").as_value(),
            ruby.str_new("21").as_value(),
        ],
    )
    .expect("Failed to set RPORT");
    let hash = ruby_bridge::call_method(datastore, "to_h", &[]).expect("Failed to convert to hash");
    assert!(!ruby_bridge::is_nil(hash), "Hash is nil");
    println!("✓ DataStore can be converted to hash");

    // Test 13: Global DataStore
    println!("\n=== Test 13: Global DataStore ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let datastore =
        ruby_bridge::call_method(framework, "datastore", &[]).expect("Failed to get datastore");
    assert!(!ruby_bridge::is_nil(datastore), "Global datastore is nil");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    ruby_bridge::call_method(
        datastore,
        "[]=",
        &[
            ruby.str_new("WORKSPACE").as_value(),
            ruby.str_new("default").as_value(),
        ],
    )
    .expect("Failed to set global value");
    let result = ruby_bridge::call_method(datastore, "[]", &[ruby.str_new("WORKSPACE").as_value()])
        .expect("Failed to get global value");
    let result_str = ruby_bridge::value_to_string(result).expect("Failed to convert result");
    println!("  Global WORKSPACE = {}", result_str);
    assert_eq!(result_str, "default");
    println!("✓ Global DataStore works");

    // Test 14: SessionManager access
    println!("\n=== Test 14: SessionManager ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let sessions = ruby_bridge::call_method(framework, "sessions", &[]);
    assert!(
        sessions.is_ok(),
        "Failed to get sessions: {:?}",
        sessions.err()
    );
    let session_mgr = sessions.unwrap();
    assert!(!ruby_bridge::is_nil(session_mgr), "Session manager is nil");
    let keys = ruby_bridge::call_method(session_mgr, "keys", &[]);
    assert!(keys.is_ok(), "Failed to get session keys: {:?}", keys.err());
    let key_array = keys.unwrap();
    let key_list: Vec<i64> = TryConvert::try_convert(key_array).unwrap_or_else(|_| Vec::new());
    println!("  Active sessions: {}", key_list.len());
    println!("✓ SessionManager accessible");

    // Test 15: Module options
    println!("\n=== Test 15: Module options ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let options = ruby_bridge::call_method(module, "options", &[]);
    assert!(
        options.is_ok(),
        "Failed to get options: {:?}",
        options.err()
    );
    let opts = options.unwrap();
    assert!(!ruby_bridge::is_nil(opts), "Options is nil");
    println!("✓ Module options accessible");

    // Test 16: Module rank and privileged
    println!("\n=== Test 16: Module rank and privileged ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let rank = ruby_bridge::call_method(module, "rank", &[]).expect("Failed to get rank");
    let rank_str = ruby_bridge::value_to_string(rank).expect("Failed to convert rank");
    println!("  Rank: {}", rank_str);
    assert!(!rank_str.is_empty());
    let privileged =
        ruby_bridge::call_method(module, "privileged", &[]).expect("Failed to get privileged");
    let priv_bool = ruby_bridge::value_to_bool(privileged).expect("Failed to convert privileged");
    println!("  Privileged: {}", priv_bool);
    println!("✓ Module rank and privileged accessible");

    // Test 17: Module license and aliases
    println!("\n=== Test 17: Module license and aliases ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let license = ruby_bridge::call_method(module, "license", &[]).expect("Failed to get license");
    let license_str = ruby_bridge::value_to_string(license).expect("Failed to convert license");
    println!("  License: {}", license_str);
    let aliases = ruby_bridge::call_method(module, "aliases", &[]).expect("Failed to get aliases");
    let aliases_vec: Vec<String> = TryConvert::try_convert(aliases).unwrap_or_else(|_| Vec::new());
    println!("  Aliases count: {}", aliases_vec.len());
    println!("✓ Module license and aliases accessible");

    // Test 18: Framework threads
    println!("\n=== Test 18: Framework threads ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let threads = ruby_bridge::call_method(framework, "threads", &[]);
    assert!(
        threads.is_ok(),
        "Failed to get threads: {:?}",
        threads.err()
    );
    let threads_val = threads.unwrap();
    let threads_i64: i64 = TryConvert::try_convert(threads_val).expect("Failed to convert threads");
    println!("  Threads: {}", threads_i64);
    let threads_enabled =
        ruby_bridge::call_method(framework, "threads?", &[]).expect("Failed to get threads?");
    let enabled_bool =
        ruby_bridge::value_to_bool(threads_enabled).expect("Failed to convert threads?");
    println!("  Threads enabled: {}", enabled_bool);
    println!("✓ Framework threads accessible");

    // Test 19: Framework search
    println!("\n=== Test 19: Framework search ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let query = ruby.str_new("vsftpd").as_value();
    let results = ruby_bridge::call_method(framework, "search", &[query]);
    assert!(results.is_ok(), "Failed to search: {:?}", results.err());
    let results_val = results.unwrap();
    let results_vec: Vec<String> =
        TryConvert::try_convert(results_val).unwrap_or_else(|_| Vec::new());
    println!("  Search results count: {}", results_vec.len());
    assert!(
        !results_vec.is_empty(),
        "Expected search results for 'vsftpd'"
    );
    println!("✓ Framework search works");

    // Test 20: Framework jobs
    println!("\n=== Test 20: Framework jobs ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let jobs = ruby_bridge::call_method(framework, "jobs", &[]);
    assert!(jobs.is_ok(), "Failed to get jobs: {:?}", jobs.err());
    let jobs_mgr = jobs.unwrap();
    assert!(!ruby_bridge::is_nil(jobs_mgr), "Jobs manager is nil");
    let job_list = ruby_bridge::call_method(jobs_mgr, "keys", &[]).expect("Failed to get job keys");
    let job_ids: Vec<String> = TryConvert::try_convert(job_list).unwrap_or_else(|_| Vec::new());
    println!("  Active jobs: {}", job_ids.len());
    println!("✓ Jobs manager accessible");

    // Test 21: Framework database
    println!("\n=== Test 21: Framework database ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let db = ruby_bridge::call_method(framework, "db", &[]);
    assert!(db.is_ok(), "Failed to get db: {:?}", db.err());
    let db_mgr = db.unwrap();
    assert!(!ruby_bridge::is_nil(db_mgr), "Database manager is nil");
    let hosts = ruby_bridge::call_method(db_mgr, "hosts", &[]).expect("Failed to get hosts");
    let hosts_vec: Vec<String> = TryConvert::try_convert(hosts).unwrap_or_else(|_| Vec::new());
    println!("  Hosts in database: {}", hosts_vec.len());
    println!("✓ Database manager accessible");

    // Test 22: DataStore delete, keys, clear
    println!("\n=== Test 22: DataStore delete, keys, clear ===");
    let framework = ruby_bridge::create_framework(None).expect("Failed to create framework");
    let modules =
        ruby_bridge::call_method(framework, "modules", &[]).expect("Failed to get modules");
    let ruby = ruby_bridge::get_ruby().expect("Failed to get Ruby");
    let module_name = ruby
        .str_new("exploit/unix/ftp/vsftpd_234_backdoor")
        .as_value();
    let module = ruby_bridge::call_method(modules, "create", &[module_name])
        .expect("Failed to create module");
    let datastore =
        ruby_bridge::call_method(module, "datastore", &[]).expect("Failed to get datastore");
    // Set some values
    ruby_bridge::call_method(
        datastore,
        "[]=",
        &[
            ruby.str_new("RHOSTS").as_value(),
            ruby.str_new("192.168.1.100").as_value(),
        ],
    )
    .expect("Failed to set RHOSTS");
    ruby_bridge::call_method(
        datastore,
        "[]=",
        &[
            ruby.str_new("RPORT").as_value(),
            ruby.str_new("21").as_value(),
        ],
    )
    .expect("Failed to set RPORT");
    // Get keys
    let keys = ruby_bridge::call_method(datastore, "keys", &[]).expect("Failed to get keys");
    let keys_vec: Vec<String> = TryConvert::try_convert(keys).expect("Failed to convert keys");
    println!("  Keys count: {}", keys_vec.len());
    assert!(keys_vec.len() >= 2, "Expected at least 2 keys");
    // Delete one key
    ruby_bridge::call_method(datastore, "delete", &[ruby.str_new("RHOSTS").as_value()])
        .expect("Failed to delete RHOSTS");
    let value = ruby_bridge::call_method(datastore, "[]", &[ruby.str_new("RHOSTS").as_value()])
        .expect("Failed to get RHOSTS");
    assert!(ruby_bridge::is_nil(value), "RHOSTS should be deleted");
    println!("  Deleted RHOSTS successfully");
    // Clear all
    ruby_bridge::call_method(datastore, "clear", &[]).expect("Failed to clear datastore");
    let keys_after = ruby_bridge::call_method(datastore, "keys", &[]).expect("Failed to get keys");
    let keys_after_vec: Vec<String> =
        TryConvert::try_convert(keys_after).expect("Failed to convert keys");
    println!("  Keys after clear: {}", keys_after_vec.len());
    println!("✓ DataStore delete, keys, clear work");

    println!("\n=== ALL TESTS PASSED! ===");
}
