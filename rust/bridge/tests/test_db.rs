// Consolidated test: All database operations
// Run with: ./run_tests.sh --test test_db
//
// This consolidates:
//   - test_db_active.rs (database connection status)
//   - test_db_workspace.rs (workspace CRUD operations)
//   - test_db_hosts.rs (host and service reporting/querying)
//   - test_db_get_host.rs (single host query)
//
// Magnus pattern: Ruby VM can only init once per process, so all database tests
// are combined into a single test function with multiple sub-tests.
//
// Note: Some sub-tests require PostgreSQL to be running and ~/.msf4/database.yml
// configured. Tests gracefully handle missing database connection.

mod common;

use msf::Framework;
use msf::ruby_bridge::RubyVal;
use std::collections::HashMap;

#[test]
fn it_tests_database_operations_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Get database manager
    let db = framework.db().expect("Failed to get DbManager");
    println!("✓ Got DbManager");

    // =========================================================================
    // Sub-test 1: Database status (active, driver)
    // =========================================================================
    println!("\n=== Testing Database Status ===");

    // Check if database is active
    let active = db.active().expect("Failed to check db.active()");
    println!("✓ Database active: {}", active);

    // Get database driver
    let driver = db.driver().expect("Failed to get db.driver()");
    println!("✓ Database driver: {}", driver);

    // If active, driver should be postgresql
    if active {
        assert_eq!(driver, "postgresql", "Driver should be postgresql when active");
        println!("✓ Confirmed postgresql driver");
    } else {
        println!("⚠ Database not active - ensure ~/.msf4/database.yml is configured");
        println!("  and PostgreSQL is running (docker compose up -d postgres)");
    }

    println!("✓ Database status tests passed");

    // =========================================================================
    // Sub-test 2: Workspace operations (requires active database)
    // =========================================================================
    println!("\n=== Testing Workspace Operations ===");

    if !active {
        println!("⏭ Skipping workspace tests - database not active");
    } else {
        // Create a test workspace with unique name
        let test_ws_name = format!("test_workspace_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        let new_ws = db.add_workspace(&test_ws_name).expect("Failed to create workspace");
        println!("✓ Created workspace: {:?}", new_ws);

        // Verify workspace has ID and name
        assert!(new_ws.get("id").is_some(), "Workspace should have ID");
        assert_eq!(
            new_ws.get("name").and_then(|v| v.as_str()),
            Some(test_ws_name.as_str()),
            "Workspace name should match"
        );

        // Find workspace by name
        let found_ws = db.find_workspace(&test_ws_name).expect("Failed to find workspace");
        assert!(found_ws.is_some(), "Should find the workspace we just created");
        println!("✓ Found workspace by name");

        // List all workspaces
        let workspaces = db.workspaces().expect("Failed to list workspaces");
        println!("✓ Listed {} workspaces", workspaces.len());
        assert!(workspaces.len() >= 1, "Should have at least one workspace");

        // Check our test workspace is in the list
        let found_in_list = workspaces.iter().any(|ws| {
            ws.get("name").and_then(|v| v.as_str()) == Some(test_ws_name.as_str())
        });
        assert!(found_in_list, "Test workspace should be in list");
        println!("✓ Test workspace found in list");

        // Set workspace as current
        db.set_workspace(&test_ws_name).expect("Failed to set workspace");
        println!("✓ Set current workspace");

        // Get current workspace
        let current_ws = db.workspace().expect("Failed to get current workspace");
        assert_eq!(
            current_ws.get("name").and_then(|v| v.as_str()),
            Some(test_ws_name.as_str()),
            "Current workspace should be our test workspace"
        );
        println!("✓ Verified current workspace");

        // Delete the test workspace
        let ws_id = new_ws.get("id").and_then(|v| v.as_i64()).expect("Workspace should have ID");
        let deleted = db.delete_workspace(ws_id).expect("Failed to delete workspace");
        assert!(deleted, "Should successfully delete workspace");
        println!("✓ Deleted test workspace");

        // Verify workspace is gone
        let gone = db.find_workspace(&test_ws_name).expect("Failed to search for deleted workspace");
        assert!(gone.is_none(), "Deleted workspace should not be found");
        println!("✓ Verified workspace deleted");

        println!("✓ Workspace tests passed");
    }

    // =========================================================================
    // Sub-test 3: Host and service reporting (requires active database)
    // =========================================================================
    println!("\n=== Testing Host/Service Reporting ===");

    if !active {
        println!("⏭ Skipping host/service tests - database not active");
    } else {
        // Create a test workspace to isolate our test data
        let test_ws_name = format!("test_hosts_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        db.add_workspace(&test_ws_name).expect("Failed to create test workspace");
        db.set_workspace(&test_ws_name).expect("Failed to set workspace");
        println!("✓ Created and set test workspace: {}", test_ws_name);

        // Report a host
        let mut host_opts: HashMap<String, RubyVal> = HashMap::new();
        host_opts.insert("host".to_string(), RubyVal::String("192.168.1.100".to_string()));
        host_opts.insert("os_name".to_string(), RubyVal::String("Linux".to_string()));
        host_opts.insert("os_flavor".to_string(), RubyVal::String("Ubuntu".to_string()));

        let host_id = db.report_host(Some(host_opts)).expect("Failed to report host");
        println!("✓ Reported host 192.168.1.100, ID: {}", host_id);
        assert!(host_id > 0, "Host ID should be positive");

        // Query hosts
        let hosts = db.hosts().expect("Failed to query hosts");
        println!("✓ Found {} hosts in workspace", hosts.len());
        assert!(hosts.contains(&"192.168.1.100".to_string()), "Should find our reported host");

        // Report a service on the host
        let mut service_opts: HashMap<String, RubyVal> = HashMap::new();
        service_opts.insert("host".to_string(), RubyVal::String("192.168.1.100".to_string()));
        service_opts.insert("port".to_string(), RubyVal::Int(22));
        service_opts.insert("proto".to_string(), RubyVal::String("tcp".to_string()));
        service_opts.insert("name".to_string(), RubyVal::String("ssh".to_string()));

        let service_id = db.report_service(Some(service_opts)).expect("Failed to report service");
        println!("✓ Reported service SSH on port 22, ID: {}", service_id);
        assert!(service_id > 0, "Service ID should be positive");

        // Report another service
        let mut http_opts: HashMap<String, RubyVal> = HashMap::new();
        http_opts.insert("host".to_string(), RubyVal::String("192.168.1.100".to_string()));
        http_opts.insert("port".to_string(), RubyVal::Int(80));
        http_opts.insert("proto".to_string(), RubyVal::String("tcp".to_string()));
        http_opts.insert("name".to_string(), RubyVal::String("http".to_string()));

        db.report_service(Some(http_opts)).expect("Failed to report HTTP service");
        println!("✓ Reported service HTTP on port 80");

        // Query services
        let services = db.services().expect("Failed to query services");
        println!("✓ Found {} services", services.len());

        // Services are formatted as "host:port/proto"
        let has_ssh = services.iter().any(|s| s.contains("192.168.1.100:22/tcp"));
        let has_http = services.iter().any(|s| s.contains("192.168.1.100:80/tcp"));
        assert!(has_ssh, "Should find SSH service");
        assert!(has_http, "Should find HTTP service");
        println!("✓ Verified SSH and HTTP services");

        // Clean up - delete the test workspace
        let ws = db.find_workspace(&test_ws_name).expect("Failed to find workspace");
        if let Some(ws_obj) = ws {
            let ws_id = ws_obj.get("id").and_then(|v| v.as_i64()).unwrap();
            db.delete_workspace(ws_id).expect("Failed to delete workspace");
            println!("✓ Cleaned up test workspace");
        }

        println!("✓ Host/service reporting tests passed");
    }

    // =========================================================================
    // Sub-test 4: Single host query (get_host)
    // =========================================================================
    println!("\n=== Testing Single Host Query ===");

    if !active {
        println!("⏭ Skipping get_host tests - database not active");
    } else {
        // Create a test workspace to isolate our test data
        let test_ws_name = format!("test_get_host_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());

        db.add_workspace(&test_ws_name).expect("Failed to create test workspace");
        db.set_workspace(&test_ws_name).expect("Failed to set workspace");
        println!("✓ Created and set test workspace: {}", test_ws_name);

        // First report a host so we have something to query
        let mut host_opts: HashMap<String, RubyVal> = HashMap::new();
        host_opts.insert("host".to_string(), RubyVal::String("10.20.30.40".to_string()));
        host_opts.insert("os_name".to_string(), RubyVal::String("Windows".to_string()));
        host_opts.insert("os_flavor".to_string(), RubyVal::String("10 Pro".to_string()));

        let host_id = db.report_host(Some(host_opts)).expect("Failed to report host");
        println!("✓ Reported host 10.20.30.40, ID: {}", host_id);

        // Now test get_host for the host we just created
        println!("[*] Testing get_host for existing address...");
        match db.get_host("10.20.30.40") {
            Ok(result) => {
                match result {
                    Some(host) => {
                        println!("✓ Found host: {:?}", host);
                        assert!(host.get("address").is_some(), "Host should have address");
                        assert_eq!(
                            host.get("address").and_then(|v| v.as_str()),
                            Some("10.20.30.40"),
                            "Address should match"
                        );
                        // Check OS info was stored
                        if let Some(os_name) = host.get("os_name").and_then(|v| v.as_str()) {
                            println!("✓ OS name: {}", os_name);
                            assert_eq!(os_name, "Windows");
                        }
                    }
                    None => {
                        panic!("❌ get_host returned None for a host we just created!");
                    }
                }
            }
            Err(e) => {
                panic!("❌ get_host failed: {}", e);
            }
        }

        // Test get_host on a non-existent address
        println!("[*] Testing get_host for non-existent address...");
        match db.get_host("192.168.99.99") {
            Ok(result) => {
                assert!(result.is_none(), "Non-existent host should return None");
                println!("✓ Non-existent host returned None as expected");
            }
            Err(e) => {
                panic!("❌ get_host failed for non-existent address: {}", e);
            }
        }

        // Clean up - delete the test workspace
        let ws = db.find_workspace(&test_ws_name).expect("Failed to find workspace");
        if let Some(ws_obj) = ws {
            let ws_id = ws_obj.get("id").and_then(|v| v.as_i64()).unwrap();
            db.delete_workspace(ws_id).expect("Failed to delete workspace");
            println!("✓ Cleaned up test workspace");
        }
    }

    println!("✓ Single host query tests passed");

    // =========================================================================
    println!("\n✓ All database tests passed!");
}
