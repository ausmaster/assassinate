// Test: System and Network Information
// Tests Meterpreter system info and network config operations

mod common;

use bridge::{ruby_bridge, Session};
use magnus::value::ReprValue;

#[test]
fn it_gets_system_and_network_info() {
    // Use the common initialization helper - returns (Ruby, Value)
    let (ruby, framework) = common::init_framework();

    println!("✓ Framework initialized");

    // Get sessions manager using raw Ruby call
    let sessions_val = ruby_bridge::call_method(framework, "sessions", &[])
        .expect("Failed to get sessions");

    // List sessions - get keys
    let session_keys = ruby_bridge::call_method(sessions_val, "keys", &[])
        .expect("Failed to get session keys");
    let session_ids: Vec<i64> = magnus::TryConvert::try_convert(session_keys)
        .expect("Failed to convert session IDs");

    if session_ids.is_empty() {
        println!("⚠ No active sessions - skipping test");
        println!("  This test requires an active Meterpreter session");
        println!("  Run a module that creates a session first, then run this test");
        return;
    }

    println!("✓ Found {} session(s)", session_ids.len());

    // Get the first session
    let session_id = session_ids[0];
    let id_val = ruby.eval::<magnus::Value>(&format!("{}", session_id))
        .expect("Failed to convert session ID");
    let session_val = ruby_bridge::call_method(sessions_val, "[]", &[id_val])
        .expect("Failed to get session");

    if ruby_bridge::is_nil(session_val) {
        println!("⚠ Session not found - skipping test");
        return;
    }

    // Wrap in Session struct
    let session = Session::from_raw(session_val, session_id);

    println!("✓ Got session {}", session_id);

    // Check if it's a Meterpreter session
    let session_type = session.session_type().expect("Failed to get session type");
    println!("  Session type: {}", session_type);

    if !session_type.contains("meterpreter") {
        println!("⚠ Not a Meterpreter session - skipping Meterpreter-specific tests");
        return;
    }

    // ========== System Information Tests ==========
    println!("\n=== Testing System Information ===");

    // Test sysinfo
    match session.sys_sysinfo() {
        Ok(sysinfo) => {
            println!("✓ sysinfo: {}", sysinfo);
            assert!(sysinfo.is_object(), "sysinfo should be an object");

            // Verify expected keys exist
            let obj = sysinfo.as_object().unwrap();
            if let Some(os) = obj.get("OS") {
                println!("  OS: {}", os);
            }
            if let Some(arch) = obj.get("Architecture") {
                println!("  Architecture: {}", arch);
            }
            if let Some(computer) = obj.get("Computer") {
                println!("  Computer: {}", computer);
            }
        }
        Err(e) => println!("⚠ sysinfo failed: {} (may not be supported on this target)", e),
    }

    // Test getuid
    match session.sys_getuid() {
        Ok(uid) => {
            println!("✓ getuid: {}", uid);
            assert!(!uid.is_empty(), "UID should not be empty");
        }
        Err(e) => println!("⚠ getuid failed: {}", e),
    }

    // Test localtime
    match session.sys_localtime() {
        Ok(localtime) => {
            println!("✓ localtime: {}", localtime);
            assert!(!localtime.is_empty(), "localtime should not be empty");
        }
        Err(e) => println!("⚠ localtime failed: {}", e),
    }

    // Test getenv
    match session.sys_getenv("PATH") {
        Ok(Some(path)) => {
            println!("✓ getenv(PATH): {} (truncated)", &path[0..path.len().min(50)]);
            assert!(!path.is_empty(), "PATH should not be empty");
        }
        Ok(None) => println!("⚠ PATH not found"),
        Err(e) => println!("⚠ getenv failed: {}", e),
    }

    // Test getenvs
    match session.sys_getenvs(vec!["PATH".to_string(), "HOME".to_string(), "USER".to_string()]) {
        Ok(envs) => {
            println!("✓ getenvs: got {} variables", envs.len());
            for (key, value) in envs.iter() {
                println!("  {}: {} (truncated)", key, &value[0..value.len().min(50)]);
            }
        }
        Err(e) => println!("⚠ getenvs failed: {}", e),
    }

    // Test getsid (Windows only)
    match session.sys_getsid() {
        Ok(sid) => {
            println!("✓ getsid: {}", sid);
            assert!(!sid.is_empty(), "SID should not be empty");
        }
        Err(e) => println!("⚠ getsid failed: {} (may be Windows-only)", e),
    }

    // Test is_system (Windows only)
    match session.sys_is_system() {
        Ok(is_system) => {
            println!("✓ is_system: {}", is_system);
        }
        Err(e) => println!("⚠ is_system failed: {} (may be Windows-only)", e),
    }

    // Test getprivs (Windows only)
    match session.sys_getprivs() {
        Ok(privs) => {
            println!("✓ getprivs: got {} privileges", privs.len());
            for (i, priv_name) in privs.iter().enumerate().take(5) {
                println!("  [{}] {}", i, priv_name);
            }
            if privs.len() > 5 {
                println!("  ... and {} more", privs.len() - 5);
            }
        }
        Err(e) => println!("⚠ getprivs failed: {} (may be Windows-only)", e),
    }

    // Test getdrivers (Windows only)
    match session.sys_getdrivers() {
        Ok(drivers) => {
            println!("✓ getdrivers: got {} drivers", drivers.len());
            for (i, driver) in drivers.iter().enumerate().take(5) {
                println!("  [{}] {}", i, driver);
            }
            if drivers.len() > 5 {
                println!("  ... and {} more", drivers.len() - 5);
            }
        }
        Err(e) => println!("⚠ getdrivers failed: {} (may be Windows-only)", e),
    }

    // ========== Network Configuration Tests ==========
    println!("\n=== Testing Network Configuration ===");

    // Test get_interfaces
    match session.net_get_interfaces() {
        Ok(interfaces) => {
            println!("✓ get_interfaces: got {} interfaces", interfaces.len());
            for (i, iface) in interfaces.iter().enumerate() {
                let iface_obj = iface.as_object().unwrap();
                let name = iface_obj.get("mac_name").and_then(|v| v.as_str()).unwrap_or("unknown");
                let addrs = iface_obj.get("addrs").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                println!("  [{}] {} ({} addresses)", i, name, addrs);
            }
            assert!(!interfaces.is_empty(), "Should have at least one interface");
        }
        Err(e) => println!("⚠ get_interfaces failed: {}", e),
    }

    // Test get_routes
    match session.net_get_routes() {
        Ok(routes) => {
            println!("✓ get_routes: got {} routes", routes.len());
            for (i, route) in routes.iter().enumerate().take(5) {
                let route_obj = route.as_object().unwrap();
                let subnet = route_obj.get("subnet").and_then(|v| v.as_str()).unwrap_or("unknown");
                let gateway = route_obj.get("gateway").and_then(|v| v.as_str()).unwrap_or("unknown");
                println!("  [{}] {} via {}", i, subnet, gateway);
            }
            if routes.len() > 5 {
                println!("  ... and {} more", routes.len() - 5);
            }
        }
        Err(e) => println!("⚠ get_routes failed: {}", e),
    }

    // Test get_arp_table
    match session.net_get_arp_table() {
        Ok(arps) => {
            println!("✓ get_arp_table: got {} entries", arps.len());
            for (i, arp) in arps.iter().enumerate().take(5) {
                let arp_obj = arp.as_object().unwrap();
                let ip = arp_obj.get("ip_addr").and_then(|v| v.as_str()).unwrap_or("unknown");
                let mac = arp_obj.get("mac_addr").and_then(|v| v.as_str()).unwrap_or("unknown");
                println!("  [{}] {} -> {}", i, ip, mac);
            }
            if arps.len() > 5 {
                println!("  ... and {} more", arps.len() - 5);
            }
        }
        Err(e) => println!("⚠ get_arp_table failed: {}", e),
    }

    // Test get_netstat
    match session.net_get_netstat() {
        Ok(connections) => {
            println!("✓ get_netstat: got {} connections", connections.len());
            for (i, conn) in connections.iter().enumerate().take(5) {
                let conn_obj = conn.as_object().unwrap();
                let local = conn_obj.get("local_addr").and_then(|v| v.as_str()).unwrap_or("unknown");
                let remote = conn_obj.get("remote_addr").and_then(|v| v.as_str()).unwrap_or("unknown");
                let proto = conn_obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("unknown");
                let state = conn_obj.get("state").and_then(|v| v.as_str()).unwrap_or("unknown");
                println!("  [{}] {} -> {} ({}/{})", i, local, remote, proto, state);
            }
            if connections.len() > 5 {
                println!("  ... and {} more", connections.len() - 5);
            }
        }
        Err(e) => println!("⚠ get_netstat failed: {}", e),
    }

    // Test get_proxy_config (Windows only)
    match session.net_get_proxy_config() {
        Ok(proxy_config) => {
            println!("✓ get_proxy_config: {}", proxy_config);
        }
        Err(e) => println!("⚠ get_proxy_config failed: {} (may be Windows-only)", e),
    }

    // Verify we can get the Ruby handle (confirms VM is working)
    let _ = ruby.str_new("test").as_value();
    println!("\n✓ Ruby VM still operational");

    println!("\n✅ System and network information tests completed");
}
