// Common test utilities for Assassinate bridge tests
// Following Magnus's testing pattern: each test file = separate process

use std::env;

/// Get MSF path from environment variable or use default
pub fn get_msf_path() -> String {
    env::var("MSF_ROOT").unwrap_or_else(|_| "/opt/metasploit-framework".to_string())
}

/// Initialize Ruby VM and Metasploit Framework
/// Call this at the start of each test file
/// Uses bridge::ruby_bridge::init_ruby() which has proper Once guard
pub fn init_msf() -> magnus::Ruby {
    // Use the bridge's init_ruby which handles Once guard properly
    bridge::ruby_bridge::init_ruby().expect("Failed to initialize Ruby");

    let ruby = magnus::Ruby::get().expect("Failed to get Ruby handle");

    let msf_path = get_msf_path();
    bridge::ruby_bridge::init_metasploit(&msf_path)
        .expect("Failed to initialize Metasploit");

    ruby
}

/// Initialize and create a framework instance
pub fn init_framework() -> (magnus::Ruby, magnus::Value) {
    let ruby = init_msf();
    let framework = bridge::ruby_bridge::create_framework(None)
        .expect("Failed to create framework");
    (ruby, framework)
}

// =============================================================================
// Integration Test Helpers
// =============================================================================

/// Check if integration tests are enabled via INTEGRATION_TESTS env var
pub fn is_integration_env() -> bool {
    env::var("INTEGRATION_TESTS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Get target host from environment (defaults to assassinate-target for Docker)
pub fn get_target_host() -> String {
    env::var("TARGET_HOST").unwrap_or_else(|_| "assassinate-target".to_string())
}

/// Get target FTP port (defaults to 21)
pub fn get_target_ftp_port() -> u16 {
    env::var("TARGET_FTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(21)
}

/// Get target shell listener port (defaults to 4445)
pub fn get_target_shell_port() -> u16 {
    env::var("TARGET_SHELL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4445)
}

/// Skip test if not in integration environment
/// Returns Some(target_info) if integration tests are enabled, None otherwise
pub fn require_integration_env() -> Option<IntegrationEnv> {
    if !is_integration_env() {
        println!("⚠ Skipping integration test (INTEGRATION_TESTS != true)");
        println!("  Set INTEGRATION_TESTS=true and ensure target container is running");
        return None;
    }

    Some(get_integration_env())
}

/// Get integration environment
pub fn get_integration_env() -> IntegrationEnv {
    IntegrationEnv {
        target_host: get_target_host(),
        ftp_port: get_target_ftp_port(),
        shell_port: get_target_shell_port(),
    }
}

/// Integration test environment configuration
#[derive(Debug, Clone)]
pub struct IntegrationEnv {
    pub target_host: String,
    pub ftp_port: u16,
    pub shell_port: u16,
}
