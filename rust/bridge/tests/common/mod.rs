// Common test utilities for Assassinate bridge tests
// Following Magnus's testing pattern: each test file = separate process

use std::env;

/// Get MSF path from environment variable or use default
pub fn get_msf_path() -> String {
    env::var("MSF_ROOT").unwrap_or_else(|_| "/tmp/metasploit-framework".to_string())
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
