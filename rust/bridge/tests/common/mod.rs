// Common test utilities for Assassinate bridge tests
// Magnus pattern: each test file = separate process (Ruby VM can only init once)

use std::env;

/// Get MSF path from environment variable or use default
pub fn get_msf_path() -> String {
    env::var("MSF_ROOT").unwrap_or_else(|_| "/opt/metasploit-framework".to_string())
}

/// Initialize Ruby VM and Metasploit Framework
/// Call this at the start of each test file
pub fn init_msf() -> magnus::Ruby {
    bridge::ruby_bridge::init_ruby().expect("Failed to initialize Ruby");

    let ruby = magnus::Ruby::get().expect("Failed to get Ruby handle");

    let msf_path = get_msf_path();
    bridge::ruby_bridge::init_metasploit(&msf_path).expect("Failed to initialize Metasploit");

    ruby
}
