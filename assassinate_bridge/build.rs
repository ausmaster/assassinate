use std::env;
use std::process::Command;

fn main() {
    // Determine Ruby command to use:
    // 1. Check RUBY environment variable (for custom setups, e.g., export RUBY=/path/to/ruby)
    // 2. Fall back to "ruby" in PATH (system Ruby or rbenv/rvm if configured in PATH)
    let ruby_cmd = env::var("RUBY").unwrap_or_else(|_| "ruby".to_string());

    println!("cargo:warning=Using Ruby: {}", ruby_cmd);

    // Get Ruby library configuration
    let output = Command::new(&ruby_cmd)
        .args(["-e", "require 'rbconfig'; puts RbConfig::CONFIG['libdir']"])
        .output()
        .expect("Failed to execute ruby command");

    let libdir = String::from_utf8(output.stdout)
        .expect("Invalid UTF-8 in ruby output")
        .trim()
        .to_string();

    // Tell Cargo where to find Ruby library
    println!("cargo:rustc-link-search=native={}", libdir);
    println!("cargo:rustc-link-lib=dylib=ruby");

    // Set environment variable for rb-sys to use the correct Ruby
    env::set_var("RUBY", &ruby_cmd);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RUBY");
}
