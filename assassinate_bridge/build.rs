use std::env;
use std::process::Command;

fn main() {
    // Determine Ruby command to use:
    // 1. Check RUBY environment variable (for CI or custom setups)
    // 2. Try rbenv Ruby 3.3.8 if it exists (local development)
    // 3. Fall back to "ruby" in PATH (system Ruby)
    let ruby_cmd = if let Ok(ruby_env) = env::var("RUBY") {
        ruby_env
    } else {
        let rbenv_ruby = "/home/aus/.rbenv/versions/3.3.8/bin/ruby";
        if std::path::Path::new(rbenv_ruby).exists() {
            rbenv_ruby.to_string()
        } else {
            "ruby".to_string()
        }
    };

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
