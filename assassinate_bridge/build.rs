use std::env;
use std::process::Command;

fn main() {
    // Use rbenv Ruby 3.3.8 explicitly
    let ruby_cmd = "/home/aus/.rbenv/versions/3.3.8/bin/ruby";

    // Get Ruby library configuration
    let output = Command::new(ruby_cmd)
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
    env::set_var("RUBY", ruby_cmd);

    println!("cargo:rerun-if-changed=build.rs");
}
