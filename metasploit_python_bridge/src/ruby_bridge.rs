use magnus::{exception, prelude::*, RString, Value, eval, embed};
use lazy_static::lazy_static;
use std::sync::Mutex;

/// Global Ruby interpreter state
lazy_static! {
    static ref RUBY: Mutex<Option<magnus::embed::Cleanup>> = Mutex::new(None);
}

/// Initializes the Ruby interpreter and loads Metasploit
pub unsafe fn init_ruby() {
    let ruby = embed::init();

    // Path to Metasploit source
    let metasploit_path = "/home/aus/PycharmProjects/assassinate/metasploit-framework/lib";  // Update this if necessary

    // Add Metasploit to Ruby's $LOAD_PATH
    let add_path_script = format!(r#"$LOAD_PATH.unshift('{}')"#, metasploit_path);
    eval::<Value>(&add_path_script).expect("Failed to add Metasploit to $LOAD_PATH");

    // Attempt to load Metasploit Framework
    if let Err(e) = eval::<Value>("require 'metasploit/framework'") {
        panic!("Failed to load Metasploit Framework: {:?}", e);
    }

    // Debugging: Print all loaded constants
    let loaded_constants: Value = eval("Module.constants").expect("Failed to get Ruby constants");
    println!("Loaded Ruby Constants: {:?}", loaded_constants);

    *RUBY.lock().unwrap() = Some(ruby);
}

/// Retrieves the Metasploit version from the Ruby environment
pub fn get_metasploit_version() -> Result<String, magnus::Error> {
    let ruby = RUBY.lock().unwrap();
    if ruby.is_some() {
        let version: RString = magnus::eval("Metasploit::Framework::Version.version")?;
        return Ok(version.to_string()?);
    }
    Err(magnus::Error::new(exception::runtime_error(), "Ruby not initialized"))
}

/// Lists all available Metasploit modules
pub fn list_metasploit_modules() -> Result<String, magnus::Error> {
    let ruby = RUBY.lock().unwrap();
    if ruby.is_some() {
        let modules: RString = magnus::eval("Metasploit::Framework::DataService.list_modules")?;
        return Ok(modules.to_string()?);
    }
    Err(magnus::Error::new(exception::runtime_error(), "Ruby not initialized"))
}

/// Runs a Metasploit module with specified options
pub fn run_metasploit_module(module: &str, options: &str) -> Result<String, magnus::Error> {
    let ruby = RUBY.lock().unwrap();
    if ruby.is_some() {
        let script = format!(
            "Metasploit::Framework::Simple.run_module('{}', JSON.parse('{}'))",
            module, options
        );
        let result: RString = magnus::eval(&script)?;
        return Ok(result.to_string()?);
    }
    Err(magnus::Error::new(exception::runtime_error(), "Ruby not initialized"))
}
