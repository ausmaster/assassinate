use log::{debug, error, info, trace};
use magnus::value::ReprValue;
use magnus::{Error, RArray, RHash, Ruby, Value};
use std::sync::OnceLock;

static RUBY_INIT: OnceLock<()> = OnceLock::new();

/// Ensure Ruby VM is initialized (one-time operation)
pub fn ensure_ruby() -> Result<(), Error> {
    let was_initialized = RUBY_INIT.get().is_some();

    RUBY_INIT.get_or_init(|| {
        info!(target: "msf::ruby", "Initializing embedded Ruby VM");
        let cleanup = unsafe { magnus::embed::init() };
        std::mem::forget(cleanup);
    });

    if !was_initialized {
        debug!(target: "msf::ruby", "Ruby VM initialized successfully");
    }

    Ok(())
}

/// Initialize Ruby environment with load paths and environment variables
pub fn init_ruby(load_paths: &[String], env_vars: &[(String, String)]) -> Result<(), Error> {
    trace!(target: "msf::ruby", "init_ruby() called with {} load paths, {} env vars",
           load_paths.len(), env_vars.len());

    ensure_ruby()?;

    let ruby = unsafe { Ruby::get_unchecked() };
    let env_hash: RHash = ruby.eval("ENV")?;
    let load_path: RArray = ruby.eval("$LOAD_PATH")?;

    for (key, value) in env_vars {
        debug!(target: "msf::ruby", "Setting ENV[{}]", key);
        env_hash.funcall::<_, _, Value>("[]=", (key.as_str(), value.as_str()))?;
    }

    for path in load_paths {
        let exists: bool = load_path.funcall("include?", (path.as_str(),))?;
        if !exists {
            debug!(target: "msf::ruby", "Adding load path: {}", path);
            load_path.funcall::<_, _, Value>("unshift", (path.as_str(),))?;
        }
    }

    info!(target: "msf::ruby", "Ruby environment configured");
    Ok(())
}

/// Require Ruby files/gems
pub fn require_all(requires: &[String]) -> Result<(), Error> {
    trace!(target: "msf::ruby", "require_all() called with {} requires", requires.len());

    ensure_ruby()?;

    let ruby = unsafe { Ruby::get_unchecked() };
    let kernel: Value = ruby.eval("Kernel")?;

    for req in requires {
        debug!(target: "msf::ruby", "Requiring: {}", req);
        match kernel.funcall::<_, _, Value>("require", (req.as_str(),)) {
            Ok(_) => trace!(target: "msf::ruby", "Required {} successfully", req),
            Err(e) => {
                error!(target: "msf::ruby", "Failed to require {}: {}", req, e);
                return Err(e);
            }
        }
    }

    info!(target: "msf::ruby", "All requires loaded successfully");
    Ok(())
}
