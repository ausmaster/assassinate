use magnus::value::ReprValue;
use magnus::{Error, RArray, RHash, Ruby, Value};
use std::sync::OnceLock;

static RUBY_INIT: OnceLock<()> = OnceLock::new();

pub fn ensure_ruby() -> Result<(), Error> {
    RUBY_INIT.get_or_init(|| {
        let cleanup = unsafe { magnus::embed::init() };
        std::mem::forget(cleanup);
    });

    Ok(())
}

pub fn init_ruby(load_paths: &[String], env_vars: &[(String, String)]) -> Result<(), Error> {
    ensure_ruby()?;

    let ruby = unsafe { Ruby::get_unchecked() };
    let env_hash: RHash = ruby.eval("ENV")?;
    let load_path: RArray = ruby.eval("$LOAD_PATH")?;

    for (key, value) in env_vars {
        env_hash.funcall::<_, _, Value>("[]=", (key.as_str(), value.as_str()))?;
    }

    for path in load_paths {
        let exists: bool = load_path.funcall("include?", (path.as_str(),))?;
        if !exists {
            load_path.funcall::<_, _, Value>("unshift", (path.as_str(),))?;
        }
    }

    Ok(())
}

pub fn require_all(requires: &[String]) -> Result<(), Error> {
    ensure_ruby()?;

    let ruby = unsafe { Ruby::get_unchecked() };
    let kernel: Value = ruby.eval("Kernel")?;

    for req in requires {
        kernel.funcall::<_, _, Value>("require", (req.as_str(),))?;
    }

    Ok(())
}
