//! Session management types and operations
//!
//! This module contains:
//! - SessionManager - manages collection of sessions
//! - Session - individual session with FS, Process, and Post module operations

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{
    call_bool_with_str, call_method, call_str_with_str, call_strings_with_str, call_void_with_str,
    get_i64_attr, get_string_attr, is_nil, to_ruby_str, value_to_bool, value_to_string,
};
use magnus::{value::ReprValue, TryConvert, Value};

/// Session manager for listing and accessing sessions
#[derive(Clone)]
pub struct SessionManager {
    pub(crate) ruby_sessions: Value,
}

impl SessionManager {
    /// List all session IDs
    pub fn list(&self) -> Result<Vec<i64>> {
        let keys_val = call_method(self.ruby_sessions, "keys", &[])?;

        let session_ids: Vec<i64> =
            TryConvert::try_convert(keys_val).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert session IDs: {}", e))
            })?;

        Ok(session_ids)
    }

    /// Get a session by ID
    pub fn get(&self, session_id: i64) -> Result<Option<Session>> {
        let id_val = crate::ruby_bridge::get_ruby()?
            .eval::<Value>(&format!("{}", session_id))
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
            })?;

        let session_val = call_method(self.ruby_sessions, "[]", &[id_val])?;

        // Check if nil
        if is_nil(session_val) {
            Ok(None)
        } else {
            Ok(Some(Session {
                ruby_session: session_val,
                session_id,
            }))
        }
    }

    /// Kill a session by ID
    pub fn kill(&self, session_id: i64) -> Result<bool> {
        let id_val = crate::ruby_bridge::get_ruby()?
            .eval::<Value>(&format!("{}", session_id))
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
            })?;

        // Call delete method on sessions hash
        let result_val = call_method(self.ruby_sessions, "delete", &[id_val])?;

        // If delete returns nil, session didn't exist
        Ok(!is_nil(result_val))
    }

    /// Get a session by ID (raw version without PyO3)
    pub fn get_raw(&self, session_id: i64) -> Result<Option<Value>> {
        let id_val = crate::ruby_bridge::get_ruby()?
            .eval::<Value>(&format!("{}", session_id))
            .map_err(|e| {
                AssassinateError::ConversionError(format!("Failed to convert session ID: {}", e))
            })?;

        let session_val = call_method(self.ruby_sessions, "[]", &[id_val])?;

        // Check if nil
        if is_nil(session_val) {
            Ok(None)
        } else {
            Ok(Some(session_val))
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!("<SessionManager count={}>", self.list()?.len()))
    }
}

/// Individual session with FS, Process, and Post module operations
#[derive(Clone)]
pub struct Session {
    pub(crate) ruby_session: Value,
    pub session_id: i64,
}

impl Session {
    /// Get session type
    pub fn session_type(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "type")
    }

    /// Get session info
    pub fn info(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "info")
    }

    /// Check if session is alive
    pub fn alive(&self) -> Result<bool> {
        crate::ruby_bridge::get_bool_attr(self.ruby_session, "alive?")
    }

    /// Kill the session
    pub fn kill(&self) -> Result<()> {
        call_method(self.ruby_session, "kill", &[])?;
        Ok(())
    }

    /// Write data to the session
    pub fn write(&self, data: &str) -> Result<usize> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let data_val = ruby.str_new(data).as_value();

        let result = call_method(self.ruby_session, "write", &[data_val])?;

        // Try to convert to integer (bytes written)
        let bytes_written: i64 = TryConvert::try_convert(result).unwrap_or(data.len() as i64);

        Ok(bytes_written as usize)
    }

    /// Read data from the session
    pub fn read(&self, length: Option<usize>) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        let result = if let Some(len) = length {
            let len_val = ruby
                .eval::<Value>(&format!("{}", len))
                .map_err(|e| AssassinateError::ConversionError(e.to_string()))?;
            call_method(self.ruby_session, "read", &[len_val])?
        } else {
            call_method(self.ruby_session, "read", &[])?
        };

        if is_nil(result) {
            Ok(String::new())
        } else {
            Ok(value_to_string(result)?)
        }
    }

    /// Execute a command in the session (shell command)
    pub fn execute(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Write command
        self.write(&format!("{}\n", command))?;

        // Give it time to execute (you may want to make this configurable)
        ruby.eval::<Value>("sleep 0.5")
            .map_err(|e| AssassinateError::RubyError(e.to_string()))?;

        // Read response
        self.read(None)
    }

    /// Run a Meterpreter command (if it's a meterpreter session)
    pub fn run_cmd(&self, command: &str) -> Result<String> {
        let ruby = crate::ruby_bridge::get_ruby()?;
        let cmd_val = ruby.str_new(command).as_value();

        let result = call_method(self.ruby_session, "run_cmd", &[cmd_val])?;

        if is_nil(result) {
            Ok(String::new())
        } else {
            Ok(value_to_string(result)?)
        }
    }

    /// Get session description
    pub fn desc(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "desc")
    }

    /// Get tunnel peer (remote address)
    pub fn tunnel_peer(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "tunnel_peer")
    }

    /// Get target host
    pub fn target_host(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "target_host")
    }

    /// Get session host
    pub fn session_host(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "session_host")
    }

    /// Get session port
    pub fn session_port(&self) -> Result<i64> {
        get_i64_attr(self.ruby_session, "session_port")
    }

    /// Get exploit that created this session
    pub fn via_exploit(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "via_exploit")
    }

    /// Get payload that created this session
    pub fn via_payload(&self) -> Result<String> {
        get_string_attr(self.ruby_session, "via_payload")
    }

    /// Create Session from raw Ruby value (for daemon use)
    pub fn from_raw(session_val: Value, session_id: i64) -> Self {
        Session {
            ruby_session: session_val,
            session_id,
        }
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok(format!(
            "<Session id={} type='{}' alive={}>",
            self.session_id,
            self.session_type()?,
            self.alive()?
        ))
    }

    // ========== Meterpreter Extension Helpers (DRY) ==========

    /// Get the fs extension object (caches fs access pattern)
    fn fs(&self) -> Result<Value> {
        call_method(self.ruby_session, "fs", &[])
    }

    /// Get fs.dir for directory operations
    fn fs_dir_ext(&self) -> Result<Value> {
        call_method(self.fs()?, "dir", &[])
    }

    /// Get fs.file for file operations
    fn fs_file_ext(&self) -> Result<Value> {
        call_method(self.fs()?, "file", &[])
    }

    /// Get the sys extension object for system operations
    fn sys(&self) -> Result<Value> {
        call_method(self.ruby_session, "sys", &[])
    }

    /// Get sys.process for process operations
    fn sys_process(&self) -> Result<Value> {
        call_method(self.sys()?, "process", &[])
    }

    /// Get sys.config for system configuration
    #[allow(dead_code)]
    fn sys_config(&self) -> Result<Value> {
        call_method(self.sys()?, "config", &[])
    }

    /// Get the net extension object for network operations
    #[allow(dead_code)]
    fn net(&self) -> Result<Value> {
        call_method(self.ruby_session, "net", &[])
    }

    /// Get net.config for network configuration
    #[allow(dead_code)]
    fn net_config(&self) -> Result<Value> {
        call_method(self.net()?, "config", &[])
    }

    /// Check if this session has a specific extension/method
    #[allow(dead_code)]
    fn has_extension(&self, name: &str) -> Result<bool> {
        let method_name = to_ruby_str(name)?;
        let result = call_method(self.ruby_session, "respond_to?", &[method_name])?;
        value_to_bool(result)
    }

    // ========== Meterpreter Filesystem Operations ==========

    /// Get current working directory (pwd)
    /// Only works on Meterpreter sessions
    pub fn fs_pwd(&self) -> Result<String> {
        get_string_attr(self.fs_dir_ext()?, "pwd")
    }

    /// Change working directory (chdir)
    /// Only works on Meterpreter sessions
    pub fn fs_chdir(&self, path: &str) -> Result<()> {
        call_void_with_str(self.fs_dir_ext()?, "chdir", path)
    }

    /// List directory contents
    /// Returns list of filenames (strings)
    /// Only works on Meterpreter sessions
    pub fn fs_ls(&self, path: &str) -> Result<Vec<String>> {
        call_strings_with_str(self.fs_dir_ext()?, "entries", path)
    }

    /// Create directory
    /// Only works on Meterpreter sessions
    pub fn fs_mkdir(&self, path: &str) -> Result<()> {
        call_void_with_str(self.fs_dir_ext()?, "mkdir", path)
    }

    /// Remove directory (must be empty)
    /// Only works on Meterpreter sessions
    pub fn fs_rmdir(&self, path: &str) -> Result<()> {
        call_void_with_str(self.fs_dir_ext()?, "rmdir", path)
    }

    /// Get file/directory metadata (stat)
    /// Returns JSON with file info: size, ftype, mtime, is_file, is_directory
    /// Only works on Meterpreter sessions
    pub fn fs_stat(&self, path: &str) -> Result<serde_json::Value> {
        let stat_val = call_method(self.fs_file_ext()?, "stat", &[to_ruby_str(path)?])?;

        // Extract stat attributes
        let mut stat_obj = serde_json::Map::new();

        // Size
        if let Ok(size_val) = call_method(stat_val, "size", &[]) {
            let size: i64 = TryConvert::try_convert(size_val).unwrap_or(0);
            stat_obj.insert("size".to_string(), serde_json::json!(size));
        }

        // File type
        if let Ok(ftype_val) = call_method(stat_val, "ftype", &[]) {
            if let Ok(ftype) = value_to_string(ftype_val) {
                stat_obj.insert("ftype".to_string(), serde_json::json!(ftype));
            }
        }

        // Modified time
        if let Ok(mtime_val) = call_method(stat_val, "mtime", &[]) {
            if let Ok(mtime_str) = value_to_string(call_method(mtime_val, "to_s", &[])?) {
                stat_obj.insert("mtime".to_string(), serde_json::json!(mtime_str));
            }
        }

        // Check type predicates
        if let Ok(is_file_val) = call_method(stat_val, "file?", &[]) {
            if let Ok(is_file) = value_to_bool(is_file_val) {
                stat_obj.insert("is_file".to_string(), serde_json::json!(is_file));
            }
        }

        if let Ok(is_dir_val) = call_method(stat_val, "directory?", &[]) {
            if let Ok(is_dir) = value_to_bool(is_dir_val) {
                stat_obj.insert("is_directory".to_string(), serde_json::json!(is_dir));
            }
        }

        Ok(serde_json::Value::Object(stat_obj))
    }

    /// Check if file/directory exists
    /// Only works on Meterpreter sessions
    pub fn fs_exists(&self, path: &str) -> Result<bool> {
        call_bool_with_str(self.fs_file_ext()?, "exist?", path)
    }

    /// Delete file
    /// Only works on Meterpreter sessions
    pub fn fs_rm(&self, path: &str) -> Result<()> {
        call_void_with_str(self.fs_file_ext()?, "rm", path)
    }

    /// Move/rename file
    /// Only works on Meterpreter sessions
    pub fn fs_mv(&self, old_path: &str, new_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "mv",
            &[to_ruby_str(old_path)?, to_ruby_str(new_path)?],
        )?;
        Ok(())
    }

    /// Copy file
    /// Only works on Meterpreter sessions
    pub fn fs_cp(&self, src_path: &str, dst_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "cp",
            &[to_ruby_str(src_path)?, to_ruby_str(dst_path)?],
        )?;
        Ok(())
    }

    /// Get path separator for target system
    /// Returns "\\" on Windows, "/" on Unix
    /// Only works on Meterpreter sessions
    pub fn fs_separator(&self) -> Result<String> {
        get_string_attr(self.fs_file_ext()?, "separator")
    }

    /// Expand path (resolve environment variables like %appdata%, $HOME)
    /// Only works on Meterpreter sessions
    pub fn fs_expand_path(&self, path: &str) -> Result<String> {
        call_str_with_str(self.fs_file_ext()?, "expand_path", path)
    }

    /// Download file from remote to local
    /// Only works on Meterpreter sessions
    pub fn fs_download_file(&self, local_path: &str, remote_path: &str) -> Result<String> {
        let status_val = call_method(
            self.fs_file_ext()?,
            "download_file",
            &[to_ruby_str(local_path)?, to_ruby_str(remote_path)?],
        )?;
        // download_file returns status string: "Completed", "Skipped", etc.
        value_to_string(status_val)
    }

    /// Upload file from local to remote
    /// Only works on Meterpreter sessions
    pub fn fs_upload_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        call_method(
            self.fs_file_ext()?,
            "upload_file",
            &[to_ruby_str(remote_path)?, to_ruby_str(local_path)?],
        )?;
        Ok(())
    }

    // ========== Post Module Execution ==========

    /// Run a post module on this session
    ///
    /// This is used for post-exploitation tasks like:
    /// - Upgrading shell to meterpreter (post/multi/manage/shell_to_meterpreter)
    /// - Gathering credentials
    /// - Privilege escalation
    /// - Persistence
    ///
    /// The module will automatically have its SESSION datastore option set to this session.
    pub fn run_post_module(
        &self,
        module_path: &str,
        options: std::collections::HashMap<String, String>,
    ) -> Result<bool> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Get framework
        let framework = crate::ruby_bridge::create_framework(None)?;

        // Get modules
        let modules = call_method(framework, "modules", &[])?;

        // Create the post module
        let module_name = ruby.str_new(module_path).as_value();
        let module = call_method(modules, "create", &[module_name])?;

        if is_nil(module) {
            return Err(AssassinateError::ModuleNotFound(module_path.to_string()));
        }

        // Set SESSION datastore option to this session's ID
        let datastore = call_method(module, "datastore", &[])?;
        call_method(
            datastore,
            "[]=",
            &[
                ruby.str_new("SESSION").as_value(),
                ruby.integer_from_i64(self.session_id).as_value(),
            ],
        )?;

        // Set additional options
        for (key, value) in options {
            let key_val = ruby.str_new(&key).as_value();
            let value_val = ruby.str_new(&value).as_value();
            call_method(datastore, "[]=", &[key_val, value_val])?;
        }

        // Run the module
        let result = call_method(module, "run", &[])?;

        // Check if nil (failure) or has a value (success)
        Ok(!is_nil(result))
    }

    // ========== Process Management (Meterpreter) ==========

    /// Get the current process ID (getpid)
    /// Only works on Meterpreter sessions
    pub fn process_getpid(&self) -> Result<i64> {
        let pid_val = call_method(self.sys_process()?, "getpid", &[])?;
        crate::ruby_bridge::value_to_i64(pid_val)
    }

    /// List all running processes
    /// Returns Vec of JSON objects with keys: pid, ppid, name, path, user, session, arch
    /// Only works on Meterpreter sessions
    pub fn process_list(&self) -> Result<Vec<serde_json::Value>> {
        let processes = call_method(self.sys_process()?, "get_processes", &[])?;
        let len = crate::ruby_bridge::ruby_array_len(processes)?;

        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let process = crate::ruby_bridge::ruby_array_get(processes, i)?;
            let process_json = crate::ruby_bridge::hash_to_json(process)?;
            result.push(process_json);
        }

        Ok(result)
    }

    /// Kill a process by PID
    /// Only works on Meterpreter sessions
    pub fn process_kill(&self, pid: i64) -> Result<()> {
        call_method(
            self.sys_process()?,
            "kill",
            &[crate::ruby_bridge::to_ruby_int(pid)?],
        )?;
        Ok(())
    }

    /// Execute a command and return the process info
    /// Returns JSON with: pid, handle, channel_id (if channelized)
    /// Only works on Meterpreter sessions
    pub fn process_execute(
        &self,
        path: &str,
        args: &str,
        hidden: bool,
        channelized: bool,
    ) -> Result<serde_json::Value> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Build options hash
        let opts_hash = ruby.hash_new();
        if hidden {
            call_method(
                opts_hash.as_value(),
                "[]=",
                &[to_ruby_str("Hidden")?, ruby.qtrue().as_value()],
            )?;
        }
        if channelized {
            call_method(
                opts_hash.as_value(),
                "[]=",
                &[to_ruby_str("Channelized")?, ruby.qtrue().as_value()],
            )?;
        }

        // Execute: sys.process.execute(path, args, opts)
        let process_val = call_method(
            self.sys_process()?,
            "execute",
            &[to_ruby_str(path)?, to_ruby_str(args)?, opts_hash.as_value()],
        )?;

        // Extract pid from process object
        let pid_val = call_method(process_val, "pid", &[])?;
        let pid = crate::ruby_bridge::value_to_i64(pid_val)?;

        // Extract handle
        let handle_val = call_method(process_val, "handle", &[])?;
        let handle = if is_nil(handle_val) {
            0
        } else {
            crate::ruby_bridge::value_to_i64(handle_val).unwrap_or(0)
        };

        // Extract channel if it exists
        let channel_val = call_method(process_val, "channel", &[])?;
        let channel_id = if is_nil(channel_val) {
            None
        } else {
            // Get channel ID from channel object
            let cid_val = call_method(channel_val, "cid", &[])?;
            Some(crate::ruby_bridge::value_to_i64(cid_val).unwrap_or(0))
        };

        Ok(serde_json::json!({
            "pid": pid,
            "handle": handle,
            "channel_id": channel_id,
        }))
    }
}
