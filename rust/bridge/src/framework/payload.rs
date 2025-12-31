//! Payload generation for Metasploit Framework

use crate::error::{AssassinateError, Result};
use crate::ruby_bridge::{call_method, Options};
use magnus::{value::ReprValue, IntoValue, TryConvert, Value};

/// Payload generator
#[derive(Clone)]
pub struct PayloadGenerator {
    ruby_framework: Value,
}

impl PayloadGenerator {
    pub fn new(framework: &super::Framework) -> Result<Self> {
        Ok(PayloadGenerator {
            ruby_framework: framework.ruby_framework,
        })
    }

    /// Generate a payload
    pub fn generate(
        &self,
        payload_name: &str,
        options: Option<Options>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if payload.is_nil() {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            )));
        }

        // Set options
        if let Some(opts_map) = options {
            let datastore = call_method(payload, "datastore", &[])?;
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = value.into_value_with(&ruby);
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the payload
        let generated = call_method(payload, "generate", &[])?;

        if generated.is_nil() {
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Convert Ruby binary string to bytes (don't use value_to_string - binary data isn't UTF-8)
        let rstring: magnus::RString =
            TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert payload to RString: {}",
                    e
                ))
            })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    /// Generate a payload and encode it
    pub fn generate_encoded(
        &self,
        payload_name: &str,
        encoder: Option<&str>,
        iterations: Option<i32>,
        options: Option<Options>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if payload.is_nil() {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            )));
        }

        // Get datastore
        let datastore = call_method(payload, "datastore", &[])?;

        // Set encoder if provided
        if let Some(enc) = encoder {
            let encoder_key = ruby.str_new("ENCODER").as_value();
            let encoder_val = ruby.str_new(enc).as_value();
            call_method(datastore, "[]=", &[encoder_key, encoder_val])?;
        }

        // Set iterations if provided
        if let Some(iter) = iterations {
            let iter_key = ruby.str_new("Iterations").as_value();
            let iter_val = ruby.integer_from_i64(iter as i64).as_value();
            call_method(datastore, "[]=", &[iter_key, iter_val])?;
        }

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = value.into_value_with(&ruby);
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the payload
        let generated = call_method(payload, "generate", &[])?;

        if generated.is_nil() {
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Convert Ruby binary string to bytes (don't use value_to_string - binary data isn't UTF-8)
        let rstring: magnus::RString =
            TryConvert::try_convert(generated).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert payload to RString: {}",
                    e
                ))
            })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    /// List all available payloads
    pub fn list_payloads(&self) -> Result<Vec<String>> {
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payloads = call_method(modules_mgr, "payloads", &[])?;
        let refnames = call_method(payloads, "module_refnames", &[])?;

        let payload_list: Vec<String> =
            TryConvert::try_convert(refnames).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert payload list: {}", e))
            })?;

        Ok(payload_list)
    }

    /// Generate a standalone executable payload
    pub fn generate_executable(
        &self,
        payload_name: &str,
        platform: &str,
        arch: &str,
        options: Option<Options>,
    ) -> Result<Vec<u8>> {
        let ruby = crate::ruby_bridge::get_ruby()?;

        // Create payload instance
        let name_val = ruby.str_new(payload_name).as_value();
        let modules_mgr = call_method(self.ruby_framework, "modules", &[])?;
        let payload = call_method(modules_mgr, "create", &[name_val])?;

        if payload.is_nil() {
            return Err(AssassinateError::PayloadError(format!(
                "Payload not found: {}",
                payload_name
            )));
        }

        // Get datastore
        let datastore = call_method(payload, "datastore", &[])?;

        // Set platform and arch
        let platform_key = ruby.str_new("Platform").as_value();
        let platform_val = ruby.str_new(platform).as_value();
        call_method(datastore, "[]=", &[platform_key, platform_val])?;

        let arch_key = ruby.str_new("Arch").as_value();
        let arch_val = ruby.str_new(arch).as_value();
        call_method(datastore, "[]=", &[arch_key, arch_val])?;

        // Set additional options
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = value.into_value_with(&ruby);
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the raw payload
        let raw_payload = call_method(payload, "generate", &[])?;

        if raw_payload.is_nil() {
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Call Msf::Util::EXE.to_executable
        // We need to properly construct arch array and platform list
        let ruby = magnus::Ruby::get().unwrap();

        // Create options hash
        let opts = ruby.hash_new();

        // Get the payload's arch and platform directly from the payload module
        // This ensures we use the correct arch/platform values that MSF expects
        let payload_arch = call_method(payload, "arch", &[])?;
        let payload_platform = call_method(payload, "platform", &[])?;

        // Get Msf::Util::EXE module
        let exe_module: Value = ruby.eval("Msf::Util::EXE").map_err(|e| {
            AssassinateError::RubyError(format!("Failed to get Msf::Util::EXE: {}", e))
        })?;

        // Call to_executable with the payload's own arch/platform
        // These are already in the correct format (arrays of constants)
        let exe: Value = exe_module
            .funcall(
                "to_executable",
                (
                    self.ruby_framework,
                    payload_arch,
                    payload_platform,
                    raw_payload,
                    opts,
                ),
            )
            .map_err(|e| AssassinateError::RubyError(format!("to_executable failed: {}", e)))?;

        if exe.is_nil() {
            return Err(AssassinateError::PayloadError(format!(
                "to_executable returned nil for arch={}, platform={}",
                arch, platform
            )));
        }

        // Convert Ruby binary string to bytes
        let rstring: magnus::RString =
            TryConvert::try_convert(exe).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert executable to RString: {}. Value type: {:?}",
                    e, exe
                ))
            })?;
        let bytes = unsafe { rstring.as_slice() }.to_vec();
        Ok(bytes)
    }

    pub fn __repr__(&self) -> Result<String> {
        Ok("<PayloadGenerator>".to_string())
    }
}
