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
    ///
    /// This properly creates an encoder module instance and calls its encode() method,
    /// rather than just setting datastore options.
    ///
    /// # Arguments
    /// * `payload_name` - Full payload path (e.g., "linux/x86/shell_reverse_tcp")
    /// * `encoder` - Optional encoder name (e.g., "x86/shikata_ga_nai")
    /// * `iterations` - Number of encoding iterations (default: 1)
    /// * `options` - Payload options (LHOST, LPORT, etc.)
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

        // Get datastore and set options
        let datastore = call_method(payload, "datastore", &[])?;

        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = value.into_value_with(&ruby);
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate the raw payload first
        let raw_payload = call_method(payload, "generate", &[])?;

        if raw_payload.is_nil() {
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // If no encoder specified, return raw payload
        let encoder_name = match encoder {
            Some(enc) => enc,
            None => {
                let rstring: magnus::RString =
                    TryConvert::try_convert(raw_payload).map_err(|e: magnus::Error| {
                        AssassinateError::ConversionError(format!(
                            "Failed to convert payload to RString: {}",
                            e
                        ))
                    })?;
                return Ok(unsafe { rstring.as_slice() }.to_vec());
            }
        };

        // Create the encoder module instance
        // framework.encoders.create(encoder_name)
        let encoders_mgr = call_method(self.ruby_framework, "encoders", &[])?;
        let encoder_name_val = ruby.str_new(encoder_name).as_value();
        let encoder_module = call_method(encoders_mgr, "create", &[encoder_name_val])?;

        if encoder_module.is_nil() {
            return Err(AssassinateError::PayloadError(format!(
                "Encoder not found: {}",
                encoder_name
            )));
        }

        // Get the payload's platform for encoding
        let platform = call_method(payload, "platform", &[])?;

        // Encode the payload (potentially multiple iterations)
        // encoder.encode(shellcode, badchars, state, platform)
        let iter_count = iterations.unwrap_or(1).max(1);
        let mut encoded = raw_payload;

        // Get nil for badchars and state
        let nil_val = ruby.qnil().as_value();

        for _ in 0..iter_count {
            encoded = call_method(
                encoder_module,
                "encode",
                &[encoded, nil_val, nil_val, platform],
            )?;

            if encoded.is_nil() {
                return Err(AssassinateError::PayloadError(
                    "Encoder returned nil".to_string(),
                ));
            }
        }

        // Convert Ruby binary string to bytes
        let rstring: magnus::RString =
            TryConvert::try_convert(encoded).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert encoded payload to RString: {}",
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

    /// Generate a payload with automatic encoder selection to avoid bad characters.
    ///
    /// This implements MSF's encoder auto-selection logic:
    /// 1. Generate raw payload
    /// 2. Check if badchars actually exist in payload (skip encoding if not)
    /// 3. Get compatible encoders ranked by arch/platform
    /// 4. Try each encoder in ranked order until payload is clean
    ///
    /// # Arguments
    /// * `payload_name` - Full payload path (e.g., "linux/x86/shell_reverse_tcp")
    /// * `badchars` - Bytes to avoid in final payload (e.g., b"\x00\x0a\x0d")
    /// * `iterations` - Number of encoding iterations (default: 1)
    /// * `options` - Payload options (LHOST, LPORT, etc.)
    ///
    /// # Returns
    /// * `Ok((Vec<u8>, Option<String>))` - Tuple of (encoded payload, encoder name used)
    /// * `Err` if no encoder can clean the payload
    pub fn generate_with_badchars(
        &self,
        payload_name: &str,
        badchars: &[u8],
        iterations: Option<i32>,
        options: Option<Options>,
    ) -> Result<(Vec<u8>, Option<String>)> {
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
        let datastore = call_method(payload, "datastore", &[])?;
        if let Some(opts_map) = options {
            for (key, value) in opts_map {
                let key_val = ruby.str_new(&key).as_value();
                let value_val = value.into_value_with(&ruby);
                call_method(datastore, "[]=", &[key_val, value_val])?;
            }
        }

        // Generate raw payload
        let raw_payload = call_method(payload, "generate", &[])?;
        if raw_payload.is_nil() {
            return Err(AssassinateError::PayloadError(
                "Failed to generate payload".to_string(),
            ));
        }

        // Convert to bytes for badchar checking
        let rstring: magnus::RString =
            TryConvert::try_convert(raw_payload).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!(
                    "Failed to convert payload to RString: {}",
                    e
                ))
            })?;
        let raw_bytes = unsafe { rstring.as_slice() }.to_vec();

        // Check if badchars actually exist in raw payload
        if badchars.is_empty() || !Self::has_badchars(&raw_bytes, badchars) {
            // No encoding needed - payload is already clean
            return Ok((raw_bytes, None));
        }

        // Get compatible encoders ranked by arch/platform
        // framework.encoders.each_module_ranked('Arch' => arch, 'Platform' => platform)
        let payload_arch = call_method(payload, "arch", &[])?;
        let payload_platform = call_method(payload, "platform", &[])?;

        let encoders_mgr = call_method(self.ruby_framework, "encoders", &[])?;

        // Build options hash for filtering
        let opts_hash = ruby.hash_new();
        let arch_key = ruby.str_new("Arch").as_value();
        let platform_key = ruby.str_new("Platform").as_value();
        opts_hash
            .aset(arch_key, payload_arch)
            .map_err(|e| AssassinateError::RubyError(format!("Failed to set Arch: {}", e)))?;
        opts_hash
            .aset(platform_key, payload_platform)
            .map_err(|e| AssassinateError::RubyError(format!("Failed to set Platform: {}", e)))?;

        // Collect ranked encoders
        // We need to call each_module_ranked and collect results
        // Use Ruby block to collect encoder names
        let encoder_names: Value = ruby
            .eval(
                r#"
            proc { |mgr, opts|
                names = []
                mgr.each_module_ranked(opts) { |name, mod| names << name }
                names
            }
        "#,
            )
            .map_err(|e| AssassinateError::RubyError(format!("Failed to create proc: {}", e)))?;

        let names_array: Value = encoder_names
            .funcall("call", (encoders_mgr, opts_hash.as_value()))
            .map_err(|e| AssassinateError::RubyError(format!("Failed to get encoder names: {}", e)))?;

        let encoder_list: Vec<String> =
            TryConvert::try_convert(names_array).map_err(|e: magnus::Error| {
                AssassinateError::ConversionError(format!("Failed to convert encoder list: {}", e))
            })?;

        // Convert badchars to Ruby string for encoder.encode()
        let badchars_str = ruby.str_from_slice(badchars).as_value();

        let iter_count = iterations.unwrap_or(1).max(1);

        // Try each encoder in ranked order
        for encoder_name in encoder_list.iter() {
            // Skip ManualRanking encoders (check rank)
            let encoder_module = call_method(encoders_mgr, "create", &[ruby.str_new(encoder_name).as_value()])?;

            if encoder_module.is_nil() {
                continue;
            }

            // Check rank - skip ManualRanking (rank == 0)
            let rank_val = call_method(encoder_module, "rank", &[])?;
            let rank: i64 = TryConvert::try_convert(rank_val).unwrap_or(100); // Default to normal ranking
            if rank == 0 {
                // ManualRanking
                continue;
            }

            // Share datastore with payload
            let encoder_datastore = call_method(encoder_module, "datastore", &[])?;
            let payload_datastore = call_method(payload, "datastore", &[])?;
            call_method(encoder_datastore, "merge!", &[payload_datastore])?;

            // Try encoding
            let nil_val = ruby.qnil().as_value();
            let mut encoded = raw_payload;
            let mut encode_failed = false;

            for _ in 0..iter_count {
                // encoder.encode(buf, badchars, state, platform)
                match encoder_module.funcall::<_, _, Value>(
                    "encode",
                    (encoded, badchars_str, nil_val, payload_platform),
                ) {
                    Ok(result) => {
                        if result.is_nil() {
                            encode_failed = true;
                            break;
                        }
                        encoded = result;
                    }
                    Err(_) => {
                        // Encoder failed (BadcharError, etc.) - try next
                        encode_failed = true;
                        break;
                    }
                }
            }

            if encode_failed {
                continue;
            }

            // Convert result and verify no badchars remain
            let encoded_rstring: magnus::RString =
                match TryConvert::try_convert(encoded) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
            let encoded_bytes = unsafe { encoded_rstring.as_slice() }.to_vec();

            // Final badchar verification
            if !Self::has_badchars(&encoded_bytes, badchars) {
                return Ok((encoded_bytes, Some(encoder_name.clone())));
            }
            // This encoder didn't fully clean payload - try next
        }

        Err(AssassinateError::PayloadError(format!(
            "No encoder could avoid badchars {:?} for payload {}",
            badchars, payload_name
        )))
    }

    /// Check if buffer contains any bad characters
    fn has_badchars(buf: &[u8], badchars: &[u8]) -> bool {
        for &bad in badchars {
            if buf.contains(&bad) {
                return true;
            }
        }
        false
    }

    /// Generate a payload and output in a specific format.
    ///
    /// Supported formats:
    /// - "raw" - Raw binary bytes (no transformation)
    /// - "hex" - Hex escape sequence: \x41\x42...
    /// - "c" - C array: unsigned char buf[] = "\x41\x42...";
    /// - "python" / "py" - Python bytes: buf = b"\x41\x42..."
    /// - "ruby" / "rb" - Ruby string: buf = "\x41\x42..."
    /// - "bash" / "sh" - Bash export: export buf=$'\x41\x42...'
    /// - "csharp" / "cs" - C# byte array: byte[] buf = new byte[] { 0x41, ... };
    /// - "perl" / "pl" - Perl string: my $buf = "\x41\x42...";
    /// - "powershell" / "ps1" - PowerShell: [Byte[]] $buf = 0x41,0x42,...
    /// - "java" - Java byte array
    /// - "go" / "golang" - Go slice: buf := []byte{0x41, ...}
    /// - "rust" / "rustlang" - Rust array: let buf: [u8; N] = [0x41, ...];
    /// - "num" - Numeric hex: 0x41, 0x42, ...
    /// - "dword" - 32-bit dwords: 0x41424344, ...
    /// - "base64" - Base64 encoded string
    ///
    /// # Arguments
    /// * `payload_name` - Full payload path (e.g., "linux/x86/shell_reverse_tcp")
    /// * `format` - Output format (see above)
    /// * `var_name` - Variable name to use in output (default: "buf")
    /// * `options` - Payload options (LHOST, LPORT, etc.)
    ///
    /// # Returns
    /// Formatted string representation of the payload
    pub fn generate_formatted(
        &self,
        payload_name: &str,
        format: &str,
        var_name: Option<&str>,
        options: Option<Options>,
    ) -> Result<String> {
        // Generate raw payload first
        let raw_bytes = self.generate(payload_name, options)?;

        // Transform to requested format
        let name = var_name.unwrap_or("buf");
        Self::transform_buffer(&raw_bytes, format, name)
    }

    /// Transform raw bytes to a specific output format.
    ///
    /// This is a pure Rust implementation of MSF's Buffer.transform() logic.
    pub fn transform_buffer(buf: &[u8], format: &str, var_name: &str) -> Result<String> {
        match format.to_lowercase().as_str() {
            "raw" => {
                // Return as hex string for raw (can't return binary in String)
                Ok(buf.iter().map(|b| format!("{:02x}", b)).collect())
            }

            "hex" => {
                // \x41\x42\x43...
                Ok(buf.iter().map(|b| format!("\\x{:02x}", b)).collect())
            }

            "num" => {
                // 0x41, 0x42, 0x43, ...
                let mut result = String::new();
                for (i, &b) in buf.iter().enumerate() {
                    if i > 0 && i % 15 == 0 {
                        result.push_str("\n");
                    }
                    if i > 0 {
                        result.push_str(", ");
                    }
                    result.push_str(&format!("0x{:02x}", b));
                }
                result.push('\n');
                Ok(result)
            }

            "dword" => {
                // Convert to 32-bit little-endian dwords
                let mut padded = buf.to_vec();
                let align = buf.len() % 4;
                if align > 0 {
                    padded.extend(vec![0u8; 4 - align]);
                }

                let mut result = String::new();
                for (i, chunk) in padded.chunks(4).enumerate() {
                    if i > 0 && i % 8 == 0 {
                        result.push_str("\n");
                    }
                    if i > 0 {
                        result.push_str(", ");
                    }
                    let dword = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    result.push_str(&format!("0x{:08x}", dword));
                }
                result.push('\n');
                Ok(result)
            }

            "c" => {
                // unsigned char buf[] = "\x41\x42...";
                let hex_str: String = buf.iter().map(|b| format!("\\x{:02x}", b)).collect();
                Ok(format!(
                    "unsigned char {}[] = \n\"{}\";\n",
                    var_name,
                    Self::wrap_string(&hex_str, 60, "\"", "\"")
                ))
            }

            "python" | "py" => {
                // buf = b"\x41\x42..."
                let hex_str: String = buf.iter().map(|b| format!("\\x{:02x}", b)).collect();
                Ok(format!(
                    "{} = b\"\"\n{} += b\"{}\"\n",
                    var_name,
                    var_name,
                    Self::wrap_string_prefixed(&hex_str, 60, &format!("{} += b\"", var_name), "\"")
                ))
            }

            "ruby" | "rb" => {
                // buf = "\x41\x42..."
                let hex_str: String = buf.iter().map(|b| format!("\\x{:02x}", b)).collect();
                Ok(format!(
                    "{} = \n\"{}\"\n",
                    var_name,
                    Self::wrap_string(&hex_str, 60, "\"", "\" +")
                ))
            }

            "bash" | "sh" => {
                // export buf=$'\x41\x42...'
                let hex_str: String = buf.iter().map(|b| format!("\\x{:02x}", b)).collect();
                Ok(format!(
                    "export {}=\\\n$'{}'\n",
                    var_name,
                    Self::wrap_string(&hex_str, 60, "$'", "'\\'")
                ))
            }

            "perl" | "pl" => {
                // my $buf = "\x41\x42...";
                let hex_str: String = buf.iter().map(|b| format!("\\x{:02x}", b)).collect();
                Ok(format!(
                    "my ${} = \n\"{}\";\n",
                    var_name,
                    Self::wrap_string(&hex_str, 60, "\"", "\" .")
                ))
            }

            "csharp" | "cs" => {
                // byte[] buf = new byte[N] { 0x41, 0x42, ... };
                let bytes_str: String = buf
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                Ok(format!(
                    "byte[] {} = new byte[{}] {{\n{}\n}};\n",
                    var_name,
                    buf.len(),
                    Self::wrap_simple(&bytes_str, 60)
                ))
            }

            "java" => {
                // byte buf[] = new byte[] { (byte) 0x41, ... };
                let mut lines = Vec::new();
                let mut line = String::new();
                for (i, &b) in buf.iter().enumerate() {
                    if i > 0 {
                        line.push_str(", ");
                    }
                    if i > 0 && i % 8 == 0 {
                        lines.push(format!("\t{}", line));
                        line = String::new();
                    }
                    line.push_str(&format!("(byte) 0x{:02x}", b));
                }
                if !line.is_empty() {
                    lines.push(format!("\t{}", line));
                }
                Ok(format!(
                    "byte {}[] = new byte[]\n{{\n{}\n}};\n",
                    var_name,
                    lines.join(",\n")
                ))
            }

            "go" | "golang" => {
                // buf := []byte{0x41, 0x42, ...}
                let bytes_str: String = buf
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(format!(
                    "{} := []byte{{\n{}\n}}\n",
                    var_name,
                    Self::wrap_simple(&bytes_str, 60)
                ))
            }

            "rust" | "rustlang" => {
                // let buf: [u8; N] = [0x41, 0x42, ...];
                let bytes_str: String = buf
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(format!(
                    "let {}: [u8; {}] = [\n{}\n];\n",
                    var_name,
                    buf.len(),
                    Self::wrap_simple(&bytes_str, 60)
                ))
            }

            "powershell" | "ps1" => {
                // [Byte[]] $buf = 0x41,0x42,...
                let bytes_str: String = buf
                    .iter()
                    .map(|b| format!("0x{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                Ok(format!(
                    "[Byte[]] ${} = {}\n",
                    var_name,
                    Self::wrap_simple(&bytes_str, 60)
                ))
            }

            "base64" => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                Ok(STANDARD.encode(buf))
            }

            "js_le" => {
                // JavaScript little-endian unicode: %u4142%u4344...
                let mut result = String::new();
                let mut padded = buf.to_vec();
                if padded.len() % 2 != 0 {
                    padded.push(0x41); // Pad odd length
                }
                for chunk in padded.chunks(2) {
                    result.push_str(&format!("%u{:02x}{:02x}", chunk[1], chunk[0]));
                }
                Ok(result)
            }

            "js_be" => {
                // JavaScript big-endian unicode: %u4142%u4344...
                let mut result = String::new();
                let mut padded = buf.to_vec();
                if padded.len() % 2 != 0 {
                    padded.push(0x41); // Pad odd length
                }
                for chunk in padded.chunks(2) {
                    result.push_str(&format!("%u{:02x}{:02x}", chunk[0], chunk[1]));
                }
                Ok(result)
            }

            _ => Err(AssassinateError::PayloadError(format!(
                "Unsupported format: {}. Valid formats: raw, hex, num, dword, c, python, ruby, bash, perl, csharp, java, go, rust, powershell, base64, js_le, js_be",
                format
            ))),
        }
    }

    /// Wrap a hex string with line prefixes/suffixes
    fn wrap_string(s: &str, width: usize, line_start: &str, line_end: &str) -> String {
        let mut result = String::new();
        let mut pos = 0;
        let effective_width = width.saturating_sub(line_start.len() + line_end.len());

        while pos < s.len() {
            let end = (pos + effective_width).min(s.len());
            // Align to 4-char boundary (\xNN)
            let aligned_end = if end < s.len() {
                (end / 4) * 4
            } else {
                end
            };
            let chunk = &s[pos..aligned_end.max(pos + 4).min(s.len())];

            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(line_start);
            result.push_str(chunk);
            result.push_str(line_end);

            pos = aligned_end.max(pos + 4).min(s.len());
        }
        result
    }

    /// Wrap with prefixed lines (for Python style)
    fn wrap_string_prefixed(s: &str, width: usize, prefix: &str, suffix: &str) -> String {
        let mut result = String::new();
        let mut pos = 0;
        let effective_width = width.saturating_sub(prefix.len() + suffix.len());

        while pos < s.len() {
            let end = (pos + effective_width).min(s.len());
            let aligned_end = if end < s.len() {
                (end / 4) * 4
            } else {
                end
            };
            let chunk = &s[pos..aligned_end.max(pos + 4).min(s.len())];

            if !result.is_empty() {
                result.push('\n');
                result.push_str(prefix);
            }
            result.push_str(chunk);
            result.push_str(suffix);

            pos = aligned_end.max(pos + 4).min(s.len());
        }
        result
    }

    /// Simple line wrapping for comma-separated values
    fn wrap_simple(s: &str, width: usize) -> String {
        let mut result = String::new();
        let mut line = String::new();

        for part in s.split(',') {
            let part = part.trim();
            if line.len() + part.len() + 2 > width {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&line);
                line = String::new();
            }
            if !line.is_empty() {
                line.push_str(", ");
            }
            line.push_str(part);
        }

        if !line.is_empty() {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&line);
        }

        result
    }
}
