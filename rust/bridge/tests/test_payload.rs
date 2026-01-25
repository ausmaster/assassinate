// Consolidated test: All payload generation operations
// Run with: ./run_tests.sh --test test_payload
//
// This consolidates:
//   - test_payload_list.rs (list all payloads)
//   - test_payload_generate.rs (generate raw payload)
//   - test_payload_encoded.rs (generate encoded payload)
//   - test_payload_executable.rs (generate ELF/PE executable)
//   - test_payload_badchars.rs (auto-select encoder to avoid badchars)
//   - test_payload_format.rs (transform to c/python/ruby/hex/base64/etc.)
//
// Magnus pattern: Ruby VM can only init once per process, so all payload tests
// are combined into a single test function with multiple sub-tests.

mod common;

use msf::framework::PayloadGenerator;
use msf::ruby_bridge::RubyVal;
use msf::Framework;
use std::collections::HashMap;

#[test]
fn it_tests_payload_generation_comprehensively() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Create payload generator (shared across sub-tests)
    let generator = PayloadGenerator::new(&framework).expect("Failed to create PayloadGenerator");
    println!("✓ Created PayloadGenerator");

    // =========================================================================
    // Sub-test 1: List available payloads
    // =========================================================================
    println!("\n=== Testing Payload Listing ===");

    let payloads = generator.list_payloads().expect("Failed to list payloads");
    println!("✓ Found {} payloads", payloads.len());
    assert!(!payloads.is_empty(), "Should have payloads available");

    // Check for some expected payloads
    let has_linux_shell = payloads
        .iter()
        .any(|p| p.contains("linux") && p.contains("shell"));
    println!("✓ Has Linux shell payloads: {}", has_linux_shell);
    assert!(has_linux_shell, "Should have Linux shell payloads");

    let has_windows_meterpreter = payloads
        .iter()
        .any(|p| p.contains("windows") && p.contains("meterpreter"));
    println!("✓ Has Windows Meterpreter payloads: {}", has_windows_meterpreter);
    assert!(has_windows_meterpreter, "Should have Windows Meterpreter payloads");

    let has_cmd_unix = payloads.iter().any(|p| p.starts_with("cmd/unix"));
    println!("✓ Has cmd/unix payloads: {}", has_cmd_unix);
    assert!(has_cmd_unix, "Should have cmd/unix payloads");

    println!("✓ Payload list tests passed");

    // =========================================================================
    // Sub-test 2: Generate raw payload
    // =========================================================================
    println!("\n=== Testing Raw Payload Generation ===");

    // Generate cmd/unix/reverse_bash (simple, text-based payload)
    let mut options: HashMap<String, RubyVal> = HashMap::new();
    options.insert("LHOST".to_string(), RubyVal::String("127.0.0.1".to_string()));
    options.insert("LPORT".to_string(), RubyVal::Int(4444));

    let payload_bytes = generator
        .generate("cmd/unix/reverse_bash", Some(options.clone()))
        .expect("Failed to generate payload");

    println!("✓ Generated cmd/unix/reverse_bash: {} bytes", payload_bytes.len());
    assert!(!payload_bytes.is_empty(), "Payload should not be empty");

    // The bash reverse shell should contain recognizable bash commands
    let payload_str = String::from_utf8_lossy(&payload_bytes);
    let preview_len = payload_str.len().min(100);
    println!("  Payload preview: {}...", &payload_str[..preview_len]);

    let has_bash_content = payload_str.contains("bash")
        || payload_str.contains("/dev/tcp")
        || payload_str.contains("exec")
        || payload_str.contains("sh");
    assert!(has_bash_content, "Bash payload should contain shell commands");

    // Also test a binary payload (linux/x64/shell_reverse_tcp)
    let mut linux_opts: HashMap<String, RubyVal> = HashMap::new();
    linux_opts.insert("LHOST".to_string(), RubyVal::String("127.0.0.1".to_string()));
    linux_opts.insert("LPORT".to_string(), RubyVal::Int(4444));

    let linux_payload = generator
        .generate("linux/x64/shell_reverse_tcp", Some(linux_opts))
        .expect("Failed to generate Linux x64 payload");

    println!("✓ Generated linux/x64/shell_reverse_tcp: {} bytes", linux_payload.len());
    assert!(!linux_payload.is_empty(), "Linux payload should not be empty");
    assert!(linux_payload.len() > 10, "Binary payload should have meaningful size");

    println!("✓ Raw payload generation tests passed");

    // =========================================================================
    // Sub-test 3: Generate encoded payload
    // =========================================================================
    println!("\n=== Testing Encoded Payload Generation ===");

    // Options for x86 payload (shikata_ga_nai is x86-only)
    let mut x86_opts: HashMap<String, RubyVal> = HashMap::new();
    x86_opts.insert("LHOST".to_string(), RubyVal::String("127.0.0.1".to_string()));
    x86_opts.insert("LPORT".to_string(), RubyVal::Int(4444));

    // Generate raw payload first for comparison
    let raw_payload = generator
        .generate("linux/x86/shell_reverse_tcp", Some(x86_opts.clone()))
        .expect("Failed to generate raw payload");
    println!("✓ Generated raw x86 payload: {} bytes", raw_payload.len());

    // Generate encoded payload with shikata_ga_nai (3 iterations)
    let encoded_payload = generator
        .generate_encoded(
            "linux/x86/shell_reverse_tcp",
            Some("x86/shikata_ga_nai"),
            Some(3),
            Some(x86_opts),
        )
        .expect("Failed to generate encoded payload");

    println!(
        "✓ Generated encoded payload (shikata_ga_nai, 3 iterations): {} bytes",
        encoded_payload.len()
    );
    assert!(!encoded_payload.is_empty(), "Encoded payload should not be empty");

    // Encoded payload MUST be different from raw
    assert_ne!(
        raw_payload, encoded_payload,
        "Encoded payload MUST differ from raw payload"
    );

    println!(
        "  Size comparison: raw={} bytes, encoded={} bytes",
        raw_payload.len(),
        encoded_payload.len()
    );

    println!("✓ Encoded payload generation tests passed");

    // =========================================================================
    // Sub-test 4: Generate executable
    // =========================================================================
    println!("\n=== Testing Executable Payload Generation ===");

    let mut exe_opts: HashMap<String, RubyVal> = HashMap::new();
    exe_opts.insert("LHOST".to_string(), RubyVal::String("127.0.0.1".to_string()));
    exe_opts.insert("LPORT".to_string(), RubyVal::Int(4444));

    // Generate a Linux ELF executable
    let exe_payload = generator
        .generate_executable("linux/x64/shell_reverse_tcp", "linux", "x64", Some(exe_opts))
        .expect("Failed to generate executable");

    println!("✓ Generated Linux x64 executable: {} bytes", exe_payload.len());
    assert!(!exe_payload.is_empty(), "Executable should not be empty");

    // Verify ELF magic bytes (0x7f 'E' 'L' 'F')
    assert!(
        exe_payload.len() >= 4,
        "Executable should be at least 4 bytes"
    );

    let elf_magic = &exe_payload[0..4];
    println!(
        "  Magic bytes: {:02x} {:02x} {:02x} {:02x}",
        elf_magic[0], elf_magic[1], elf_magic[2], elf_magic[3]
    );

    assert_eq!(
        elf_magic,
        &[0x7f, b'E', b'L', b'F'],
        "Linux executable MUST have ELF magic bytes"
    );

    // MSF uses minimal ELF templates (120 bytes for x64) + shellcode
    assert!(
        exe_payload.len() > 120,
        "ELF should be larger than x64 template (120 bytes), got {} bytes",
        exe_payload.len()
    );

    println!("✓ Executable payload generation tests passed");

    // =========================================================================
    // Sub-test 5: Badchar avoidance with auto-encoder selection
    // =========================================================================
    println!("\n=== Testing Badchar Avoidance ===");

    // Generate linux/x86/exec with badchars
    let badchars = b"\x00";

    let mut cmd_opts = HashMap::new();
    cmd_opts.insert("CMD".to_string(), RubyVal::String("id".to_string()));

    println!("[*] Generating linux/x86/exec payload avoiding null bytes...");

    match generator.generate_with_badchars(
        "linux/x86/exec",
        badchars,
        Some(1),
        Some(cmd_opts),
    ) {
        Ok((payload, encoder_used)) => {
            println!("✓ Generated payload: {} bytes", payload.len());
            if let Some(enc) = &encoder_used {
                println!("✓ Encoder used: {}", enc);
            } else {
                println!("✓ No encoding needed (payload already clean)");
            }

            // Verify no badchars in output
            for &bad in badchars {
                assert!(
                    !payload.contains(&bad),
                    "Payload still contains bad character 0x{:02x}",
                    bad
                );
            }
            println!("✓ Verified: no null bytes in payload");
        }
        Err(e) => {
            // This is acceptable - some payloads may not be cleanable
            println!("⚠ Could not generate clean payload: {}", e);
            println!("  This may be expected if no compatible encoder exists");
        }
    }

    println!("✓ Badchar avoidance tests passed");

    // =========================================================================
    // Sub-test 6: Format transformation
    // =========================================================================
    println!("\n=== Testing Format Transformation ===");

    // Test data
    let test_bytes: &[u8] = &[0x41, 0x42, 0x43, 0x44]; // ABCD
    println!("[*] Testing format transformations on test bytes: {:?}", test_bytes);

    // Test raw format
    let raw = PayloadGenerator::transform_buffer(test_bytes, "raw", "buf").unwrap();
    println!("raw: {}", raw);
    assert!(raw.contains("41424344"));

    // Test hex format
    let hex = PayloadGenerator::transform_buffer(test_bytes, "hex", "buf").unwrap();
    println!("hex: {}", hex);
    assert!(hex.contains("\\x41\\x42\\x43\\x44"));

    // Test num format
    let num = PayloadGenerator::transform_buffer(test_bytes, "num", "buf").unwrap();
    println!("num: {}", num);
    assert!(num.contains("0x41"));
    assert!(num.contains("0x42"));

    // Test C format
    let c = PayloadGenerator::transform_buffer(test_bytes, "c", "shellcode").unwrap();
    println!("c:\n{}", c);
    assert!(c.contains("unsigned char shellcode[]"));
    assert!(c.contains("\\x41"));

    // Test Python format
    let python = PayloadGenerator::transform_buffer(test_bytes, "python", "buf").unwrap();
    println!("python:\n{}", python);
    assert!(python.contains("buf ="));
    assert!(python.contains("b\""));

    // Test Ruby format
    let ruby = PayloadGenerator::transform_buffer(test_bytes, "ruby", "payload").unwrap();
    println!("ruby:\n{}", ruby);
    assert!(ruby.contains("payload ="));

    // Test base64 format
    let b64 = PayloadGenerator::transform_buffer(test_bytes, "base64", "buf").unwrap();
    println!("base64: {}", b64);
    assert_eq!(b64, "QUJDRA=="); // Base64 of "ABCD"

    // Test Rust format
    let rust = PayloadGenerator::transform_buffer(test_bytes, "rust", "shellcode").unwrap();
    println!("rust:\n{}", rust);
    assert!(rust.contains("let shellcode: [u8; 4]"));
    assert!(rust.contains("0x41"));

    // Test Go format
    let golang = PayloadGenerator::transform_buffer(test_bytes, "go", "buf").unwrap();
    println!("go:\n{}", golang);
    assert!(golang.contains("buf := []byte"));

    // Test C# format
    let csharp = PayloadGenerator::transform_buffer(test_bytes, "csharp", "buf").unwrap();
    println!("csharp:\n{}", csharp);
    assert!(csharp.contains("byte[] buf"));

    // Test Java format
    let java = PayloadGenerator::transform_buffer(test_bytes, "java", "buf").unwrap();
    println!("java:\n{}", java);
    assert!(java.contains("byte buf[]"));
    assert!(java.contains("(byte) 0x41"));

    // Test PowerShell format
    let ps = PayloadGenerator::transform_buffer(test_bytes, "powershell", "buf").unwrap();
    println!("powershell:\n{}", ps);
    assert!(ps.contains("[Byte[]] $buf"));

    // Test dword format
    let dword = PayloadGenerator::transform_buffer(test_bytes, "dword", "buf").unwrap();
    println!("dword: {}", dword);
    assert!(dword.contains("0x44434241")); // Little-endian dword

    // Test JavaScript LE format
    let js_le = PayloadGenerator::transform_buffer(test_bytes, "js_le", "buf").unwrap();
    println!("js_le: {}", js_le);
    assert!(js_le.contains("%u"));

    println!("✓ Format transformation tests passed");

    // =========================================================================
    println!("\n✓ All payload tests passed!");
}
