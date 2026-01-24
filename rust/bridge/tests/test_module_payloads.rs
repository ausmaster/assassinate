// Test: Module compatible payloads
// Run with: ./run_tests.sh --test test_module_payloads

mod common;

use bridge::Framework;

#[test]
fn it_gets_compatible_payloads() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Test with Samba exploit - should have cmd/unix payloads
    let samba = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create samba module");

    let payloads = samba.compatible_payloads().expect("Failed to get compatible payloads");
    println!("✓ Samba exploit has {} compatible payloads", payloads.len());

    for payload in payloads.iter().take(5) {
        println!("    {}", payload);
    }

    assert!(!payloads.is_empty(), "Should have compatible payloads");
    // Samba exploit uses cmd/unix/interact
    let has_cmd_unix = payloads.iter().any(|p| p.contains("cmd/unix"));
    assert!(has_cmd_unix, "Should have cmd/unix payloads");

    // Test with EternalBlue - should have Windows payloads
    let eternalblue = framework
        .create_module("exploit/windows/smb/ms17_010_eternalblue")
        .expect("Failed to create eternalblue module");

    let win_payloads = eternalblue.compatible_payloads().expect("Failed to get payloads");
    println!("✓ EternalBlue has {} compatible payloads", win_payloads.len());

    for payload in win_payloads.iter().take(5) {
        println!("    {}", payload);
    }

    assert!(!win_payloads.is_empty(), "Should have compatible payloads");
    // EternalBlue should have windows meterpreter payloads
    let has_windows = win_payloads.iter().any(|p| p.contains("windows"));
    assert!(has_windows, "Should have windows payloads");

    // Test multi/handler - should have MANY payloads (it's generic)
    let handler = framework
        .create_module("exploit/multi/handler")
        .expect("Failed to create handler");

    let handler_payloads = handler.compatible_payloads().expect("Failed to get handler payloads");
    println!("✓ Multi/handler has {} compatible payloads", handler_payloads.len());
    assert!(handler_payloads.len() > 100, "Handler should support many payloads");

    println!("✓ All payload compatibility tests passed");
}
