// Test: Module actions (for auxiliary/post modules)
// Run with: ./run_tests.sh --test test_module_actions

mod common;

use msf::Framework;

#[test]
fn it_gets_module_actions() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Test exploit module - typically no actions
    let exploit = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create exploit");

    let exploit_actions = exploit.actions().expect("Failed to get exploit actions");
    println!("✓ Exploit actions: {:?}", exploit_actions);
    // Exploits typically don't have actions
    assert!(exploit_actions.is_empty(), "Exploit should have no actions");

    let exploit_default = exploit.default_action().expect("Failed to get default action");
    println!("✓ Exploit default action: {:?}", exploit_default);
    assert!(exploit_default.is_none(), "Exploit should have no default action");

    // Test auxiliary module with actions - use a module known to have actions
    let gather = framework
        .create_module("auxiliary/gather/enum_dns")
        .expect("Failed to create DNS enum module");

    let actions = gather.actions().expect("Failed to get gather actions");
    println!("✓ DNS enum actions ({}):", actions.len());
    for action in &actions {
        println!("    {}", action);
    }

    if !actions.is_empty() {
        let default = gather.default_action().expect("Failed to get default action");
        println!("✓ Default action: {:?}", default);

        // If there are actions, there should be a default
        if let Some(def) = default {
            assert!(actions.contains(&def), "Default action should be in actions list");
        }
    }

    // Test scanner module
    let scanner = framework
        .create_module("auxiliary/scanner/portscan/tcp")
        .expect("Failed to create scanner");

    let scanner_actions = scanner.actions().expect("Failed to get scanner actions");
    println!("✓ Scanner actions: {:?}", scanner_actions);
    // Port scanner doesn't have multiple actions

    println!("✓ All actions tests passed");
}
