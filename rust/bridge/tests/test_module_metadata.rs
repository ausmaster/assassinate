// Test: Module metadata properties (fullname, description, rank, license, etc.)
// Run with: ./run_tests.sh --test test_module_metadata

mod common;

use bridge::Framework;

#[test]
fn it_gets_module_metadata() {
    let _ruby = common::init_msf();
    let framework = Framework::new(None).expect("Failed to create framework");

    // Use a well-documented exploit
    let module = framework
        .create_module("exploit/linux/samba/is_known_pipename")
        .expect("Failed to create module");

    // Test fullname
    let fullname = module.fullname().expect("Failed to get fullname");
    println!("✓ Fullname: {}", fullname);
    assert_eq!(fullname, "exploit/linux/samba/is_known_pipename");

    // Test name
    let name = module.name().expect("Failed to get name");
    println!("✓ Name: {}", name);
    assert!(!name.is_empty());

    // Test description
    let description = module.description().expect("Failed to get description");
    println!("✓ Description: {}...", &description[..description.len().min(80)]);
    assert!(!description.is_empty());
    assert!(description.to_lowercase().contains("samba") || description.to_lowercase().contains("smb"));

    // Test rank (should be a number like "600" for excellent)
    let rank = module.rank().expect("Failed to get rank");
    println!("✓ Rank: {}", rank);
    assert!(!rank.is_empty());

    // Test license
    let license = module.license().expect("Failed to get license");
    println!("✓ License: {}", license);
    assert!(license.contains("Metasploit") || license.contains("BSD"));

    // Test disclosure_date
    let disclosure = module.disclosure_date().expect("Failed to get disclosure_date");
    println!("✓ Disclosure date: {:?}", disclosure);
    if let Some(date) = disclosure {
        assert!(date.contains("2017"), "CVE-2017-7494 should have 2017 disclosure date");
    }

    // Test privileged
    let privileged = module.privileged().expect("Failed to get privileged");
    println!("✓ Privileged: {}", privileged);
    // This exploit runs as root typically
    assert!(privileged, "Samba exploit should be privileged");

    // Test targets
    let targets = module.targets().expect("Failed to get targets");
    println!("✓ Targets ({}):", targets.len());
    for (i, target) in targets.iter().take(3).enumerate() {
        println!("    {}: {}", i, target);
    }
    assert!(!targets.is_empty(), "Module should have targets");

    println!("✓ All metadata tests passed");
}
