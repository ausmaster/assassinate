// Test: Ruby bridge fundamentals (init, eval, conversions, nil, bool, array, hash)
// Run with: ./run_tests.sh --test test_ruby_bridge

use magnus::value::ReprValue;
use msf::ruby_bridge::{
    eval_ruby, get_ruby, init_ruby, ruby_array_get, ruby_array_len, ruby_array_to_ints,
    value_to_i64, value_to_string,
};

#[test]
fn it_tests_ruby_bridge_fundamentals() {
    // === Init ===
    assert!(init_ruby().is_ok(), "Ruby VM should initialize");
    println!("✓ Ruby VM initialized");

    // === Eval ===
    let result = eval_ruby("1 + 1").expect("Failed to eval");
    assert_eq!(value_to_i64(result).unwrap(), 2);
    println!("✓ Ruby eval: 1 + 1 = 2");

    // === Conversions ===
    let int_val = eval_ruby("42").expect("Failed to eval integer");
    assert_eq!(value_to_i64(int_val).unwrap(), 42);
    println!("✓ Integer conversion: 42");

    let str_val = eval_ruby("'hello'").expect("Failed to eval string");
    assert_eq!(value_to_string(str_val).unwrap(), "hello");
    println!("✓ String conversion: 'hello'");

    // === Nil ===
    let nil_val = eval_ruby("nil").expect("Failed to eval nil");
    assert!(nil_val.is_nil(), "nil should be nil");
    println!("✓ nil.is_nil() = true");

    let not_nil = eval_ruby("42").expect("Failed to eval 42");
    assert!(!not_nil.is_nil(), "42 should not be nil");
    println!("✓ 42.is_nil() = false");

    // === Bool/Truthiness ===
    let nil_val = eval_ruby("nil").expect("Failed to eval nil");
    assert!(!nil_val.to_bool(), "nil should be falsy");
    println!("✓ nil.to_bool() = false");

    let false_val = eval_ruby("false").expect("Failed to eval false");
    assert!(!false_val.to_bool(), "false should be falsy");
    println!("✓ false.to_bool() = false");

    let true_val = eval_ruby("true").expect("Failed to eval true");
    assert!(true_val.to_bool(), "true should be truthy");
    println!("✓ true.to_bool() = true");

    let zero_val = eval_ruby("0").expect("Failed to eval 0");
    assert!(zero_val.to_bool(), "0 should be truthy in Ruby");
    println!("✓ 0.to_bool() = true (Ruby-specific)");

    // === Array ===
    let arr = eval_ruby("[1, 2, 3]").expect("Failed to eval array");
    assert_eq!(ruby_array_len(arr).unwrap(), 3);
    println!("✓ Array length: 3");

    let first = ruby_array_get(arr, 0).expect("Failed to get element");
    assert_eq!(value_to_i64(first).unwrap(), 1);
    println!("✓ Array[0] = 1");

    let vec = ruby_array_to_ints(arr).expect("Failed to convert");
    assert_eq!(vec, vec![1, 2, 3]);
    println!("✓ Array to vec: [1, 2, 3]");

    // === Hash ===
    let ruby = get_ruby().expect("Failed to get Ruby handle");
    let hash = ruby.hash_new();
    hash.aset("foo", 42).expect("Failed to set");
    let val: i64 = hash.aref("foo").expect("Failed to get");
    assert_eq!(val, 42);
    println!("✓ Hash['foo'] = 42");

    println!("\n✓ All Ruby bridge tests passed!");
}
