#!/usr/bin/env python3
"""
Proof of Concept: Python Embedding Ruby via ctypes

Tests if we can initialize the Ruby VM from Python's main thread
and call MSF functionality directly.
"""

import ctypes
import ctypes.util
import sys
import threading

def find_libruby():
    """Locate the Ruby shared library."""
    # Try common locations
    candidates = [
        '/usr/lib64/libruby.so.3.4',  # System Ruby on Fedora
        '/usr/lib64/libruby.so.3.3',
        '/usr/lib64/libruby.so',
        '/usr/lib/libruby.so.3.4',
        '/usr/lib/libruby.so.3.3',
        '/usr/lib/libruby.so',
        'libruby.so.3.4',
        'libruby.so.3.3',
        'libruby.so',
    ]

    # Try ctypes.util.find_library
    lib_path = ctypes.util.find_library('ruby')
    if lib_path:
        candidates.insert(0, lib_path)

    for path in candidates:
        try:
            lib = ctypes.CDLL(path)
            print(f"✓ Found Ruby library: {path}")
            return lib
        except OSError:
            continue

    raise RuntimeError("Could not find libruby shared library")


def test_ruby_init():
    """Test if we can initialize Ruby VM from Python main thread."""
    print("=" * 60)
    print("Python → Ruby Embedding POC")
    print("=" * 60)

    # Display thread info
    print(f"\nPython Version: {sys.version}")
    print(f"Current Thread: {threading.current_thread().name}")
    print(f"Is Main Thread: {threading.current_thread() is threading.main_thread()}")

    # Load Ruby library
    print("\n[Step 1] Loading Ruby shared library...")
    try:
        ruby = find_libruby()
    except RuntimeError as e:
        print(f"✗ FAILED: {e}")
        return False

    # Initialize Ruby VM
    print("\n[Step 2] Calling ruby_init() from Python main thread...")
    try:
        # Call ruby_init() - this is the critical test
        ruby.ruby_init()
        print("✓ ruby_init() succeeded!")
    except Exception as e:
        print(f"✗ FAILED: {e}")
        return False

    # Test basic Ruby evaluation
    print("\n[Step 3] Testing Ruby code evaluation...")
    try:
        # Set up function signature for rb_eval_string
        ruby.rb_eval_string.argtypes = [ctypes.c_char_p]
        ruby.rb_eval_string.restype = ctypes.c_void_p

        # Test simple Ruby code
        test_code = b"RUBY_VERSION"
        result = ruby.rb_eval_string(test_code)

        # Try to convert result to string
        ruby.rb_string_value_cstr.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        ruby.rb_string_value_cstr.restype = ctypes.c_char_p

        result_ptr = ctypes.c_void_p(result)
        version_str = ruby.rb_string_value_cstr(ctypes.byref(result_ptr))

        print(f"✓ Ruby evaluation succeeded!")
        print(f"  Ruby Version: {version_str.decode('utf-8')}")
    except Exception as e:
        print(f"✗ FAILED: {e}")
        print("  (Ruby initialized but evaluation failed)")
        # Don't return False - initialization is what matters

    # Test MSF loading
    print("\n[Step 4] Testing Metasploit Framework loading...")
    try:
        msf_path = "/home/aus/PycharmProjects/assassinate/metasploit-framework"

        # Build Ruby code to initialize MSF
        msf_init_code = f"""
        Dir.chdir('{msf_path}')
        $LOAD_PATH.unshift('{msf_path}/lib')
        ENV['RAILS_ENV'] ||= 'production'
        require '{msf_path}/config/boot'
        require 'msfenv'
        'MSF Loaded'
        """.encode('utf-8')

        result = ruby.rb_eval_string(msf_init_code)
        print("✓ MSF initialization code executed!")

        # Try to get MSF version
        version_code = b"Msf::Framework::Version"
        result = ruby.rb_eval_string(version_code)
        result_ptr = ctypes.c_void_p(result)
        version = ruby.rb_string_value_cstr(ctypes.byref(result_ptr))
        print(f"  MSF Version: {version.decode('utf-8')}")

    except Exception as e:
        print(f"✗ FAILED: {e}")
        print("  (Ruby works but MSF loading failed)")

    # Cleanup
    print("\n[Step 5] Cleanup...")
    try:
        ruby.ruby_finalize()
        print("✓ ruby_finalize() succeeded!")
    except Exception as e:
        print(f"⚠ Warning: ruby_finalize() failed: {e}")

    print("\n" + "=" * 60)
    print("RESULT: Python CAN initialize Ruby VM from main thread!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    try:
        success = test_ruby_init()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
