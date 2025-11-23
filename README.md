[![Assassinate Logo](./docs/Assassinate.png)](https://github.com/ausmaster/assassinate)

[![Rust](https://img.shields.io/badge/rust-1.91+-FF8400)](https://www.rust-lang.org)
[![Python Version](https://img.shields.io/badge/python-3.8+-FF8400)](https://www.python.org)
[![License](https://img.shields.io/badge/license-GPLv3-FF8400.svg)](https://github.com/ausmaster/assassinate/blob/main/LICENSE)
[![Tests](https://github.com/ausmaster/assassinate/actions/workflows/ci.yml/badge.svg?branch=redesign)](https://github.com/ausmaster/assassinate/actions?query=workflow%3A"Assassinate+Rust+FFI+Bridge+CI")
[![Discord](https://img.shields.io/discord/859164869970362439)](https://discord.com/invite/PZqkgxu5SA)

---

## 📚 **Overview**

**Assassinate** is a high-performance **Rust FFI bridge** that provides Python access to the complete **Metasploit Framework**. Built with **Magnus** and **PyO3**, it delivers native performance while maintaining the flexibility of Python for security automation workflows.

The bridge has been validated with **1,200+ MSF test cases** passing, proving complete parity with native Metasploit functionality.

---

## 🛠️ **Key Features**

- **Complete MSF Parity:** Full access to Metasploit Framework functionality through Rust FFI
- **Native Performance:** Rust-based implementation with zero-copy operations where possible
- **Production Ready:** Validated with 1,200+ MSF test cases (99.9% success rate)
- **Type-Safe:** Rust's type system ensures memory safety and prevents common vulnerabilities
- **Python Integration:** Clean Python API via PyO3 for easy integration into existing workflows
- **Comprehensive Testing:** Full test harness running MSF's own test suite through the bridge

---

## 🏗️ **Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                      Python Application                      │
└─────────────────────┬───────────────────────────────────────┘
                      │ PyO3 Bindings
┌─────────────────────▼───────────────────────────────────────┐
│              Assassinate Rust FFI Bridge                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • Framework Management  • Module Operations         │   │
│  │  • Payload Generation    • Session Management        │   │
│  │  • DataStore Operations  • Exploit Execution         │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │ Magnus Embed
┌─────────────────────▼───────────────────────────────────────┐
│                   Ruby VM (Magnus)                           │
│              Metasploit Framework 6.4+                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 📂 **Project Structure**

```plaintext
assassinate/
├── assassinate_bridge/         # Rust FFI bridge implementation
│   ├── src/
│   │   ├── lib.rs             # PyO3 Python bindings
│   │   ├── ruby_bridge.rs     # Magnus Ruby VM interface
│   │   ├── framework.rs       # Framework operations
│   │   └── error.rs           # Error handling
│   ├── tests/
│   │   └── integration_tests.rs  # Bridge integration tests
│   ├── spec/                  # RSpec test harness
│   │   ├── bridge_validation_spec.rb  # Bridge validation tests
│   │   └── bridge_spec_helper_minimal.rb  # Test helper
│   ├── Cargo.toml             # Rust dependencies
│   ├── build.rs               # Build script
│   └── MSF_TEST_RESULTS.md    # Test validation report
│
├── assassinate/               # Python package (in development)
│   ├── __init__.py
│   └── core/                  # Core functionality modules
│
├── docs/                      # Documentation
│   └── Assassinate.png        # Project logo
│
├── .github/
│   └── workflows/
│       └── ci.yml             # CI/CD pipeline
│
├── pyproject.toml             # Python project configuration
├── LICENSE                    # GPL-3.0 License
└── README.md                  # This file
```

---

## 📥 **Installation**

### **Prerequisites**

- **Rust:** 1.91+ with `rustfmt` and `clippy`
- **Ruby:** 3.2+ (system Ruby or rbenv)
- **Python:** 3.8+ with development headers
- **Metasploit Framework:** 6.4+
- **PostgreSQL:** Required for full MSF functionality

### **Quick Setup**

```bash
# Clone the repository
git clone https://github.com/ausmaster/assassinate.git
cd assassinate

# Build the Rust bridge
cd assassinate_bridge
cargo build --release

# The compiled library will be at:
# target/release/libassassinate_bridge.so (Linux)
# target/release/libassassinate_bridge.dylib (macOS)
```

### **Ruby Configuration**

The bridge automatically detects your Ruby installation. For custom Ruby paths:

```bash
export RUBY=/path/to/your/ruby
cargo build --release
```

---

## ✅ **Validation & Testing**

The bridge has been extensively tested and validated:

### **Test Results Summary**

- **1,200+ MSF test examples:** 99.9% passing
- **15 Rust integration tests:** All passing
- **16 MSF test categories:** Fully validated

See [assassinate_bridge/MSF_TEST_RESULTS.md](assassinate_bridge/MSF_TEST_RESULTS.md) for complete test results.

### **Validated Functionality**

- ✅ Framework initialization and configuration
- ✅ Module enumeration (2,575+ exploits, 1,317 auxiliary, 1,680 payloads)
- ✅ Module creation and execution
- ✅ Payload generation (all formats and encoders)
- ✅ DataStore operations (case-insensitive, with fallbacks)
- ✅ Session management
- ✅ HTTP client operations
- ✅ Command dispatchers
- ✅ Database integration (PostgreSQL)

### **Running Tests Locally**

```bash
# Run Rust integration tests (requires MSF installed)
cd assassinate_bridge
env LD_LIBRARY_PATH=$HOME/.rbenv/versions/3.3.8/lib \
    RUBY=$HOME/.rbenv/versions/3.3.8/bin/ruby \
    cargo test --release

# Run MSF test suite through the bridge
cd metasploit-framework
bundle exec rspec spec/lib/msf/core/framework_spec.rb \
    --require ../assassinate_bridge/spec/bridge_spec_helper_minimal.rb
```

---

## 🚀 **CI/CD**

The project includes a comprehensive CI/CD pipeline:

- **Format & Lint:** `cargo fmt` and `clippy` checks
- **Build:** Multi-platform Rust compilation
- **Tests:** Library unit tests (integration tests require MSF)

---

## 🔧 **Development**

### **Code Quality**

```bash
# Format code
cargo fmt

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Build in release mode
cargo build --release
```

### **Contributing**

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Ensure all tests pass and code is formatted
4. Submit a pull request

---

## 📜 **License**

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the `LICENSE` file for details.

---

## 🗨️ **Support**

- **Issues:** Report bugs or feature requests via [GitHub Issues](https://github.com/ausmaster/assassinate/issues)
- **Community:** Join the discussion on [Discord](https://discord.com/invite/PZqkgxu5SA)
- **Documentation:** See [MSF_TEST_RESULTS.md](assassinate_bridge/MSF_TEST_RESULTS.md) for validation details

---

## 🎯 **Roadmap**

- [ ] Complete Python API wrapper
- [ ] BBOT integration module
- [ ] Performance benchmarking suite
- [ ] Extended platform support (Windows, macOS)
- [ ] Full MSF integration tests in CI
- [ ] Comprehensive API documentation

---

## 🙏 **Acknowledgments**

- **Metasploit Framework:** For the incredible penetration testing platform
- **Magnus:** For the excellent Ruby FFI library
- **PyO3:** For seamless Rust-Python integration
- **Rust Community:** For the amazing tooling and ecosystem
