# Assassinate Bridge Test Harness

This directory contains the RSpec test harness that allows us to run Metasploit Framework's existing tests through our Rust FFI bridge, ensuring complete parity with native MSF behavior.

## Overview

The test harness works by:
1. Loading our Rust FFI bridge (via Magnus)
2. Intercepting MSF's framework initialization in tests
3. Replacing it with our bridge's initialization
4. Running MSF's unmodified tests against the bridge

This ensures that any updates to MSF's tests automatically validate our bridge.

## Directory Structure

```
spec/
├── README.md                          # This file
├── bridge_spec_helper.rb              # Main RSpec configuration
├── bridge_validation_spec.rb          # Validates bridge test harness
├── run_msf_tests.sh                   # Convenient test runner script
└── support/
    └── shared/
        └── contexts/
            └── bridge_framework.rb    # Bridge framework context
```

## Prerequisites

1. **Build the Rust bridge:**
   ```bash
   cd rust/bridge
   cargo build
   ```

2. **Install Metasploit dependencies:**
   ```bash
   cd metasploit-framework
   bundle install
   ```

3. **Set up PostgreSQL test database (REQUIRED for full test suite):**
   ```bash
   cd rust/bridge
   ./setup_test_db.sh
   ```

   This will:
   - Create PostgreSQL user `metasploit_framework_test`
   - Create database `metasploit_framework_test`
   - Generate `config/database.yml`
   - Initialize database schema

   **Note:** PostgreSQL is optional for running Metasploit itself, but **mandatory** for:
   - Running MSF's RSpec test suite
   - Data persistence (storing loot, hosts, credentials)
   - Fast module searching
   - Armitage front-end

   See [Managing the Database](https://docs.rapid7.com/metasploit/managing-the-database/) for more info.

4. **Set MSF_ROOT environment variable (optional):**
   ```bash
   export MSF_ROOT=/path/to/metasploit-framework
   ```

## Running Tests

### Using the test runner script (recommended):

```bash
# Validate the bridge test harness
./spec/run_msf_tests.sh bridge_validation_spec.rb

# Run MSF framework core tests
./spec/run_msf_tests.sh framework

# Run module manager tests
./spec/run_msf_tests.sh module_manager

# Run specific test file
./spec/run_msf_tests.sh spec/lib/msf/core/data_store_spec.rb
```

### Using rspec directly:

```bash
cd metasploit-framework
bundle exec rspec \
  --require ../rust/bridge/spec/bridge_spec_helper.rb \
  spec/lib/msf/core/framework_spec.rb
```

## How It Works

### 1. Bridge Initialization

The `bridge_spec_helper.rb` loads our Rust bridge and creates a Ruby wrapper:

```ruby
module AssassinateBridge
  def self.init_ruby
    # Initialize Ruby VM via Magnus embed
  end

  def self.init_metasploit(msf_path)
    # Load MSF via our bridge initialization path
  end

  def self.create_framework(options)
    # Create framework via bridge (returns real MSF object)
  end
end
```

### 2. Context Replacement

The `bridge_framework.rb` provides a shared context that replaces MSF's standard framework context:

```ruby
RSpec.shared_context 'Msf::Simple::Framework::Bridge' do
  let(:framework) do
    AssassinateBridge.init_ruby()
    AssassinateBridge.init_metasploit(msf_path)
    AssassinateBridge.create_framework(options)
  end
end
```

### 3. Test Execution

When MSF tests run:
- They include the `Msf::Simple::Framework` context
- Our harness intercepts and provides our bridge version
- The framework is initialized via our Rust bridge
- Tests run against real MSF objects created via our bridge
- Any failures indicate bridge compatibility issues

## Key Tests to Run

### Priority 1: Core Framework
```bash
./spec/run_msf_tests.sh framework
./spec/run_msf_tests.sh module_manager
./spec/run_msf_tests.sh data_store
```

### Priority 2: Module Execution
```bash
./spec/run_msf_tests.sh spec/lib/msf/base/simple/exploit_spec.rb
./spec/run_msf_tests.sh spec/lib/msf/base/simple/auxiliary_spec.rb
```

### Priority 3: Sessions & Payloads
```bash
./spec/run_msf_tests.sh spec/lib/msf/core/payload_set_spec.rb
./spec/run_msf_tests.sh spec/lib/msf/core/session_manager_spec.rb
```

## Troubleshooting

### "Bridge library not found"
Run `cargo build` in the rust/bridge directory.

### "Metasploit spec_helper not found"
Set the `MSF_ROOT` environment variable:
```bash
export MSF_ROOT=/path/to/metasploit-framework
```

### "bundler not found" errors
Install MSF dependencies:
```bash
cd metasploit-framework
bundle install
```

### Tests fail with initialization errors
Ensure Ruby 3.3.8 is active:
```bash
rbenv local 3.3.8
ruby --version  # Should show 3.3.8
```

## Benefits

✅ **No test maintenance** - MSF test updates automatically apply
✅ **Complete coverage** - Run all 495 MSF test files
✅ **True parity validation** - Tests real MSF objects via our bridge
✅ **CI/CD ready** - Can run in automated pipelines
✅ **Regression detection** - Catch bridge issues immediately

## Next Steps

1. Run validation tests to ensure harness works
2. Run critical MSF tests (framework, modules, sessions)
3. Identify and fix any compatibility issues
4. Add to CI/CD pipeline for continuous validation
