# -*- coding:binary -*-
#
# Bridge Framework Context
#
# This shared context replaces the standard Msf::Simple::Framework context
# to initialize the framework through our Rust FFI bridge instead of native Ruby.
# This allows us to run Metasploit's existing RSpec tests against our bridge
# without modifying them.
#

require 'pathname'
require 'fileutils'

RSpec.shared_context 'Msf::Simple::Framework::Bridge' do
  let(:dummy_pathname) do
    Pathname.new('/tmp/assassinate_bridge_test')
  end

  let(:framework) do
    # Get the MSF path from environment or use default
    msf_path = ENV['MSF_ROOT'] || File.expand_path('../../../../../metasploit-framework', __dir__)

    # Initialize Ruby VM via our Rust bridge (if not already initialized)
    unless defined?(@@ruby_initialized)
      AssassinateBridge.init_ruby()
      @@ruby_initialized = true
    end

    # Initialize Metasploit via our Rust bridge (if not already initialized)
    unless defined?(@@msf_initialized)
      AssassinateBridge.init_metasploit(msf_path)
      @@msf_initialized = true
    end

    # Create framework via our Rust bridge
    # This returns a REAL Msf::Framework object, just initialized via our bridge
    options = {
      'ConfigDirectory' => framework_config_pathname.to_s,
      'DeferModuleLoads' => true
    }

    AssassinateBridge.create_framework(options)
  end

  let(:framework_config_pathname) do
    dummy_pathname.join('framework', 'config')
  end

  before(:example) do
    framework_config_pathname.mkpath
  end

  after(:example) do
    FileUtils.rm_rf(dummy_pathname) if dummy_pathname.exist?
  end
end
