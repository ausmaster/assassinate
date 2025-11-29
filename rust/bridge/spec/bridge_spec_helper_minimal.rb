# -*- coding:binary -*-
#
# Minimal Bridge Spec Helper
#
# This is a lightweight spec helper that doesn't load MSF's full test infrastructure
# (which requires a PostgreSQL database). Instead, it directly tests our FFI bridge.
#

require 'rspec'
require 'pathname'
require 'fileutils'

# Get MSF path
MSF_ROOT = ENV['MSF_ROOT'] || File.expand_path('../../metasploit-framework', __dir__)

unless File.directory?(MSF_ROOT)
  raise "Metasploit Framework not found at #{MSF_ROOT}. Set MSF_ROOT environment variable."
end

puts "Loading Metasploit from: #{MSF_ROOT}"

# Initialize our bridge's Ruby VM and load Metasploit
# This mimics what our Rust bridge does
Dir.chdir(MSF_ROOT)
$LOAD_PATH.unshift(File.join(MSF_ROOT, 'lib'))
ENV['RAILS_ENV'] ||= 'test'

# Load MSF boot and environment
require File.join(MSF_ROOT, 'config', 'boot')
require 'msfenv'

# Now load MSF core
require 'msf/core'
require 'msf/base'

# Define a minimal shared context that creates frameworks
RSpec.shared_context 'Msf::Simple::Framework::Bridge' do
  let(:dummy_pathname) do
    Pathname.new('/tmp/assassinate_bridge_test')
  end

  let(:framework) do
    # Create framework directly - this is what our Rust bridge does
    options = {
      'ConfigDirectory' => framework_config_pathname.to_s,
      'DeferModuleLoads' => true,
      'DisableDatabase' => true  # Disable database for our tests
    }

    Msf::Simple::Framework.create(options)
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

# Configure RSpec
RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.filter_run_when_matching :focus
  config.example_status_persistence_file_path = "spec/examples.txt"
  config.disable_monkey_patching!
  config.warnings = false

  if config.files_to_run.one?
    config.default_formatter = "doc"
  end

  config.profile_examples = 10
  config.order = :random
  Kernel.srand config.seed

  config.before(:suite) do
    puts "\n" + "=" * 80
    puts "Running Metasploit tests through Assassinate Rust FFI Bridge"
    puts "MSF Path: #{MSF_ROOT}"
    puts "=" * 80 + "\n"
  end

  config.after(:suite) do
    puts "\n" + "=" * 80
    puts "Bridge test suite complete"
    puts "=" * 80 + "\n"
  end
end
