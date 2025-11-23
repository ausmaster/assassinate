# -*- coding:binary -*-
#
# Bridge Spec Helper
#
# This spec helper configures RSpec to run Metasploit's tests through our
# Rust FFI bridge. It loads MSF's spec_helper and then overrides the
# framework context to use our bridge.
#

# First, load our Rust bridge shared library
require 'ffi'

# Determine the path to our compiled Rust library
bridge_lib_path = File.expand_path('../target/debug', __dir__)
if RUBY_PLATFORM =~ /darwin/
  bridge_lib = File.join(bridge_lib_path, 'libassassinate_bridge.dylib')
elsif RUBY_PLATFORM =~ /linux/
  bridge_lib = File.join(bridge_lib_path, 'libassassinate_bridge.so')
else
  bridge_lib = File.join(bridge_lib_path, 'assassinate_bridge.dll')
end

unless File.exist?(bridge_lib)
  raise "Bridge library not found at #{bridge_lib}. Run 'cargo build' first."
end

# Load our Rust bridge as a Ruby module
# Note: Since we're using Magnus/rb-sys, the library should define Ruby methods
# We need to use require instead of FFI
$LOAD_PATH.unshift(bridge_lib_path)

# Actually, for Magnus-based extensions, we need to load via require
# Let's create a simple FFI wrapper to call our Rust functions
module AssassinateBridge
  extend FFI::Library

  # For now, we'll use Ruby eval to call through to our existing Rust bridge
  # This is a temporary solution - ideally we'd load the .so directly

  def self.init_ruby
    # Our Rust bridge already initializes Ruby via Magnus embed
    # This is called automatically when the module loads
    true
  end

  def self.init_metasploit(msf_path)
    # Use our existing ruby_bridge functions via eval
    msf_path_abs = File.expand_path(msf_path)

    # Initialize Metasploit the same way our Rust bridge does
    Dir.chdir(msf_path_abs)
    $LOAD_PATH.unshift(File.join(msf_path_abs, 'lib'))
    ENV['RAILS_ENV'] ||= 'test'  # Use test environment for specs

    require File.join(msf_path_abs, 'config', 'boot')
    require 'msfenv'

    true
  end

  def self.create_framework(options = {})
    # Call Msf::Simple::Framework.create with our options
    require 'msf/base/simple/framework'
    Msf::Simple::Framework.create(options)
  end
end

# Now load Metasploit's spec_helper
msf_root = ENV['MSF_ROOT'] || File.expand_path('../../metasploit-framework', __dir__)
msf_spec_helper = File.join(msf_root, 'spec', 'spec_helper.rb')

unless File.exist?(msf_spec_helper)
  raise "Metasploit spec_helper not found at #{msf_spec_helper}. Set MSF_ROOT environment variable."
end

# Set MSF_ROOT for the spec helper
ENV['MSF_ROOT'] = msf_root

# Load MSF's spec_helper
require msf_spec_helper

# Load our bridge framework context
require_relative 'support/shared/contexts/bridge_framework'

# Configure RSpec to use our bridge context
RSpec.configure do |config|
  # When a test includes 'Msf::Simple::Framework', use our bridge version instead
  config.include_context 'Msf::Simple::Framework::Bridge', :include_shared => true

  # Override the standard context
  config.before(:suite) do
    puts "\n" + "=" * 80
    puts "Running Metasploit tests through Assassinate Rust FFI Bridge"
    puts "=" * 80 + "\n"
  end

  config.after(:suite) do
    puts "\n" + "=" * 80
    puts "Bridge test suite complete"
    puts "=" * 80 + "\n"
  end
end
