# -*- coding:binary -*-
#
# Bridge Validation Spec
#
# This test validates that our bridge test harness is working correctly
# before we try to run the full MSF test suite.
#

require_relative 'bridge_spec_helper_minimal'

RSpec.describe 'Assassinate Bridge Test Harness' do
  include_context 'Msf::Simple::Framework::Bridge'

  describe 'Bridge initialization' do
    it 'creates a framework instance' do
      expect(framework).not_to be_nil
      expect(framework).to be_a(Msf::Framework)
    end

    it 'returns framework version' do
      version = framework.version
      expect(version).to be_a(String)
      expect(version).to match(/\d+\.\d+\.\d+/)
      puts "  Framework version: #{version}"
    end

    it 'has modules manager' do
      expect(framework.modules).not_to be_nil
      expect(framework.modules).to respond_to(:exploits)
      expect(framework.modules).to respond_to(:auxiliary)
      expect(framework.modules).to respond_to(:payloads)
    end

    it 'has datastore' do
      expect(framework.datastore).not_to be_nil
      expect(framework.datastore).to respond_to(:[])
      expect(framework.datastore).to respond_to(:[]=)
    end

    it 'has sessions manager' do
      expect(framework.sessions).not_to be_nil
      expect(framework.sessions).to respond_to(:keys)
    end
  end

  describe 'Module enumeration through bridge' do
    it 'can list exploit modules' do
      exploits = framework.modules.exploits.module_refnames
      expect(exploits).to be_a(Array)
      expect(exploits.length).to be > 0
      puts "  Found #{exploits.length} exploit modules"
    end

    it 'can list auxiliary modules' do
      auxiliary = framework.modules.auxiliary.module_refnames
      expect(auxiliary).to be_a(Array)
      expect(auxiliary.length).to be > 0
      puts "  Found #{auxiliary.length} auxiliary modules"
    end

    it 'can list payloads' do
      payloads = framework.modules.payloads.module_refnames
      expect(payloads).to be_a(Array)
      expect(payloads.length).to be > 0
      puts "  Found #{payloads.length} payloads"
    end
  end

  describe 'Module creation through bridge' do
    it 'can create an exploit module' do
      mod = framework.modules.create('exploit/unix/ftp/vsftpd_234_backdoor')
      expect(mod).not_to be_nil
      expect(mod.name).to eq('VSFTPD v2.3.4 Backdoor Command Execution')
    end

    it 'can access module datastore' do
      mod = framework.modules.create('exploit/unix/ftp/vsftpd_234_backdoor')
      expect(mod.datastore).not_to be_nil

      # Set and get a value
      mod.datastore['RHOSTS'] = '192.168.1.100'
      expect(mod.datastore['RHOSTS']).to eq('192.168.1.100')
    end
  end
end
