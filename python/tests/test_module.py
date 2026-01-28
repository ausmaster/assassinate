"""Tests for module operations.

Tests module creation, metadata, options, and validation.
"""

import pytest

import assassinate


class TestModuleCreation:
    """Tests for module instantiation."""

    def test_create_exploit_module(self, msf_init):
        """Test creating an exploit module."""
        module = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        assert isinstance(module, assassinate.ExploitModule)
        assert module.module_type == "exploit"

    def test_create_auxiliary_module(self, msf_init):
        """Test creating an auxiliary module."""
        module = assassinate.create_module("auxiliary/scanner/smb/smb_version")
        assert isinstance(module, assassinate.AuxiliaryModule)
        assert module.module_type == "auxiliary"

    def test_create_payload_module(self, msf_init):
        """Test creating a payload module."""
        module = assassinate.create_module("payload/cmd/unix/reverse_bash")
        assert isinstance(module, assassinate.PayloadModule)
        assert module.module_type == "payload"

    def test_create_post_module(self, msf_init):
        """Test creating a post module."""
        module = assassinate.create_module("post/multi/gather/env")
        assert isinstance(module, assassinate.PostModule)
        assert module.module_type == "post"

    def test_create_encoder_module(self, msf_init):
        """Test creating an encoder module."""
        module = assassinate.create_module("encoder/x86/shikata_ga_nai")
        assert isinstance(module, assassinate.EncoderModule)
        assert module.module_type == "encoder"

    def test_create_nop_module(self, msf_init):
        """Test creating a NOP module."""
        module = assassinate.create_module("nop/x86/single_byte")
        assert isinstance(module, assassinate.NopModule)
        assert module.module_type == "nop"

    def test_create_invalid_module_fails(self, msf_init):
        """Test that creating invalid module raises error."""
        with pytest.raises(Exception):
            assassinate.create_module("exploit/nonexistent/fake_module")

    def test_multiple_instances_independent(self, msf_init):
        """Test that multiple instances are independent."""
        module1 = assassinate.create_module("exploit/linux/samba/is_known_pipename")
        module2 = assassinate.create_module("exploit/linux/samba/is_known_pipename")

        # Set different options on each
        module1.options.RHOSTS = "10.0.0.1"
        module2.options.RHOSTS = "10.0.0.2"

        # Should have different values
        assert module1.options.RHOSTS == "10.0.0.1"
        assert module2.options.RHOSTS == "10.0.0.2"


class TestModuleMetadata:
    """Tests for module metadata and information."""

    def test_module_has_fullname(self, exploit_module):
        """Test that module has a fullname."""
        assert exploit_module.fullname == "exploit/linux/samba/is_known_pipename"

    def test_module_has_description(self, exploit_module):
        """Test that module has a description."""
        description = exploit_module.description
        assert description is not None
        assert len(description) > 0
        assert "samba" in description.lower() or "smb" in description.lower()

    def test_module_has_author(self, exploit_module):
        """Test that module has authors."""
        authors = exploit_module.author
        assert isinstance(authors, list)
        assert len(authors) > 0

    def test_module_has_references(self, exploit_module):
        """Test that module has references."""
        refs = exploit_module.references
        assert isinstance(refs, list)
        # SambaCry should have CVE reference
        assert any("CVE-2017-7494" in ref for ref in refs)

    def test_module_has_platform(self, exploit_module):
        """Test that module has platform information."""
        platform = exploit_module.platform
        assert isinstance(platform, list)
        # Platform names may have varying case
        platform_lower = [p.lower() for p in platform]
        assert "linux" in platform_lower or "unix" in platform_lower

    def test_module_has_arch(self, exploit_module):
        """Test that module has architecture information."""
        arch = exploit_module.arch
        assert isinstance(arch, list)

    def test_module_has_rank(self, exploit_module):
        """Test that module has a rank."""
        rank = exploit_module.rank
        assert isinstance(rank, str)
        # Rank can be numeric (like "600") or name (like "excellent")
        # MSF uses numeric internally: 0=manual, 100=low, 200=avg, 300=normal, 400=good, 500=great, 600=excellent
        valid_ranks = ["manual", "low", "average", "normal", "good", "great", "excellent",
                       "0", "100", "200", "300", "400", "500", "600"]
        assert rank in valid_ranks or rank.isdigit()


class TestModuleOptions:
    """Tests for module option handling."""

    def test_get_options_info(self, exploit_module):
        """Test getting options information."""
        # ModuleOptions provides attribute access to options
        # Check that RHOSTS option exists by accessing it
        rhosts = exploit_module.options.RHOSTS
        # Value may be None or empty string initially
        assert rhosts is None or isinstance(rhosts, str)

    def test_set_option_attribute(self, exploit_module):
        """Test setting option via attribute."""
        exploit_module.options.RHOSTS = "192.168.1.100"
        assert exploit_module.options.RHOSTS == "192.168.1.100"

    def test_set_option_item(self, exploit_module):
        """Test setting option via item syntax."""
        exploit_module.options["RHOSTS"] = "192.168.1.200"
        assert exploit_module.options["RHOSTS"] == "192.168.1.200"

    def test_set_multiple_options(self, exploit_module):
        """Test setting multiple options."""
        exploit_module.options.RHOSTS = "192.168.1.100"
        exploit_module.options.SMB_SHARE_NAME = "testshare"

        assert exploit_module.options.RHOSTS == "192.168.1.100"
        assert exploit_module.options.SMB_SHARE_NAME == "testshare"

    def test_option_case_insensitive(self, exploit_module):
        """Test that option names are case-insensitive."""
        exploit_module.options.rhosts = "10.0.0.1"
        assert exploit_module.options.RHOSTS == "10.0.0.1"


class TestModuleValidation:
    """Tests for module validation."""

    def test_validate_incomplete_raises_error(self, exploit_module):
        """Test that validating incomplete module raises error."""
        # Don't set required options - validation should fail
        with pytest.raises(Exception):
            exploit_module.validate()

    def test_validate_complete_succeeds(self, exploit_module):
        """Test that validating complete module succeeds."""
        exploit_module.options.RHOSTS = "192.168.1.100"
        exploit_module.options.SMB_SHARE_NAME = "testshare"

        # validate() returns True on success or raises on failure
        result = exploit_module.validate()
        assert result is True or result is None or isinstance(result, list)


class TestExploitModuleSpecific:
    """Tests specific to exploit modules."""

    def test_has_targets(self, exploit_module):
        """Test that exploit has targets."""
        targets = exploit_module.targets
        assert isinstance(targets, list)
        assert len(targets) > 0

    def test_has_check(self, exploit_module):
        """Test that exploit has check method."""
        assert exploit_module.has_check()

    def test_compatible_payloads(self, exploit_module):
        """Test getting compatible payloads."""
        payloads = exploit_module.compatible_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0
        # Should include cmd/unix/interact
        assert any("cmd/unix" in p for p in payloads)


class TestAuxiliaryModuleSpecific:
    """Tests specific to auxiliary modules."""

    def test_has_run_method(self, auxiliary_module):
        """Test that auxiliary module has run method."""
        assert hasattr(auxiliary_module, "run")
        assert callable(auxiliary_module.run)

    def test_has_actions(self, auxiliary_module):
        """Test that auxiliary module has actions method."""
        actions = auxiliary_module.actions()
        assert isinstance(actions, list)


class TestPostModuleSpecific:
    """Tests specific to post modules."""

    def test_run_requires_session(self, post_module):
        """Test that post module run requires session."""
        with pytest.raises(TypeError, match="requires a session"):
            post_module.run(None)
