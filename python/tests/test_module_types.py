"""Tests for type-specific module classes.

Tests that create_module() returns the correct class for all 7 MSF module types
and that type-specific APIs are properly exposed.
"""

import pytest
import msf


@pytest.fixture(scope="module")
def msf_init():
    """Initialize MSF framework once for all tests."""
    msf.init_msf("/home/astark/Projects/metasploit-framework")


class TestModuleTypeDetection:
    """Test that create_module returns correct class for all 7 types."""

    def test_auxiliary_returns_auxiliary_module(self, msf_init):
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert isinstance(module, msf.AuxiliaryModule)
        assert module.module_type == "auxiliary"

    def test_encoder_returns_encoder_module(self, msf_init):
        module = msf.create_module("encoder/x86/shikata_ga_nai")
        assert isinstance(module, msf.EncoderModule)
        assert module.module_type == "encoder"

    def test_evasion_returns_evasion_module(self, msf_init):
        module = msf.create_module("evasion/windows/applocker_evasion_msbuild")
        assert isinstance(module, msf.EvasionModule)
        assert module.module_type == "evasion"

    def test_exploit_returns_exploit_module(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert isinstance(module, msf.ExploitModule)
        assert module.module_type == "exploit"

    def test_nop_returns_nop_module(self, msf_init):
        module = msf.create_module("nop/x86/single_byte")
        assert isinstance(module, msf.NopModule)
        assert module.module_type == "nop"

    def test_payload_returns_payload_module(self, msf_init):
        module = msf.create_module("payload/cmd/unix/reverse_bash")
        assert isinstance(module, msf.PayloadModule)
        assert module.module_type == "payload"

    def test_post_returns_post_module(self, msf_init):
        module = msf.create_module("post/multi/gather/env")
        assert isinstance(module, msf.PostModule)
        assert module.module_type == "post"


class TestExploitModuleAPI:
    """Test ExploitModule has correct type-specific methods."""

    def test_has_exploit_method(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert hasattr(module, "exploit")
        assert callable(module.exploit)

    def test_has_check_method(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert hasattr(module, "check")
        assert callable(module.check)

    def test_has_has_check_method(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert hasattr(module, "has_check")
        assert callable(module.has_check)

    def test_has_targets_property(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert hasattr(module, "targets")
        targets = module.targets
        assert isinstance(targets, list)
        assert len(targets) > 0

    def test_has_compatible_payloads_method(self, msf_init):
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert hasattr(module, "compatible_payloads")
        payloads = module.compatible_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_does_not_have_run(self, msf_init):
        """ExploitModule should NOT have run() - that's for Auxiliary."""
        module = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert not hasattr(module, "run")


class TestAuxiliaryModuleAPI:
    """Test AuxiliaryModule has correct type-specific methods."""

    def test_has_run_method(self, msf_init):
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert hasattr(module, "run")
        assert callable(module.run)

    def test_has_actions_method(self, msf_init):
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert hasattr(module, "actions")
        assert callable(module.actions)

    def test_has_default_action_method(self, msf_init):
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert hasattr(module, "default_action")
        assert callable(module.default_action)

    def test_does_not_have_exploit(self, msf_init):
        """AuxiliaryModule should NOT have exploit()."""
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert not hasattr(module, "exploit")

    def test_does_not_have_compatible_payloads(self, msf_init):
        """AuxiliaryModule should NOT have compatible_payloads()."""
        module = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert not hasattr(module, "compatible_payloads")


class TestPostModuleAPI:
    """Test PostModule has correct type-specific methods."""

    def test_has_run_method(self, msf_init):
        module = msf.create_module("post/multi/gather/env")
        assert hasattr(module, "run")
        assert callable(module.run)

    def test_run_requires_session_argument(self, msf_init):
        """PostModule.run() must require a session argument."""
        module = msf.create_module("post/multi/gather/env")
        with pytest.raises(TypeError, match="requires a session"):
            module.run(None)

    def test_does_not_have_exploit(self, msf_init):
        """PostModule should NOT have exploit()."""
        module = msf.create_module("post/multi/gather/env")
        assert not hasattr(module, "exploit")


class TestEvasionModuleAPI:
    """Test EvasionModule has correct type-specific methods."""

    def test_has_run_method(self, msf_init):
        module = msf.create_module("evasion/windows/applocker_evasion_msbuild")
        assert hasattr(module, "run")
        assert callable(module.run)

    def test_has_targets_property(self, msf_init):
        module = msf.create_module("evasion/windows/applocker_evasion_msbuild")
        assert hasattr(module, "targets")

    def test_does_not_have_exploit(self, msf_init):
        """EvasionModule should NOT have exploit()."""
        module = msf.create_module("evasion/windows/applocker_evasion_msbuild")
        assert not hasattr(module, "exploit")


class TestPayloadModuleAPI:
    """Test PayloadModule has correct type-specific methods."""

    def test_has_generate_method(self, msf_init):
        module = msf.create_module("payload/cmd/unix/reverse_bash")
        assert hasattr(module, "generate")
        assert callable(module.generate)

    def test_has_to_handler_method(self, msf_init):
        module = msf.create_module("payload/cmd/unix/reverse_bash")
        assert hasattr(module, "to_handler")
        assert callable(module.to_handler)

    def test_does_not_have_exploit(self, msf_init):
        """PayloadModule should NOT have exploit()."""
        module = msf.create_module("payload/cmd/unix/reverse_bash")
        assert not hasattr(module, "exploit")

    def test_generate_raises_not_implemented(self, msf_init):
        """generate() is not yet implemented in Rust bridge."""
        module = msf.create_module("payload/cmd/unix/reverse_bash")
        with pytest.raises(NotImplementedError):
            module.generate()


class TestEncoderModuleAPI:
    """Test EncoderModule has correct type-specific methods."""

    def test_has_encode_method(self, msf_init):
        module = msf.create_module("encoder/x86/shikata_ga_nai")
        assert hasattr(module, "encode")
        assert callable(module.encode)

    def test_does_not_have_exploit(self, msf_init):
        """EncoderModule should NOT have exploit()."""
        module = msf.create_module("encoder/x86/shikata_ga_nai")
        assert not hasattr(module, "exploit")

    def test_encode_raises_not_implemented(self, msf_init):
        """encode() is not yet implemented in Rust bridge."""
        module = msf.create_module("encoder/x86/shikata_ga_nai")
        with pytest.raises(NotImplementedError):
            module.encode(b"\x90\x90")


class TestNopModuleAPI:
    """Test NopModule has correct type-specific methods."""

    def test_has_generate_sled_method(self, msf_init):
        module = msf.create_module("nop/x86/single_byte")
        assert hasattr(module, "generate_sled")
        assert callable(module.generate_sled)

    def test_does_not_have_exploit(self, msf_init):
        """NopModule should NOT have exploit()."""
        module = msf.create_module("nop/x86/single_byte")
        assert not hasattr(module, "exploit")

    def test_generate_sled_raises_not_implemented(self, msf_init):
        """generate_sled() is not yet implemented in Rust bridge."""
        module = msf.create_module("nop/x86/single_byte")
        with pytest.raises(NotImplementedError):
            module.generate_sled(100)


class TestBaseModuleShared:
    """Test that all module types have common base properties."""

    def test_all_types_have_base_properties(self, msf_init):
        """All 7 module types should have common base properties."""
        module_paths = [
            "auxiliary/scanner/smb/smb_version",
            "encoder/x86/shikata_ga_nai",
            "evasion/windows/applocker_evasion_msbuild",
            "exploit/linux/samba/is_known_pipename",
            "nop/x86/single_byte",
            "payload/cmd/unix/reverse_bash",
            "post/multi/gather/env",
        ]

        base_attrs = [
            "fullname",
            "description",
            "author",
            "options",
            "validate",
            "module_type",
            "platform",
            "arch",
            "rank",
            "license",
        ]

        for path in module_paths:
            module = msf.create_module(path)
            for attr in base_attrs:
                assert hasattr(module, attr), f"{path} missing {attr}"

    def test_all_types_inherit_from_base_module(self, msf_init):
        """All module types should inherit from BaseModule."""
        module_paths = [
            "auxiliary/scanner/smb/smb_version",
            "encoder/x86/shikata_ga_nai",
            "evasion/windows/applocker_evasion_msbuild",
            "exploit/linux/samba/is_known_pipename",
            "nop/x86/single_byte",
            "payload/cmd/unix/reverse_bash",
            "post/multi/gather/env",
        ]

        for path in module_paths:
            module = msf.create_module(path)
            assert isinstance(module, msf.BaseModule), f"{path} not a BaseModule"


class TestModuleRepr:
    """Test __repr__ includes class name."""

    def test_repr_shows_class_name(self, msf_init):
        exploit = msf.create_module("exploit/linux/samba/is_known_pipename")
        assert "ExploitModule" in repr(exploit)
        assert "is_known_pipename" in repr(exploit)

        aux = msf.create_module("auxiliary/scanner/smb/smb_version")
        assert "AuxiliaryModule" in repr(aux)
