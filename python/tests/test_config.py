"""Tests for the configuration system."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest


class TestConfigBasics:
    """Test basic config functionality."""

    def test_config_imports(self):
        """Config module can be imported."""
        from assassinate.config import (
            AssassinateSettings,
            MetasploitConfig,
            RubyConfig,
            LoggingConfig,
            get_config,
            reload_config,
            reset_config,
        )

        assert AssassinateSettings is not None
        assert MetasploitConfig is not None

    def test_default_values(self):
        """Config has sensible defaults."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()
        settings = AssassinateSettings()

        assert settings.logging.level == "WARNING"
        assert settings.logging.colors is True
        assert settings.defaults.timeout == 60
        assert settings.defaults.lport == 4444
        assert settings.defaults.workspace == "default"
        assert settings.ruby.manager == "auto"

    def test_env_var_override(self):
        """Environment variables override defaults."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {
                "ASAS_LOGGING__LEVEL": "DEBUG",
                "ASAS_DEFAULTS__LPORT": "5555",
                "ASAS_DEFAULTS__TIMEOUT": "120",
            },
            clear=False,
        ):
            settings = AssassinateSettings()

            assert settings.logging.level == "DEBUG"
            assert settings.defaults.lport == 5555
            assert settings.defaults.timeout == 120

    def test_nested_env_vars(self):
        """Nested env vars with __ delimiter work."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {
                "ASAS_METASPLOIT__ROOT": "/test/msf/path",
                "ASAS_RUBY__VERSION": "3.3.8",
                "ASAS_RUBY__MANAGER": "rvm",
            },
            clear=False,
        ):
            settings = AssassinateSettings()

            assert settings.metasploit.root == Path("/test/msf/path")
            assert settings.ruby.version == "3.3.8"
            assert settings.ruby.manager == "rvm"


class TestDetection:
    """Test auto-detection functionality from system module."""

    def test_detection_imports(self):
        """System module detection functions can be imported."""
        from assassinate.system import (
            detect_msf_root,
            detect_ruby_manager,
            detect_ruby_version,
            get_ruby_env,
        )

        assert detect_msf_root is not None
        assert detect_ruby_manager is not None

    def test_detect_ruby_manager(self):
        """Ruby manager detection returns valid value."""
        from assassinate.system import detect_ruby_manager

        manager = detect_ruby_manager()
        assert manager in ("rvm", "rbenv", "system")

    def test_ruby_version_from_file(self):
        """Ruby version is read from .ruby-version file."""
        from assassinate.system import detect_ruby_version

        with tempfile.TemporaryDirectory() as tmpdir:
            ruby_version_file = Path(tmpdir) / ".ruby-version"
            ruby_version_file.write_text("3.3.8\n")

            version = detect_ruby_version(tmpdir)
            assert version == "3.3.8"

    def test_ruby_version_strips_prefix(self):
        """Ruby version strips 'ruby-' prefix if present."""
        from assassinate.system import detect_ruby_version

        with tempfile.TemporaryDirectory() as tmpdir:
            ruby_version_file = Path(tmpdir) / ".ruby-version"
            ruby_version_file.write_text("ruby-3.3.8\n")

            version = detect_ruby_version(tmpdir)
            assert version == "3.3.8"


class TestConfigSingleton:
    """Test config singleton behavior."""

    def test_get_config_returns_same_instance(self):
        """get_config returns the same instance on repeated calls."""
        from assassinate.config import get_config, reset_config

        reset_config()

        config1 = get_config()
        config2 = get_config()

        assert config1 is config2

    def test_reload_config_returns_new_instance(self):
        """reload_config returns a fresh instance."""
        from assassinate.config import get_config, reload_config, reset_config

        reset_config()

        config1 = get_config()
        config2 = reload_config()

        # Should be different objects
        assert config1 is not config2


class TestConfigExport:
    """Test config export functionality."""

    def test_to_yaml(self):
        """Config can be exported to YAML."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {
                "ASAS_METASPLOIT__ROOT": "/test/msf",
                "ASAS_LOGGING__LEVEL": "DEBUG",
            },
            clear=False,
        ):
            settings = AssassinateSettings()
            yaml_str = settings.to_yaml()

            assert "/test/msf" in yaml_str
            assert "DEBUG" in yaml_str

    def test_to_yaml_includes_new_defaults(self):
        """YAML export includes new default fields when non-default."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {
                "ASAS_DEFAULTS__MAX_PARALLEL": "20",
                "ASAS_DEFAULTS__PROFILE_TIMEOUT": "10.0",
                "ASAS_DEFAULTS__TIMEOUT": "120",
            },
            clear=False,
        ):
            settings = AssassinateSettings()
            yaml_str = settings.to_yaml()

            assert "max_parallel: 20" in yaml_str
            assert "profile_timeout: 10.0" in yaml_str
            assert "timeout: 120" in yaml_str


class TestConfigIntegration:
    """Test that config values are actually used by modules."""

    def test_config_has_max_parallel(self):
        """Config has max_parallel field with correct default."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        settings = AssassinateSettings()
        assert settings.defaults.max_parallel == 10

    def test_config_has_profile_timeout(self):
        """Config has profile_timeout field with correct default."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        settings = AssassinateSettings()
        assert settings.defaults.profile_timeout == 5.0

    def test_env_var_overrides_max_parallel(self):
        """Environment variable overrides max_parallel default."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {"ASAS_DEFAULTS__MAX_PARALLEL": "20"},
            clear=False,
        ):
            settings = AssassinateSettings()
            assert settings.defaults.max_parallel == 20

    def test_env_var_overrides_profile_timeout(self):
        """Environment variable overrides profile_timeout default."""
        from assassinate.config import AssassinateSettings, reset_config

        reset_config()

        with mock.patch.dict(
            os.environ,
            {"ASAS_DEFAULTS__PROFILE_TIMEOUT": "10.5"},
            clear=False,
        ):
            settings = AssassinateSettings()
            assert settings.defaults.profile_timeout == 10.5

    def test_get_config_returns_new_defaults(self):
        """get_config() returns settings with new default fields."""
        from assassinate.config import get_config, reset_config

        reset_config()

        config = get_config()
        assert hasattr(config.defaults, "max_parallel")
        assert hasattr(config.defaults, "profile_timeout")
        assert config.defaults.max_parallel == 10
        assert config.defaults.profile_timeout == 5.0
