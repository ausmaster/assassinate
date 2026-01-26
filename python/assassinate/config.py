"""Configuration system for Assassinate using Pydantic Settings.

Pydantic Settings automatically reads from environment variables with the
ASAS_ prefix. Nested models use __ delimiter (e.g., ASAS_METASPLOIT__ROOT).

Environment Variables (automatically bound by Pydantic):
    ASAS_METASPLOIT__ROOT: Path to MSF installation
    ASAS_RUBY__VERSION: Ruby version (e.g., "3.3.8")
    ASAS_RUBY__MANAGER: Ruby manager ("rvm", "rbenv", "system", "auto")
    ASAS_LOGGING__LEVEL: Log level (DEBUG, VERBOSE, INFO, WARNING, ERROR)
    ASAS_LOGGING__FILE: Path to log file
    ASAS_LOGGING__COLORS: Enable colored output (true/false)
    ASAS_DEFAULTS__LHOST: Default LHOST for reverse payloads
    ASAS_DEFAULTS__LPORT: Default LPORT (default: 4444)
    ASAS_DEFAULTS__TIMEOUT: Default timeout in seconds (default: 60)

Config File Locations (lower priority than env vars):
    - User: ~/.config/assassinate/config.yaml

Example:
    >>> from assassinate.config import get_config
    >>> config = get_config()
    >>> print(config.metasploit.root)  # From ASAS_METASPLOIT__ROOT or auto-detected
    /opt/metasploit-framework

    # Environment variables are automatically read:
    $ ASAS_LOGGING__LEVEL=DEBUG python script.py
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# =============================================================================
# Configuration Models (nested configs)
# =============================================================================


class MetasploitConfig(BaseModel):
    """Metasploit Framework configuration."""

    root: Path | None = Field(
        default=None,
        description="Path to MSF installation. Auto-detected if not set.",
    )

    @field_validator("root", mode="before")
    @classmethod
    def expand_path(cls, v: Any) -> Path | None:
        if v is None:
            return None
        if isinstance(v, str):
            return Path(v).expanduser().resolve()
        if isinstance(v, Path):
            return v.expanduser().resolve()
        return v


class RubyConfig(BaseModel):
    """Ruby environment configuration."""

    version: str | None = Field(
        default=None,
        description="Ruby version (e.g., '3.3.8'). Read from MSF .ruby-version if not set.",
    )
    manager: Literal["rvm", "rbenv", "system", "auto"] = Field(
        default="auto",
        description="Ruby version manager. Auto-detected if 'auto'.",
    )
    gem_home: Path | None = Field(
        default=None,
        description="GEM_HOME path. Derived from manager + version if not set.",
    )
    gem_path: Path | None = Field(
        default=None,
        description="GEM_PATH. Derived from manager + version if not set.",
    )


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal[
        "DEBUG", "VERBOSE", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"
    ] = Field(default="WARNING")
    file: Path | None = Field(default=None)
    colors: bool = Field(default=True)

    @field_validator("level", mode="before")
    @classmethod
    def uppercase_level(cls, v: Any) -> str:
        if isinstance(v, str):
            return v.upper()
        return v

    @field_validator("file", mode="before")
    @classmethod
    def expand_file_path(cls, v: Any) -> Path | None:
        if v is None:
            return None
        if isinstance(v, str):
            return Path(v).expanduser().resolve()
        return v


class DatabaseConfig(BaseModel):
    """MSF database configuration."""

    enabled: bool = Field(default=False)


class DefaultsConfig(BaseModel):
    """Default operational settings."""

    workspace: str = Field(default="default")
    timeout: int = Field(default=60, ge=1)
    lhost: str | None = Field(default=None)
    lport: int = Field(default=4444, ge=1, le=65535)


# =============================================================================
# User config file path
# =============================================================================

_USER_CONFIG_PATH = Path.home() / ".config" / "assassinate" / "config.yaml"


# =============================================================================
# Main Settings Class
# =============================================================================


class AssassinateSettings(BaseSettings):
    """Main configuration - Pydantic Settings automatically reads ASAS_* env vars.

    Priority (highest first):
    1. Environment variables (ASAS_* prefix)
    2. YAML config file (~/.config/assassinate/config.yaml)
    3. Default values
    4. Auto-detection (applied via .load())
    """

    model_config = SettingsConfigDict(
        env_prefix="ASAS_",
        env_nested_delimiter="__",
        extra="ignore",
        yaml_file=str(_USER_CONFIG_PATH) if _USER_CONFIG_PATH.exists() else None,
    )

    metasploit: MetasploitConfig = Field(default_factory=MetasploitConfig)
    ruby: RubyConfig = Field(default_factory=RubyConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)

    @classmethod
    def load(cls) -> AssassinateSettings:
        """Load config with auto-detection fallbacks applied."""
        settings = cls()

        # Auto-detect MSF root if not configured
        if settings.metasploit.root is None:
            from assassinate.detection import detect_msf_root

            detected = detect_msf_root()
            if detected:
                # Update in place
                object.__setattr__(settings.metasploit, "root", detected)

        # Auto-detect Ruby manager if "auto"
        if settings.ruby.manager == "auto":
            from assassinate.detection import detect_ruby_manager

            manager = detect_ruby_manager()
            object.__setattr__(settings.ruby, "manager", manager)

        # Auto-detect Ruby version from MSF's .ruby-version
        if settings.ruby.version is None and settings.metasploit.root:
            from assassinate.detection import detect_ruby_version

            version = detect_ruby_version(settings.metasploit.root)
            if version:
                object.__setattr__(settings.ruby, "version", version)

        return settings

    @property
    def msf_root(self) -> Path | None:
        """Convenience alias for metasploit.root."""
        return self.metasploit.root

    def to_yaml(self) -> str:
        """Export configuration as YAML string."""
        import yaml

        data: dict[str, Any] = {}

        if self.metasploit.root:
            data["metasploit"] = {"root": str(self.metasploit.root)}

        if self.ruby.version or self.ruby.manager not in ("auto", "system"):
            data["ruby"] = {}
            if self.ruby.version:
                data["ruby"]["version"] = self.ruby.version
            if self.ruby.manager not in ("auto", "system"):
                data["ruby"]["manager"] = self.ruby.manager

        if self.logging.level != "WARNING" or self.logging.file:
            data["logging"] = {"level": self.logging.level}
            if self.logging.file:
                data["logging"]["file"] = str(self.logging.file)
            if not self.logging.colors:
                data["logging"]["colors"] = False

        if self.defaults.lhost or self.defaults.lport != 4444:
            data["defaults"] = {}
            if self.defaults.lhost:
                data["defaults"]["lhost"] = self.defaults.lhost
            if self.defaults.lport != 4444:
                data["defaults"]["lport"] = self.defaults.lport

        return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)

    def save_user_config(self) -> Path:
        """Save current configuration to user config file."""
        _USER_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _USER_CONFIG_PATH.write_text(self.to_yaml())
        return _USER_CONFIG_PATH


# =============================================================================
# Singleton Access
# =============================================================================

_config: AssassinateSettings | None = None


def get_config() -> AssassinateSettings:
    """Get the global configuration instance (lazy-loaded with auto-detection)."""
    global _config
    if _config is None:
        _config = AssassinateSettings.load()
    return _config


def reload_config() -> AssassinateSettings:
    """Force reload configuration from all sources."""
    global _config
    _config = AssassinateSettings.load()
    return _config


def reset_config() -> None:
    """Reset global config to None (for testing)."""
    global _config
    _config = None


def get_user_config_path() -> Path:
    """Get the user config file path."""
    return _USER_CONFIG_PATH


__all__ = [
    "AssassinateSettings",
    "MetasploitConfig",
    "RubyConfig",
    "LoggingConfig",
    "DatabaseConfig",
    "DefaultsConfig",
    "get_config",
    "reload_config",
    "reset_config",
    "get_user_config_path",
]
