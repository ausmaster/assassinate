"""Tests for the profile module - TargetProfile and related data structures."""

import pytest
from assassinate.profile import (
    TargetProfile,
    LootItem,
    HarvestResult,
    Recommendation,
    HARVEST_MODULES,
    PRIVESC_MODULES,
)


class TestTargetProfile:
    """Tests for TargetProfile dataclass."""

    def test_linux_privileged_root(self):
        """Root user on Linux should be privileged."""
        profile = TargetProfile(
            os="Linux ubuntu 5.4.0 x86_64",
            os_name="Linux",
            computer="webserver",
            architecture="x64",
            user="root",
            uid=0,
        )
        assert profile.is_linux
        assert not profile.is_windows
        assert profile.is_privileged
        assert profile.is_64bit
        assert profile.is_unix

    def test_linux_unprivileged_user(self):
        """Regular user on Linux should not be privileged."""
        profile = TargetProfile(
            os="Linux ubuntu 5.4.0 x86_64",
            os_name="Linux",
            user="www-data",
            uid=33,
        )
        assert profile.is_linux
        assert not profile.is_privileged

    def test_windows_system(self):
        """SYSTEM on Windows should be privileged."""
        profile = TargetProfile(
            os="Windows 10 Build 19041",
            os_name="Windows",
            computer="WORKSTATION",
            architecture="x64",
            user="NT AUTHORITY\\SYSTEM",
            is_system=True,
            privileges=("SeDebugPrivilege", "SeImpersonatePrivilege"),
        )
        assert profile.is_windows
        assert not profile.is_linux
        assert profile.is_privileged
        assert profile.is_system

    def test_windows_admin(self):
        """Administrator on Windows should be privileged."""
        profile = TargetProfile(
            os="Windows Server 2019",
            os_name="Windows",
            user="DOMAIN\\Administrator",
            is_system=False,
        )
        assert profile.is_windows
        assert profile.is_privileged  # 'administrator' in user.lower()

    def test_windows_user(self):
        """Regular user on Windows should not be privileged."""
        profile = TargetProfile(
            os="Windows 10",
            os_name="Windows",
            user="WORKSTATION\\john",
            is_system=False,
            privileges=(),
        )
        assert profile.is_windows
        assert not profile.is_privileged

    def test_windows_with_debug_privilege(self):
        """User with SeDebugPrivilege should be privileged."""
        profile = TargetProfile(
            os="Windows 10",
            os_name="Windows",
            user="WORKSTATION\\john",
            is_system=False,
            privileges=("SeDebugPrivilege",),
        )
        assert profile.is_privileged

    def test_macos_detection(self):
        """macOS should be detected correctly."""
        profile = TargetProfile(
            os="Darwin 20.6.0",
            os_name="macOS",
        )
        assert profile.is_macos
        assert profile.is_unix
        assert not profile.is_windows

    def test_internal_networks(self):
        """Internal networks should be stored as tuple."""
        profile = TargetProfile(
            internal_networks=("10.0.0.0/24", "192.168.100.0/24"),
        )
        assert "10.0.0.0/24" in profile.internal_networks
        assert "192.168.100.0/24" in profile.internal_networks
        assert len(profile.internal_networks) == 2

    def test_frozen_dataclass(self):
        """TargetProfile should be immutable."""
        profile = TargetProfile(os="Linux", os_name="Linux")
        with pytest.raises(AttributeError):
            profile.os = "Windows"  # type: ignore

    def test_str_representation(self):
        """String representation should be informative."""
        profile = TargetProfile(
            os_name="Linux",
            architecture="x64",
            user="root",
            uid=0,
        )
        assert "Linux" in str(profile)
        assert "x64" in str(profile)
        assert "root" in str(profile)
        assert "privileged" in str(profile)


class TestLootItem:
    """Tests for LootItem dataclass."""

    def test_credential_loot(self):
        """Credential loot should store user/password data."""
        loot = LootItem(
            type="credential",
            source_module="post/windows/gather/hashdump",
            data={"user": "admin", "password": "hash123", "type": "ntlm"},
            host="192.168.1.100",
        )
        assert loot.type == "credential"
        assert loot.data["user"] == "admin"
        assert "hashdump" in loot.source_module

    def test_file_loot(self):
        """File loot should store path and content info."""
        loot = LootItem(
            type="file",
            source_module="post/linux/gather/enum_configs",
            data={"path": "/etc/passwd", "size": 1024},
            host="10.0.0.50",
        )
        assert loot.type == "file"
        assert loot.data["path"] == "/etc/passwd"

    def test_str_representation(self):
        """String representation should show type and module."""
        loot = LootItem(
            type="hash",
            source_module="post/linux/gather/hashdump",
            data={},
            host="192.168.1.100",
        )
        assert "hash" in str(loot)
        assert "hashdump" in str(loot)


class TestHarvestResult:
    """Tests for HarvestResult dataclass."""

    def test_empty_result(self):
        """Empty harvest result should have zero counts."""
        profile = TargetProfile(os="Linux", os_name="Linux")
        result = HarvestResult(profile=profile)
        assert len(result.loot) == 0
        assert result.creds_stored == 0
        assert len(result.modules_run) == 0
        assert len(result.credentials) == 0
        assert len(result.files) == 0
        assert len(result.hashes) == 0

    def test_with_loot(self):
        """Harvest result should categorize loot correctly."""
        profile = TargetProfile(os="Linux", os_name="Linux")
        result = HarvestResult(
            profile=profile,
            loot=[
                LootItem(type="credential", source_module="mod1", data={}, host="h1"),
                LootItem(type="credential", source_module="mod2", data={}, host="h1"),
                LootItem(type="file", source_module="mod3", data={}, host="h1"),
                LootItem(type="hash", source_module="mod4", data={}, host="h1"),
            ],
            creds_stored=2,
            modules_run=["mod1", "mod2", "mod3", "mod4"],
        )
        assert len(result.credentials) == 2
        assert len(result.files) == 1
        assert len(result.hashes) == 1
        assert result.creds_stored == 2

    def test_str_representation(self):
        """String representation should show counts."""
        profile = TargetProfile(os="Linux", os_name="Linux")
        result = HarvestResult(
            profile=profile,
            loot=[LootItem(type="credential", source_module="m", data={}, host="h")],
            creds_stored=1,
        )
        assert "1 items" in str(result)
        assert "1 creds" in str(result)


class TestRecommendation:
    """Tests for Recommendation dataclass."""

    def test_priority_sorting(self):
        """Recommendations should sort by priority."""
        recs = [
            Recommendation(category="persist", priority=4, title="Persistence", description=""),
            Recommendation(category="privesc", priority=1, title="Escalate", description=""),
            Recommendation(category="harvest", priority=2, title="Harvest", description=""),
        ]
        sorted_recs = sorted(recs)
        assert sorted_recs[0].priority == 1
        assert sorted_recs[1].priority == 2
        assert sorted_recs[2].priority == 4

    def test_with_module(self):
        """Recommendation can include a suggested module."""
        rec = Recommendation(
            category="privesc",
            priority=1,
            title="Local Exploit Suggester",
            description="Find local privilege escalation vectors",
            module="post/multi/recon/local_exploit_suggester",
        )
        assert rec.module is not None
        assert "suggester" in rec.module

    def test_with_options(self):
        """Recommendation can include suggested options."""
        rec = Recommendation(
            category="harvest",
            priority=2,
            title="Dump Hashes",
            description="Dump password hashes",
            module="post/windows/gather/hashdump",
            options={"GETSYSTEM": True},
        )
        assert rec.options["GETSYSTEM"] is True


class TestHarvestModulesRegistry:
    """Tests for HARVEST_MODULES registry."""

    def test_linux_modules_exist(self):
        """Linux harvest modules should be defined."""
        assert "linux" in HARVEST_MODULES
        assert "root" in HARVEST_MODULES["linux"]
        assert "user" in HARVEST_MODULES["linux"]
        assert len(HARVEST_MODULES["linux"]["root"]) > 0

    def test_windows_modules_exist(self):
        """Windows harvest modules should be defined."""
        assert "windows" in HARVEST_MODULES
        assert "system" in HARVEST_MODULES["windows"]
        assert "admin" in HARVEST_MODULES["windows"]
        assert "user" in HARVEST_MODULES["windows"]

    def test_macos_modules_exist(self):
        """macOS harvest modules should be defined."""
        assert "macos" in HARVEST_MODULES
        assert "root" in HARVEST_MODULES["macos"]
        assert "user" in HARVEST_MODULES["macos"]


class TestPrivescModulesRegistry:
    """Tests for PRIVESC_MODULES registry."""

    def test_platforms_covered(self):
        """All major platforms should have privesc modules."""
        assert "linux" in PRIVESC_MODULES
        assert "windows" in PRIVESC_MODULES
        assert "macos" in PRIVESC_MODULES

    def test_local_exploit_suggester_included(self):
        """Local exploit suggester should be in all platforms."""
        for platform in ["linux", "windows", "macos"]:
            modules = PRIVESC_MODULES[platform]
            assert any("local_exploit_suggester" in m for m in modules)
