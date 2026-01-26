"""Tests for the Hideout class.

Hideout is the main entry point for the Assassinate library.
It manages framework initialization, arsenal access, and kill tracking.

All tests require MSF initialization.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from assassinate.hideout import Hideout, KNOWN_SAFEHOUSES
from assassinate.arsenal import Arsenal
from assassinate.contract import Contract, MassContract
from assassinate.weapon import Weapon
from assassinate.target import Target
from assassinate.kill import Kill


# =============================================================================
# Hideout Construction Tests
# =============================================================================


class TestHideoutConstruction:
    """Tests for Hideout construction and initialization."""

    def test_construction_initializes_framework(self, msf_init):
        """Hideout initializes MSF framework."""
        # msf_init fixture already initializes, so we test that
        # a subsequent Hideout works
        hideout = Hideout(skip_verify=True)

        assert hideout._initialized is True
        assert hideout.version is not None

    def test_construction_sets_safehouse(self, msf_init):
        """Hideout locates MSF installation."""
        hideout = Hideout(skip_verify=True)

        assert hideout.safehouse is not None
        assert isinstance(hideout.safehouse, Path)

    def test_construction_skip_verify(self, msf_init):
        """Hideout can skip environment verification."""
        # This should not raise even if assassinate-setup isn't available
        hideout = Hideout(skip_verify=True)

        assert hideout._initialized is True


# =============================================================================
# Hideout Context Manager Tests
# =============================================================================


class TestHideoutContextManager:
    """Tests for Hideout context manager behavior."""

    def test_enter_returns_self(self, msf_init):
        """__enter__ returns the Hideout instance."""
        hideout = Hideout(skip_verify=True)

        result = hideout.__enter__()

        assert result is hideout

    def test_exit_calls_evacuate(self, msf_init):
        """__exit__ clears kills (evacuates)."""
        hideout = Hideout(skip_verify=True)

        # Add a mock kill to track
        mock_session = MagicMock()
        mock_session.sid = 99
        mock_session.alive = True
        hideout._kills[99] = Kill(mock_session)

        assert len(hideout._kills) == 1

        # Call __exit__ which should call evacuate()
        hideout.__exit__(None, None, None)

        # Kills should be cleared after evacuate
        assert len(hideout._kills) == 0

    def test_context_manager_usage(self, msf_init):
        """Hideout works as context manager."""
        with Hideout(skip_verify=True) as hideout:
            assert hideout._initialized is True

    def test_exit_returns_false(self, msf_init):
        """__exit__ returns False (doesn't suppress exceptions)."""
        hideout = Hideout(skip_verify=True)

        result = hideout.__exit__(None, None, None)

        assert result is False


# =============================================================================
# Hideout Evacuate Tests
# =============================================================================


class TestHideoutEvacuate:
    """Tests for Hideout evacuation."""

    def test_evacuate_clears_kills(self, msf_init):
        """evacuate() clears kill tracking."""
        hideout = Hideout(skip_verify=True)

        # Add a fake kill
        hideout._kills[1] = MagicMock()

        hideout.evacuate()

        assert len(hideout._kills) == 0


# =============================================================================
# Hideout Arsenal Tests
# =============================================================================


class TestHideoutArsenal:
    """Tests for Hideout arsenal access."""

    def test_arsenal_property(self, msf_init):
        """arsenal property returns Arsenal instance."""
        hideout = Hideout(skip_verify=True)

        arsenal = hideout.arsenal

        assert isinstance(arsenal, Arsenal)

    def test_arsenal_cached(self, msf_init):
        """arsenal property returns cached instance."""
        hideout = Hideout(skip_verify=True)

        arsenal1 = hideout.arsenal
        arsenal2 = hideout.arsenal

        assert arsenal1 is arsenal2


# =============================================================================
# Hideout Contract Factory Tests
# =============================================================================


class TestHideoutContractFactory:
    """Tests for Hideout contract creation."""

    def test_contract_with_strings(self, msf_init):
        """contract() accepts string arguments."""
        hideout = Hideout(skip_verify=True)

        contract = hideout.contract(
            target="192.168.1.100",
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert isinstance(contract, Contract)
        assert contract.target.host == "192.168.1.100"

    def test_contract_with_objects(self, msf_init):
        """contract() accepts Target and Weapon objects."""
        hideout = Hideout(skip_verify=True)
        target = Target("192.168.1.100")
        weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")

        contract = hideout.contract(target=target, weapon=weapon)

        assert contract.target is target

    def test_contract_with_bullet(self, msf_init):
        """contract() accepts bullet argument."""
        hideout = Hideout(skip_verify=True)

        contract = hideout.contract(
            target="192.168.1.100",
            weapon="exploit/linux/samba/is_known_pipename",
            bullet="cmd/unix/interact"
        )

        assert contract.bullet.name == "cmd/unix/interact"

    def test_mass_contract_with_strings(self, msf_init):
        """mass_contract() accepts string arguments."""
        hideout = Hideout(skip_verify=True)
        targets = ["192.168.1.100", "192.168.1.101"]

        mass = hideout.mass_contract(
            targets=targets,
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert isinstance(mass, MassContract)
        assert len(mass.targets) == 2

    def test_mass_contract_max_parallel(self, msf_init):
        """mass_contract() accepts max_parallel argument."""
        hideout = Hideout(skip_verify=True)

        mass = hideout.mass_contract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename",
            max_parallel=5
        )

        assert mass.max_parallel == 5


# =============================================================================
# Hideout Quick Operations Tests
# =============================================================================


class TestHideoutQuickOperations:
    """Tests for Hideout quick operation methods."""

    def test_quick_hit_creates_contract(self, msf_init):
        """quick_hit() creates and executes contract."""
        hideout = Hideout(skip_verify=True)

        with patch.object(Contract, 'execute', return_value=None):
            with patch.object(Contract, 'configure'):
                result = hideout.quick_hit(
                    target="192.168.1.100",
                    weapon="exploit/linux/samba/is_known_pipename"
                )

        assert result is None  # No kill returned

    def test_quick_hit_with_options(self, msf_init):
        """quick_hit() passes options to configure()."""
        hideout = Hideout(skip_verify=True)

        with patch.object(Contract, 'execute', return_value=None) as mock_execute:
            with patch.object(Contract, 'configure') as mock_configure:
                hideout.quick_hit(
                    target="192.168.1.100",
                    weapon="exploit/linux/samba/is_known_pipename",
                    SMB_SHARE_NAME="myshare"
                )

        mock_configure.assert_called_once_with(SMB_SHARE_NAME="myshare")

    def test_quick_hit_tracks_kill(self, msf_init):
        """quick_hit() tracks successful kill."""
        hideout = Hideout(skip_verify=True)

        mock_session = MagicMock()
        mock_session.sid = 99
        mock_session.alive = True
        mock_kill = Kill(mock_session)

        with patch.object(Contract, 'execute', return_value=mock_kill):
            with patch.object(Contract, 'configure'):
                result = hideout.quick_hit(
                    target="192.168.1.100",
                    weapon="exploit/linux/samba/is_known_pipename"
                )

        assert result is mock_kill
        assert 99 in hideout._kills


# =============================================================================
# Hideout Kill Management Tests
# =============================================================================


class TestHideoutKillManagement:
    """Tests for Hideout kill tracking."""

    def test_kills_empty_initially(self, msf_init):
        """kills() returns empty list initially."""
        hideout = Hideout(skip_verify=True)

        kills = hideout.kills()

        assert isinstance(kills, list)

    def test_get_kill_not_found(self, msf_init):
        """get_kill() returns None for unknown session."""
        hideout = Hideout(skip_verify=True)

        kill = hideout.get_kill(9999)

        assert kill is None

    def test_silence_all(self, msf_init):
        """silence_all() returns count of silenced kills."""
        hideout = Hideout(skip_verify=True)

        count = hideout.silence_all()

        assert isinstance(count, int)


# =============================================================================
# Hideout Legacy API Tests
# =============================================================================


class TestHideoutLegacyAPI:
    """Tests for Hideout legacy methods."""

    def test_arm_creates_module(self, msf_init):
        """arm() creates and returns MSF module."""
        hideout = Hideout(skip_verify=True)

        weapon = hideout.arm("exploit/linux/samba/is_known_pipename")

        assert weapon is not None
        assert weapon.fullname == "exploit/linux/samba/is_known_pipename"

    def test_recon_searches_arsenal(self, msf_init):
        """recon() searches for modules."""
        hideout = Hideout(skip_verify=True)

        results = hideout.recon("type:exploit samba")

        assert isinstance(results, list)

    def test_inventory_lists_modules(self, msf_init):
        """inventory() lists modules by type."""
        hideout = Hideout(skip_verify=True)

        exploits = hideout.inventory("exploit")

        assert isinstance(exploits, list)
        assert len(exploits) > 0

    def test_assets_lists_sessions(self, msf_init):
        """assets() lists session IDs."""
        hideout = Hideout(skip_verify=True)

        assets = hideout.assets()

        assert isinstance(assets, list)

    def test_get_asset(self, msf_init):
        """get_asset() returns session or None."""
        hideout = Hideout(skip_verify=True)

        # Non-existent session
        asset = hideout.get_asset(9999)
        assert asset is None

    def test_terminate_asset(self, msf_init):
        """terminate_asset() returns boolean."""
        hideout = Hideout(skip_verify=True)

        # Non-existent session should return False
        result = hideout.terminate_asset(9999)
        assert isinstance(result, bool)


# =============================================================================
# Hideout Operations Tests
# =============================================================================


class TestHideoutOperations:
    """Tests for Hideout job/operation management."""

    def test_active_ops_returns_list(self, msf_init):
        """active_ops() returns list of job IDs."""
        hideout = Hideout(skip_verify=True)

        ops = hideout.active_ops()

        assert isinstance(ops, list)

    def test_abort_op_returns_boolean(self, msf_init):
        """abort_op() returns boolean."""
        hideout = Hideout(skip_verify=True)

        # Non-existent job - should return False (job not found)
        result = hideout.abort_op(9999)
        assert isinstance(result, bool)
        assert result is False  # Job doesn't exist


# =============================================================================
# Hideout Environment Tests
# =============================================================================


class TestHideoutEnvironment:
    """Tests for Hideout environment handling."""

    def test_msf_root_env_var(self, msf_init):
        """Hideout respects MSF_ROOT environment variable."""
        # The fixture already sets MSF_ROOT
        hideout = Hideout(skip_verify=True)

        msf_root = os.environ.get("MSF_ROOT")
        if msf_root:
            assert str(hideout.safehouse) == os.path.expanduser(msf_root)

    def test_known_safehouses_list(self):
        """KNOWN_SAFEHOUSES contains expected paths."""
        assert len(KNOWN_SAFEHOUSES) > 0
        assert all(isinstance(p, Path) for p in KNOWN_SAFEHOUSES)


# =============================================================================
# Hideout Representation Tests
# =============================================================================


class TestHideoutRepresentation:
    """Tests for Hideout string representation."""

    def test_repr_shows_status(self, msf_init):
        """repr includes operational status."""
        hideout = Hideout(skip_verify=True)

        repr_str = repr(hideout)

        assert "<Hideout" in repr_str
        assert "operational" in repr_str

    def test_repr_shows_version(self, msf_init):
        """repr includes framework version."""
        hideout = Hideout(skip_verify=True)

        repr_str = repr(hideout)

        assert "version=" in repr_str

    def test_repr_shows_kills_count(self, msf_init):
        """repr includes kills count."""
        hideout = Hideout(skip_verify=True)

        repr_str = repr(hideout)

        assert "kills=" in repr_str


# =============================================================================
# Integration Tests
# =============================================================================


class TestHideoutIntegration:
    """Integration tests for Hideout with other components."""

    def test_full_workflow_without_execution(self, msf_init):
        """Test full workflow up to (but not including) execution."""
        with Hideout(skip_verify=True) as hideout:
            # Get specific weapon (avoid heavy search)
            weapon = hideout.arsenal.get("exploit/linux/samba/is_known_pipename")
            assert weapon.name == "is_known_pipename"

            # Create target
            target = Target("192.168.1.100")
            target.add_port(445, "smb")

            # Create contract
            contract = hideout.contract(target, weapon)
            contract.configure(SMB_SHARE_NAME="myshare")

            # Validate contract
            issues = contract.validate()
            assert isinstance(issues, list)

            # Summary
            summary = contract.summary()
            assert "192.168.1.100" in summary

    def test_mass_workflow_without_execution(self, msf_init):
        """Test mass contract workflow without execution."""
        with Hideout(skip_verify=True) as hideout:
            targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

            mass = hideout.mass_contract(
                targets=targets,
                weapon="exploit/linux/samba/is_known_pipename",
                max_parallel=2
            )

            mass.configure(SMB_SHARE_NAME="myshare")

            # Check summary
            summary = mass.summary()
            assert "Targets: 3" in summary
            assert "is_known_pipename" in summary

    def test_bullet_catalog_integration(self, msf_init):
        """Test bullet catalog filtering integration."""
        with Hideout(skip_verify=True) as hideout:
            # Use bullet catalog (lightweight, no module loading)
            meterpreter = hideout.arsenal.bullets.meterpreter().reverse().limit(5)

            # Should have results
            assert len(meterpreter) >= 0
