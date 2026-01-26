"""Tests for the Contract and MassContract classes.

Contract orchestrates Target + Weapon + Bullet for exploitation.
MassContract handles parallel multi-target attacks.

All tests require MSF initialization.
"""

import pytest
from unittest.mock import patch, MagicMock

from assassinate.contract import Contract, MassContract
from assassinate.target import Target
from assassinate.weapon import Weapon, Bullet


# =============================================================================
# Contract Construction Tests
# =============================================================================


class TestContractConstruction:
    """Tests for Contract construction and initialization."""

    def test_construction_with_strings(self, msf_init):
        """Contract accepts string target and weapon."""
        contract = Contract(
            target="192.168.1.100",
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert isinstance(contract.target, Target)
        assert contract.target.host == "192.168.1.100"
        assert isinstance(contract.weapon, Weapon)
        assert contract.weapon.fullname == "exploit/linux/samba/is_known_pipename"

    def test_construction_with_objects(self, exploit_module):
        """Contract accepts Target and Weapon objects."""
        target = Target("192.168.1.100")
        weapon = Weapon(exploit_module)

        contract = Contract(target=target, weapon=weapon)

        assert contract.target is target
        assert contract.weapon is weapon

    def test_auto_bullet_selection(self, exploit_module):
        """Contract auto-selects bullet if not provided."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        assert contract.bullet is not None
        assert isinstance(contract.bullet, Bullet)

    def test_explicit_bullet_string(self, exploit_module):
        """Contract accepts string bullet name."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module),
            bullet="cmd/unix/interact"
        )

        assert contract.bullet.name == "cmd/unix/interact"

    def test_explicit_bullet_object(self, exploit_module):
        """Contract accepts Bullet object."""
        bullet = Bullet("cmd/unix/interact")
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module),
            bullet=bullet
        )

        assert contract.bullet is bullet

    def test_initial_state(self, exploit_module):
        """Contract starts in unconfigured, unprofiled state."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        assert contract._profiled is False
        assert contract._configured is False
        assert contract._executed is False


# =============================================================================
# Contract Configuration Tests
# =============================================================================


class TestContractConfiguration:
    """Tests for Contract configuration."""

    def test_configure_sets_options(self, exploit_module):
        """configure() sets weapon options."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        contract.configure(SMB_SHARE_NAME="myshare")

        assert contract.weapon.options.SMB_SHARE_NAME == "myshare"

    def test_configure_auto_sets_rhosts(self, exploit_module):
        """configure() auto-sets RHOSTS from target."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        contract.configure()

        assert contract.weapon.options.RHOSTS == "192.168.1.100"

    def test_configure_explicit_rhosts(self, exploit_module):
        """configure() uses explicit RHOSTS if provided."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        contract.configure(RHOSTS="192.168.1.200")

        assert contract.weapon.options.RHOSTS == "192.168.1.200"

    def test_configure_returns_self(self, exploit_module):
        """configure() returns self for chaining."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        result = contract.configure(SMB_SHARE_NAME="myshare")

        assert result is contract

    def test_configure_multiple_options(self, exploit_module):
        """configure() sets multiple options at once."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        contract.configure(
            SMB_SHARE_NAME="myshare",
            RPORT=445,
        )

        assert contract.weapon.options.SMB_SHARE_NAME == "myshare"

    def test_set_bullet_option(self, exploit_module):
        """set_bullet_option() sets payload-related options."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        contract.set_bullet_option("LHOST", "10.0.0.1")

        assert contract.weapon.options.LHOST == "10.0.0.1"

    def test_set_bullet_option_returns_self(self, exploit_module):
        """set_bullet_option() returns self for chaining."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        result = contract.set_bullet_option("LHOST", "10.0.0.1")

        assert result is contract


# =============================================================================
# Contract Validation Tests
# =============================================================================


class TestContractValidation:
    """Tests for Contract validation."""

    def test_validate_unconfigured(self, exploit_module):
        """validate() returns issues for unconfigured contract."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        # validate() returns a list of issues when options are missing
        issues = contract.validate()
        assert isinstance(issues, list)
        # Should have at least RHOSTS issue since module isn't validated
        assert len(issues) > 0

    def test_validate_configured(self, exploit_module):
        """validate() returns fewer issues when configured."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        # With RHOSTS set, validation may pass or have fewer issues
        issues = contract.validate()
        assert isinstance(issues, list)

    def test_ready_property(self, exploit_module):
        """ready property reflects validation state."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        # Unconfigured - not ready
        assert contract.ready is False

        contract.configure()

        # Configured - may be ready (depends on module requirements)
        ready = contract.ready
        assert isinstance(ready, bool)


# =============================================================================
# Contract Profiling Tests
# =============================================================================


class TestContractProfiling:
    """Tests for Contract profiling (pre-execution checks)."""

    def test_profile_auto_configures(self, exploit_module):
        """profile() auto-configures if not done."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        # Mock socket to avoid network
        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # Port closed
            mock_socket.return_value = mock_sock

            contract.profile()

        assert contract._configured is True

    def test_profile_checks_port(self, exploit_module):
        """profile() checks if target port is open."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0  # Port open
            mock_socket.return_value = mock_sock

            result = contract.profile()

        # Port open means potentially vulnerable
        assert result is True
        assert contract._profiled is True

    def test_profile_port_closed(self, exploit_module):
        """profile() returns False if port closed."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # Port closed
            mock_socket.return_value = mock_sock

            result = contract.profile()

        assert result is False

    def test_profile_updates_target_ports(self, exploit_module):
        """profile() updates target.ports when port is open."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0  # Port open
            mock_socket.return_value = mock_sock

            contract.profile()

        # Target should have port recorded
        assert len(contract.target.ports) > 0

    def test_profile_handles_socket_error(self, exploit_module):
        """profile() handles socket errors gracefully."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_socket.side_effect = OSError("Connection refused")

            result = contract.profile()

        assert result is False


# =============================================================================
# Contract Execution Tests
# =============================================================================


class TestContractExecution:
    """Tests for Contract execution.

    Note: Actual exploitation tests require integration environment.
    These tests verify the contract API structure.
    """

    def test_execute_auto_configures(self, exploit_module):
        """execute() auto-configures if not done."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        # Try to execute - will fail but should auto-configure first
        try:
            contract.execute(timeout=1)  # Short timeout
        except Exception:
            pass

        # Should have been configured
        assert contract._configured is True

    def test_execute_marks_executed(self, exploit_module):
        """execute() marks contract as executed."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        # Execute will fail (no real target) but should mark executed
        try:
            contract.execute(timeout=1)
        except Exception:
            pass

        assert contract._executed is True

    def test_assassinate_exists(self, exploit_module):
        """assassinate() method exists as alias."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        assert hasattr(contract, 'assassinate')
        assert callable(contract.assassinate)

    def test_hit_exists(self, exploit_module):
        """hit() method exists as alias."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )

        assert hasattr(contract, 'hit')
        assert callable(contract.hit)


# =============================================================================
# Contract Summary Tests
# =============================================================================


class TestContractSummary:
    """Tests for Contract summary and representation."""

    def test_summary_includes_target(self, exploit_module):
        """summary() includes target information."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        summary = contract.summary()
        assert "192.168.1.100" in summary

    def test_summary_includes_weapon(self, exploit_module):
        """summary() includes weapon information."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        summary = contract.summary()
        assert contract.weapon.name in summary

    def test_summary_includes_bullet(self, exploit_module):
        """summary() includes bullet information."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        summary = contract.summary()
        assert "Bullet:" in summary

    def test_repr(self, exploit_module):
        """repr includes essential information."""
        contract = Contract(
            target="192.168.1.100",
            weapon=Weapon(exploit_module)
        )
        contract.configure()

        repr_str = repr(contract)

        assert "<Contract:" in repr_str
        assert "192.168.1.100" in repr_str
        assert contract.weapon.name in repr_str


# =============================================================================
# MassContract Construction Tests
# =============================================================================


class TestMassContractConstruction:
    """Tests for MassContract construction."""

    def test_construction_with_strings(self, msf_init):
        """MassContract accepts string targets and weapon."""
        targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
        mass = MassContract(
            targets=targets,
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert len(mass.targets) == 3
        assert all(isinstance(t, Target) for t in mass.targets)

    def test_construction_with_target_objects(self, exploit_module):
        """MassContract accepts Target objects."""
        targets = [
            Target("192.168.1.100"),
            Target("192.168.1.101"),
        ]
        mass = MassContract(
            targets=targets,
            weapon=Weapon(exploit_module)
        )

        assert mass.targets[0] is targets[0]
        assert mass.targets[1] is targets[1]

    def test_max_parallel_setting(self, msf_init):
        """MassContract accepts max_parallel setting."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename",
            max_parallel=5
        )

        assert mass.max_parallel == 5

    def test_initial_state(self, msf_init):
        """MassContract starts with empty results."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert mass._kills == []
        assert mass._failures == []
        assert mass._profile_results == {}


# =============================================================================
# MassContract Configuration Tests
# =============================================================================


class TestMassContractConfiguration:
    """Tests for MassContract configuration."""

    def test_configure_sets_common_options(self, msf_init):
        """configure() sets options for all targets."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        mass.configure(SMB_SHARE_NAME="myshare")

        assert mass._common_options["SMB_SHARE_NAME"] == "myshare"

    def test_configure_returns_self(self, msf_init):
        """configure() returns self for chaining."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        result = mass.configure(SMB_SHARE_NAME="myshare")

        assert result is mass


# =============================================================================
# MassContract Profiling Tests
# =============================================================================


class TestMassContractProfiling:
    """Tests for MassContract profiling."""

    def test_profile_all_returns_dict(self, msf_init):
        """profile_all() returns dict mapping targets to results."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename"
        )
        mass.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # Port closed
            mock_socket.return_value = mock_sock

            results = mass.profile_all()

        assert isinstance(results, dict)
        assert len(results) == 2

    def test_profile_all_parallel(self, msf_init):
        """profile_all() runs in parallel by default."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename",
            max_parallel=2
        )
        mass.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1
            mock_socket.return_value = mock_sock

            results = mass.profile_all(parallel=True)

        assert len(results) == 2

    def test_profile_all_sequential(self, msf_init):
        """profile_all() can run sequentially."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename"
        )
        mass.configure()

        with patch('assassinate.contract.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1
            mock_socket.return_value = mock_sock

            results = mass.profile_all(parallel=False)

        assert len(results) == 2


# =============================================================================
# MassContract Execution Tests
# =============================================================================


class TestMassContractExecution:
    """Tests for MassContract execution."""

    def test_execute_all_returns_list(self, msf_init):
        """execute_all() returns list of kills."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )
        mass.configure()

        # Mock to avoid actual exploitation
        with patch.object(Contract, 'execute', return_value=None):
            with patch.object(Contract, 'profile', return_value=False):
                # Skip profiling to avoid socket operations
                mass._profile_results = {mass.targets[0]: True}
                result = mass.execute_all(profile_first=False)

        assert isinstance(result, list)

    def test_massacre_alias(self, msf_init):
        """massacre() is alias for execute_all()."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )
        mass.configure()

        # Skip profiling and mock execution
        with patch.object(Contract, 'execute', return_value=None):
            with patch.object(Contract, 'profile', return_value=False):
                mass._profile_results = {mass.targets[0]: True}
                result = mass.massacre(profile_first=False)

        assert isinstance(result, list)


# =============================================================================
# MassContract Results Tests
# =============================================================================


class TestMassContractResults:
    """Tests for MassContract result tracking."""

    def test_kills_property(self, msf_init):
        """kills property returns copy of kills list."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        kills = mass.kills

        assert isinstance(kills, list)
        # Modifying copy shouldn't affect original
        kills.append("test")
        assert "test" not in mass._kills

    def test_failures_property(self, msf_init):
        """failures property returns copy of failures list."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        failures = mass.failures

        assert isinstance(failures, list)

    def test_success_rate_no_attempts(self, msf_init):
        """success_rate is 0 with no attempts."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        assert mass.success_rate == 0.0

    def test_success_rate_calculation(self, msf_init):
        """success_rate calculates correctly."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        # Simulate some results
        mass._kills = [MagicMock()]  # 1 kill
        mass._failures = [(Target("192.168.1.101"), "Failed")]  # 1 failure

        assert mass.success_rate == 0.5

    def test_attempted_count(self, msf_init):
        """attempted counts total attempts."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        mass._kills = [MagicMock()]
        mass._failures = [(Target("192.168.1.101"), "Failed")]

        assert mass.attempted == 2


# =============================================================================
# MassContract Summary Tests
# =============================================================================


class TestMassContractSummary:
    """Tests for MassContract summary and representation."""

    def test_summary_includes_target_count(self, msf_init):
        """summary() includes target count."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        summary = mass.summary()

        assert "Targets: 2" in summary

    def test_summary_includes_weapon(self, msf_init):
        """summary() includes weapon name."""
        mass = MassContract(
            targets=["192.168.1.100"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        summary = mass.summary()

        assert "is_known_pipename" in summary

    def test_repr(self, msf_init):
        """repr includes essential information."""
        mass = MassContract(
            targets=["192.168.1.100", "192.168.1.101"],
            weapon="exploit/linux/samba/is_known_pipename"
        )

        repr_str = repr(mass)

        assert "<MassContract:" in repr_str
        assert "2 targets" in repr_str
