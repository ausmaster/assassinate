"""Tests for the chain module - AttackChain and ChainStage."""

import pytest
from unittest.mock import MagicMock, patch

from assassinate.chain import AttackChain, ChainStage


class TestChainStage:
    """Tests for ChainStage dataclass."""

    def test_basic_stage(self):
        """ChainStage should store target and weapon info."""
        stage = ChainStage(
            name="dmz",
            target="192.168.1.100",
            weapon="exploit/linux/samba/is_known_pipename",
        )
        assert stage.name == "dmz"
        assert stage.target == "192.168.1.100"
        assert "samba" in stage.weapon
        assert stage.via is None
        assert stage.status == "pending"

    def test_stage_with_via(self):
        """ChainStage can reference another stage for pivoting."""
        stage = ChainStage(
            name="db",
            target="10.0.0.50",
            weapon="exploit/linux/postgres/...",
            via="dmz",
        )
        assert stage.via == "dmz"

    def test_stage_with_options(self):
        """ChainStage can include weapon options."""
        stage = ChainStage(
            name="initial",
            target="192.168.1.100",
            weapon="exploit/linux/samba/...",
            options={"SMB_SHARE_NAME": "myshare"},
        )
        assert stage.options["SMB_SHARE_NAME"] == "myshare"

    def test_repr(self):
        """Repr should be informative."""
        stage = ChainStage(
            name="dmz",
            target="192.168.1.100",
            weapon="exploit/linux/samba/...",
        )
        assert "dmz" in repr(stage)
        assert "192.168.1.100" in repr(stage)
        assert "pending" in repr(stage)


class TestAttackChainInit:
    """Tests for AttackChain initialization."""

    def test_init(self):
        """AttackChain should initialize with a hideout."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        assert len(chain.stages) == 0
        assert len(chain.results) == 0

    def test_repr_empty(self):
        """Repr should show stage count."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        assert "0 stages" in repr(chain)


class TestAttackChainAdd:
    """Tests for adding stages to a chain."""

    def test_add_single_stage(self):
        """add() should add a stage to the chain."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/linux/samba/...", name="initial")
        assert len(chain.stages) == 1
        assert chain.stages[0].name == "initial"

    def test_add_auto_name(self):
        """add() should auto-generate name if not provided."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/linux/samba/...")
        assert chain.stages[0].name == "stage_0"
        chain.add("192.168.1.101", "exploit/linux/samba/...")
        assert chain.stages[1].name == "stage_1"

    def test_add_chaining(self):
        """add() should return self for method chaining."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        result = chain.add("192.168.1.100", "exploit/linux/samba/...", name="a")
        assert result is chain

    def test_add_with_via(self):
        """add() should allow via parameter for pivoting."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/linux/samba/...", name="dmz")
        chain.add("10.0.0.50", "exploit/linux/postgres/...", name="db", via="dmz")
        assert chain.stages[1].via == "dmz"

    def test_add_with_options(self):
        """add() should accept keyword options."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add(
            "192.168.1.100",
            "exploit/linux/samba/...",
            name="initial",
            SMB_SHARE_NAME="myshare",
            TARGET=0,
        )
        assert chain.stages[0].options["SMB_SHARE_NAME"] == "myshare"
        assert chain.stages[0].options["TARGET"] == 0

    def test_add_duplicate_name_raises(self):
        """add() should raise ValueError for duplicate stage names."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/linux/samba/...", name="dmz")
        with pytest.raises(ValueError) as exc_info:
            chain.add("192.168.1.101", "exploit/linux/samba/...", name="dmz")
        assert "already exists" in str(exc_info.value)

    def test_add_unknown_via_raises(self):
        """add() should raise ValueError for unknown via reference."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        with pytest.raises(ValueError) as exc_info:
            chain.add("10.0.0.50", "exploit/...", name="db", via="nonexistent")
        assert "unknown via stage" in str(exc_info.value).lower()


class TestAttackChainExecutionOrder:
    """Tests for dependency resolution."""

    def test_independent_stages(self):
        """Independent stages should maintain add order."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("192.168.1.101", "exploit/...", name="b")
        chain.add("192.168.1.102", "exploit/...", name="c")

        order = chain._resolve_execution_order()
        names = [s.name for s in order]
        # All independent, should be in original order
        assert names == ["a", "b", "c"]

    def test_linear_dependency(self):
        """Linear dependencies should resolve to correct order."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("10.0.0.50", "exploit/...", name="b", via="a")
        chain.add("10.0.1.50", "exploit/...", name="c", via="b")

        order = chain._resolve_execution_order()
        names = [s.name for s in order]
        assert names.index("a") < names.index("b")
        assert names.index("b") < names.index("c")

    def test_complex_dependencies(self):
        """Complex dependency graph should resolve correctly."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        # a -> b, a -> c, b -> d
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("10.0.0.50", "exploit/...", name="b", via="a")
        chain.add("10.0.0.51", "exploit/...", name="c", via="a")
        chain.add("10.0.1.50", "exploit/...", name="d", via="b")

        order = chain._resolve_execution_order()
        names = [s.name for s in order]

        # a must be before b and c
        assert names.index("a") < names.index("b")
        assert names.index("a") < names.index("c")
        # b must be before d
        assert names.index("b") < names.index("d")

    def test_circular_dependency_raises(self):
        """Circular dependencies should raise ValueError."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        # Manually create circular dependency
        chain._stages = [
            ChainStage(name="a", target="1.1.1.1", weapon="x", via="b"),
            ChainStage(name="b", target="1.1.1.2", weapon="x", via="a"),
        ]

        with pytest.raises(ValueError) as exc_info:
            chain._resolve_execution_order()
        assert "circular" in str(exc_info.value).lower()


class TestAttackChainExecution:
    """Tests for chain execution."""

    @patch("assassinate.chain.msf")
    def test_execute_single_stage(self, mock_msf):
        """execute() should run a single stage."""
        mock_msf.route_exists.return_value = False
        mock_msf.route_add.return_value = True

        mock_hideout = MagicMock()
        mock_contract = MagicMock()
        mock_contract.profile.return_value = True
        mock_kill = MagicMock()
        mock_kill.id = 1
        mock_contract.execute.return_value = mock_kill
        mock_hideout.contract.return_value = mock_contract

        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="initial")

        results = chain.execute(timeout=60)

        assert "initial" in results
        assert results["initial"] is mock_kill
        mock_contract.configure.assert_called_once_with()
        mock_contract.execute.assert_called_once_with(60)

    @patch("assassinate.chain.msf")
    def test_execute_with_pivot(self, mock_msf):
        """execute() should set up pivot routes."""
        mock_msf.route_exists.return_value = False
        mock_msf.route_add.return_value = True

        mock_hideout = MagicMock()
        mock_contract = MagicMock()
        mock_contract.profile.return_value = True

        mock_kill1 = MagicMock()
        mock_kill1.id = 1
        mock_kill2 = MagicMock()
        mock_kill2.id = 2

        # First call returns kill1, second returns kill2
        mock_contract.execute.side_effect = [mock_kill1, mock_kill2]
        mock_hideout.contract.return_value = mock_contract

        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="dmz")
        chain.add("10.0.0.50", "exploit/...", name="db", via="dmz")

        results = chain.execute()

        assert len(results) == 2
        # Route should have been added for the internal network
        mock_msf.route_add.assert_called()

    @patch("assassinate.chain.msf")
    def test_execute_skip_on_failed_dependency(self, mock_msf):
        """Stages depending on failed stages should be skipped."""
        mock_hideout = MagicMock()
        mock_contract = MagicMock()
        mock_contract.profile.return_value = True
        mock_contract.execute.return_value = None  # Fail

        mock_hideout.contract.return_value = mock_contract

        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="dmz")
        chain.add("10.0.0.50", "exploit/...", name="db", via="dmz")

        results = chain.execute()

        assert len(results) == 0
        assert chain.stages[1].status == "skipped"

    @patch("assassinate.chain.msf")
    def test_execute_profile_failure(self, mock_msf):
        """Stages failing profile() should be marked failed."""
        mock_hideout = MagicMock()
        mock_contract = MagicMock()
        mock_contract.profile.return_value = False  # Profile fails

        mock_hideout.contract.return_value = mock_contract

        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="initial")

        results = chain.execute(profile_first=True)

        assert len(results) == 0
        assert chain.stages[0].status == "failed"


class TestAttackChainCleanup:
    """Tests for chain cleanup."""

    @patch("assassinate.chain.msf")
    def test_cleanup_removes_routes(self, mock_msf):
        """cleanup() should remove routes that were added."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)

        # Simulate routes that were added
        chain._routes_added = [
            ("10.0.0.0", "255.255.255.0", 1),
            ("10.0.1.0", "255.255.255.0", 1),
        ]

        chain.cleanup()

        assert mock_msf.route_remove.call_count == 2
        assert len(chain._routes_added) == 0

    @patch("assassinate.chain.msf")
    def test_cleanup_kills_sessions(self, mock_msf):
        """cleanup(kill_sessions=True) should kill sessions."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)

        mock_kill1 = MagicMock()
        mock_kill2 = MagicMock()
        chain._results = {"a": mock_kill1, "b": mock_kill2}

        chain.cleanup(kill_sessions=True)

        mock_kill1.silence.assert_called_once()
        mock_kill2.silence.assert_called_once()
        assert len(chain._results) == 0


class TestAttackChainProperties:
    """Tests for chain properties."""

    def test_pending_stages(self):
        """pending_stages should return stages with pending status."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("192.168.1.101", "exploit/...", name="b")

        chain._stages[0].status = "success"

        pending = chain.pending_stages
        assert len(pending) == 1
        assert pending[0].name == "b"

    def test_successful_stages(self):
        """successful_stages should return stages with success status."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("192.168.1.101", "exploit/...", name="b")

        chain._stages[0].status = "success"
        chain._stages[1].status = "failed"

        successful = chain.successful_stages
        assert len(successful) == 1
        assert successful[0].name == "a"

    def test_failed_stages(self):
        """failed_stages should return stages with failed status."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="a")
        chain.add("192.168.1.101", "exploit/...", name="b")

        chain._stages[0].status = "success"
        chain._stages[1].status = "failed"

        failed = chain.failed_stages
        assert len(failed) == 1
        assert failed[0].name == "b"


class TestAttackChainSummary:
    """Tests for chain summary."""

    def test_summary_includes_all_stages(self):
        """summary() should include all stages."""
        mock_hideout = MagicMock()
        chain = AttackChain(mock_hideout)
        chain.add("192.168.1.100", "exploit/...", name="dmz")
        chain.add("10.0.0.50", "exploit/...", name="db", via="dmz")

        summary = chain.summary()

        assert "dmz" in summary
        assert "db" in summary
        assert "via dmz" in summary
        assert "2 stages" in summary
