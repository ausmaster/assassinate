"""Tests for the Kill class.

Kill wraps msf.Session with themed methods for post-exploitation.
Most tests use mock sessions to avoid needing real connections.
"""

import pytest
from unittest.mock import MagicMock, patch
import tempfile
import os

from assassinate.kill import Kill
from assassinate.target import Target


# =============================================================================
# Mock Session Fixture
# =============================================================================


@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    session = MagicMock()
    session.sid = 1
    session.session_type = "shell"
    session.host = "192.168.1.100"
    session.port = 445
    session.alive = True
    session.via_exploit = "exploit/linux/samba/is_known_pipename"
    session.via_payload = "cmd/unix/interact"
    session.info = "Test session"
    session.run_cmd.return_value = "root"
    session.read.return_value = "output data"
    session.write.return_value = 10
    return session


@pytest.fixture
def mock_meterpreter_session():
    """Create a mock meterpreter session for testing."""
    session = MagicMock()
    session.sid = 2
    session.session_type = "meterpreter"
    session.host = "192.168.1.100"
    session.port = 4444
    session.alive = True
    session.via_exploit = "exploit/multi/handler"
    session.via_payload = "linux/x64/meterpreter/reverse_tcp"
    session.info = "Meterpreter session"
    session.run_cmd.return_value = "root"
    session._rust = MagicMock()
    session._rust.fs_download = MagicMock()
    session._rust.fs_upload = MagicMock()
    return session


# =============================================================================
# Kill Construction Tests
# =============================================================================


class TestKillConstruction:
    """Tests for Kill construction."""

    def test_construction_minimal(self, mock_session):
        """Kill can be constructed with just a session."""
        kill = Kill(mock_session)

        assert kill._session is mock_session
        assert kill.target is None
        assert kill._via_weapon is None
        assert kill._via_payload is None

    def test_construction_with_target(self, mock_session):
        """Kill can be constructed with target."""
        target = Target("192.168.1.100")
        kill = Kill(mock_session, target=target)

        assert kill.target is target

    def test_construction_with_via_info(self, mock_session):
        """Kill can be constructed with via_weapon and via_payload."""
        kill = Kill(
            mock_session,
            via_weapon="exploit/test",
            via_payload="payload/test"
        )

        assert kill._via_weapon == "exploit/test"
        assert kill._via_payload == "payload/test"


# =============================================================================
# Kill Identity Tests
# =============================================================================


class TestKillIdentity:
    """Tests for Kill identity properties."""

    def test_id(self, mock_session):
        """id returns session ID."""
        kill = Kill(mock_session)

        assert kill.id == 1

    def test_type(self, mock_session):
        """type returns session type."""
        kill = Kill(mock_session)

        assert kill.type == "shell"

    def test_confirmed_when_alive(self, mock_session):
        """confirmed returns True when session alive."""
        kill = Kill(mock_session)

        assert kill.confirmed is True

    def test_confirmed_when_dead(self, mock_session):
        """confirmed returns False when session dead."""
        mock_session.alive = False
        kill = Kill(mock_session)

        assert kill.confirmed is False

    def test_confirmed_handles_exception(self, mock_session):
        """confirmed returns False on exception."""
        mock_session.alive = property(lambda self: (_ for _ in ()).throw(Exception("Error")))
        type(mock_session).alive = property(lambda self: (_ for _ in ()).throw(Exception("Error")))
        kill = Kill(mock_session)

        # This should not raise
        result = kill.confirmed
        assert result is False

    def test_is_meterpreter_true(self, mock_meterpreter_session):
        """is_meterpreter returns True for meterpreter sessions."""
        kill = Kill(mock_meterpreter_session)

        assert kill.is_meterpreter is True
        assert kill.is_shell is False

    def test_is_shell_true(self, mock_session):
        """is_shell returns True for shell sessions."""
        kill = Kill(mock_session)

        assert kill.is_shell is True
        assert kill.is_meterpreter is False


# =============================================================================
# Kill Target Info Tests
# =============================================================================


class TestKillTargetInfo:
    """Tests for Kill target information properties."""

    def test_host(self, mock_session):
        """host returns session host."""
        kill = Kill(mock_session)

        assert kill.host == "192.168.1.100"

    def test_port(self, mock_session):
        """port returns session port."""
        kill = Kill(mock_session)

        assert kill.port == 445

    def test_via_exploit_from_session(self, mock_session):
        """via_exploit uses session value if not provided."""
        kill = Kill(mock_session)

        assert kill.via_exploit == "exploit/linux/samba/is_known_pipename"

    def test_via_exploit_override(self, mock_session):
        """via_exploit uses provided value over session."""
        kill = Kill(mock_session, via_weapon="exploit/custom")

        assert kill.via_exploit == "exploit/custom"

    def test_via_payload_from_session(self, mock_session):
        """via_payload uses session value if not provided."""
        kill = Kill(mock_session)

        assert kill.via_payload == "cmd/unix/interact"

    def test_via_payload_override(self, mock_session):
        """via_payload uses provided value over session."""
        kill = Kill(mock_session, via_payload="payload/custom")

        assert kill.via_payload == "payload/custom"

    def test_info(self, mock_session):
        """info returns session info."""
        kill = Kill(mock_session)

        assert kill.info == "Test session"


# =============================================================================
# Kill Interrogation Tests
# =============================================================================


class TestKillInterrogation:
    """Tests for Kill command execution."""

    def test_interrogate(self, mock_session):
        """interrogate() executes command and returns output."""
        kill = Kill(mock_session)

        result = kill.interrogate("whoami")

        mock_session.run_cmd.assert_called_once_with("whoami", None)
        assert result == "root"

    def test_interrogate_with_timeout(self, mock_session):
        """interrogate() passes timeout to session."""
        kill = Kill(mock_session)

        kill.interrogate("id", timeout=30)

        mock_session.run_cmd.assert_called_once_with("id", 30)

    def test_read(self, mock_session):
        """read() returns session buffer data."""
        kill = Kill(mock_session)

        result = kill.read()

        mock_session.read.assert_called_once_with(None)
        assert result == "output data"

    def test_read_with_length(self, mock_session):
        """read() passes length parameter."""
        kill = Kill(mock_session)

        kill.read(length=100)

        mock_session.read.assert_called_once_with(100)

    def test_write(self, mock_session):
        """write() sends data to session."""
        kill = Kill(mock_session)

        result = kill.write("test data")

        mock_session.write.assert_called_once_with("test data")
        assert result == 10


# =============================================================================
# Kill File Operations Tests
# =============================================================================


class TestKillFileOperations:
    """Tests for Kill file operations."""

    def test_extract_shell_session(self, mock_session):
        """extract() uses cat for shell sessions."""
        mock_session.run_cmd.return_value = "file contents"
        kill = Kill(mock_session)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = os.path.join(tmpdir, "extracted.txt")
            result = kill.extract("/etc/passwd", local_path)

            # Check that run_cmd was called with the cat command
            call_args = mock_session.run_cmd.call_args[0][0]
            assert call_args == "cat /etc/passwd"
            assert result == local_path
            assert os.path.exists(local_path)

    def test_extract_meterpreter_session(self, mock_meterpreter_session):
        """extract() uses fs_download for meterpreter sessions."""
        kill = Kill(mock_meterpreter_session)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = os.path.join(tmpdir, "extracted.txt")
            kill.extract("/etc/passwd", local_path)

            mock_meterpreter_session._rust.fs_download.assert_called_once_with(
                "/etc/passwd", local_path
            )

    def test_extract_default_local_path(self, mock_session):
        """extract() uses filename as default local path."""
        mock_session.run_cmd.return_value = "contents"
        kill = Kill(mock_session)

        # Patch os.makedirs to avoid creating directories
        with patch('assassinate.kill.os.makedirs'):
            with patch('builtins.open', MagicMock()):
                result = kill.extract("/etc/passwd")

        assert result == "passwd"

    def test_extract_creates_directory(self, mock_session):
        """extract() creates parent directories."""
        mock_session.run_cmd.return_value = "contents"
        kill = Kill(mock_session)

        with tempfile.TemporaryDirectory() as tmpdir:
            local_path = os.path.join(tmpdir, "subdir", "extracted.txt")
            result = kill.extract("/etc/passwd", local_path)

            assert os.path.exists(os.path.dirname(local_path))

    def test_implant_shell_session(self, mock_session):
        """implant() uses base64 for shell sessions."""
        kill = Kill(mock_session)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            f.flush()

            try:
                result = kill.implant(f.name, "/tmp/uploaded.txt")

                # Should have called run_cmd with base64 echo
                assert mock_session.run_cmd.called
                call_args = mock_session.run_cmd.call_args[0][0]
                assert "base64" in call_args
                assert "/tmp/uploaded.txt" in call_args
                assert result is True
            finally:
                os.unlink(f.name)

    def test_implant_meterpreter_session(self, mock_meterpreter_session):
        """implant() uses fs_upload for meterpreter sessions."""
        kill = Kill(mock_meterpreter_session)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data")
            f.flush()

            try:
                result = kill.implant(f.name, "/tmp/uploaded.txt")

                mock_meterpreter_session._rust.fs_upload.assert_called_once_with(
                    f.name, "/tmp/uploaded.txt"
                )
                assert result is True
            finally:
                os.unlink(f.name)


# =============================================================================
# Kill Session Control Tests
# =============================================================================


class TestKillSessionControl:
    """Tests for Kill session control."""

    def test_silence(self, mock_session):
        """silence() kills the session."""
        kill = Kill(mock_session)

        kill.silence()

        mock_session.kill.assert_called_once()

    def test_silence_handles_exception(self, mock_session):
        """silence() handles exceptions gracefully."""
        mock_session.kill.side_effect = Exception("Error")
        kill = Kill(mock_session)

        # Should not raise
        kill.silence()


# =============================================================================
# Kill Future Features Tests
# =============================================================================


class TestKillFutureFeatures:
    """Tests for Kill future features (stubs)."""

    def test_escalate_not_implemented(self, mock_session):
        """escalate() raises NotImplementedError."""
        kill = Kill(mock_session)

        with pytest.raises(NotImplementedError) as exc_info:
            kill.escalate()

        assert "not yet implemented" in str(exc_info.value)

    def test_persist_not_implemented(self, mock_session):
        """persist() raises NotImplementedError."""
        kill = Kill(mock_session)

        with pytest.raises(NotImplementedError) as exc_info:
            kill.persist()

        assert "not yet implemented" in str(exc_info.value)

    def test_pivot_not_implemented(self, mock_session):
        """pivot() raises NotImplementedError."""
        kill = Kill(mock_session)

        with pytest.raises(NotImplementedError) as exc_info:
            kill.pivot("192.168.1.200")

        assert "not yet implemented" in str(exc_info.value)


# =============================================================================
# Kill Raw Access Tests
# =============================================================================


class TestKillRawAccess:
    """Tests for Kill raw session access."""

    def test_session_property(self, mock_session):
        """session property exposes underlying session."""
        kill = Kill(mock_session)

        assert kill.session is mock_session


# =============================================================================
# Kill Summary Tests
# =============================================================================


class TestKillSummary:
    """Tests for Kill summary and representation."""

    def test_summary_includes_id(self, mock_session):
        """summary() includes session ID."""
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "Kill #1" in summary

    def test_summary_includes_type(self, mock_session):
        """summary() includes session type."""
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "shell" in summary

    def test_summary_includes_host(self, mock_session):
        """summary() includes host and port."""
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "192.168.1.100" in summary
        assert "445" in summary

    def test_summary_includes_status(self, mock_session):
        """summary() includes confirmation status."""
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "CONFIRMED" in summary

    def test_summary_lost_status(self, mock_session):
        """summary() shows LOST for dead sessions."""
        mock_session.alive = False
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "LOST" in summary

    def test_summary_includes_via_info(self, mock_session):
        """summary() includes via_exploit and via_payload."""
        kill = Kill(mock_session)

        summary = kill.summary()

        assert "Via:" in summary or kill.via_exploit in summary

    def test_summary_includes_target(self, mock_session):
        """summary() includes target info if provided."""
        target = Target("192.168.1.100")
        kill = Kill(mock_session, target=target)

        summary = kill.summary()

        assert "Target:" in summary

    def test_repr(self, mock_session):
        """repr includes essential info."""
        kill = Kill(mock_session)

        repr_str = repr(kill)

        assert "<Kill #1" in repr_str
        assert "shell" in repr_str
        assert "192.168.1.100" in repr_str
        assert "confirmed" in repr_str

    def test_str(self, mock_session):
        """str provides brief summary."""
        kill = Kill(mock_session)

        str_val = str(kill)

        assert "Kill #1" in str_val
        assert "shell" in str_val


# =============================================================================
# Kill Equality Tests
# =============================================================================


class TestKillEquality:
    """Tests for Kill equality and hashing."""

    def test_equality_same_session(self):
        """Kills with same session ID are equal."""
        session1 = MagicMock()
        session1.sid = 1
        session1.alive = True

        session2 = MagicMock()
        session2.sid = 1
        session2.alive = True

        kill1 = Kill(session1)
        kill2 = Kill(session2)

        assert kill1 == kill2

    def test_inequality_different_session(self):
        """Kills with different session IDs are not equal."""
        session1 = MagicMock()
        session1.sid = 1
        session1.alive = True

        session2 = MagicMock()
        session2.sid = 2
        session2.alive = True

        kill1 = Kill(session1)
        kill2 = Kill(session2)

        assert kill1 != kill2

    def test_equality_with_int(self, mock_session):
        """Kill can be compared to int (session ID)."""
        kill = Kill(mock_session)

        assert kill == 1
        assert kill != 2

    def test_hash(self, mock_session):
        """Kill can be hashed based on ID."""
        kill = Kill(mock_session)

        h = hash(kill)
        assert isinstance(h, int)
        assert h == hash(1)

    def test_usable_in_set(self):
        """Kills can be used in sets."""
        session1 = MagicMock()
        session1.sid = 1
        session1.alive = True

        session2 = MagicMock()
        session2.sid = 1
        session2.alive = True

        session3 = MagicMock()
        session3.sid = 2
        session3.alive = True

        kill_set = {Kill(session1), Kill(session2), Kill(session3)}

        # session1 and session2 have same ID, should dedupe
        assert len(kill_set) == 2


# =============================================================================
# Kill Boolean Tests
# =============================================================================


class TestKillBoolean:
    """Tests for Kill boolean behavior."""

    def test_truthy_when_confirmed(self, mock_session):
        """Kill is truthy when session confirmed."""
        kill = Kill(mock_session)

        assert bool(kill) is True

    def test_falsy_when_lost(self, mock_session):
        """Kill is falsy when session lost."""
        mock_session.alive = False
        kill = Kill(mock_session)

        assert bool(kill) is False

    def test_if_statement_usage(self, mock_session):
        """Kill works in if statements."""
        kill = Kill(mock_session)

        if kill:
            result = "confirmed"
        else:
            result = "lost"

        assert result == "confirmed"
