"""Tests for the intel module - Intel class wrapping db_* functions."""

import sys
import pytest
from unittest.mock import patch, MagicMock


# Since Intel does `import msf` inside methods, we need to patch the msf module directly
@pytest.fixture
def mock_msf():
    """Create a mock msf module."""
    mock = MagicMock()
    with patch.dict(sys.modules, {'msf': mock}):
        yield mock


class TestIntelInit:
    """Tests for Intel initialization."""

    def test_init(self):
        """Intel should initialize without error."""
        from assassinate.intel import Intel
        intel = Intel()
        assert intel is not None

    def test_repr(self):
        """Repr should show database status."""
        from assassinate.intel import Intel
        intel = Intel()
        # Without mocking, db will likely be inactive
        assert "Intel" in repr(intel)


class TestIntelDatabaseStatus:
    """Tests for database status checks."""

    def test_is_active_true(self, mock_msf):
        """is_active should return True when db_active returns True."""
        mock_msf.db_active.return_value = True
        from assassinate.intel import Intel
        intel = Intel()
        assert intel.is_active is True

    def test_is_active_false(self, mock_msf):
        """is_active should return False when db_active returns False."""
        mock_msf.db_active.return_value = False
        from assassinate.intel import Intel
        intel = Intel()
        assert intel.is_active is False

    def test_is_active_exception(self, mock_msf):
        """is_active should return False when db_active raises."""
        mock_msf.db_active.side_effect = Exception("Connection failed")
        from assassinate.intel import Intel
        intel = Intel()
        assert intel.is_active is False

    def test_driver(self, mock_msf):
        """driver should return the database driver name."""
        mock_msf.db_driver.return_value = "postgresql"
        from assassinate.intel import Intel
        intel = Intel()
        assert intel.driver == "postgresql"


class TestIntelHosts:
    """Tests for host management."""

    def test_hosts_when_active(self, mock_msf):
        """hosts() should return hosts from db_hosts."""
        mock_msf.db_active.return_value = True
        mock_msf.db_hosts.return_value = [
            {"address": "192.168.1.100", "os_name": "Linux"},
            {"address": "192.168.1.101", "os_name": "Windows"},
        ]
        from assassinate.intel import Intel
        intel = Intel()
        hosts = intel.hosts()
        assert len(hosts) == 2
        assert hosts[0]["address"] == "192.168.1.100"

    def test_hosts_when_inactive(self, mock_msf):
        """hosts() should return empty list when database inactive."""
        mock_msf.db_active.return_value = False
        from assassinate.intel import Intel
        intel = Intel()
        hosts = intel.hosts()
        assert hosts == []

    def test_get_host(self, mock_msf):
        """get_host() should return single host by address."""
        mock_msf.db_active.return_value = True
        mock_msf.db_get_host.return_value = {"address": "192.168.1.100", "os_name": "Linux"}
        from assassinate.intel import Intel
        intel = Intel()
        host = intel.get_host("192.168.1.100")
        assert host is not None
        assert host["address"] == "192.168.1.100"

    def test_report_host(self, mock_msf):
        """report_host() should call db_report_host."""
        mock_msf.db_active.return_value = True
        mock_msf.db_report_host.return_value = 1
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.report_host("192.168.1.100", os_name="Linux")
        assert result == 1
        mock_msf.db_report_host.assert_called_once()


class TestIntelServices:
    """Tests for service management."""

    def test_services_when_active(self, mock_msf):
        """services() should return services from db_services."""
        mock_msf.db_active.return_value = True
        mock_msf.db_services.return_value = [
            {"host": "192.168.1.100", "port": 22, "proto": "tcp", "name": "ssh"},
            {"host": "192.168.1.100", "port": 80, "proto": "tcp", "name": "http"},
            {"host": "192.168.1.101", "port": 445, "proto": "tcp", "name": "smb"},
        ]
        from assassinate.intel import Intel
        intel = Intel()

        # All services
        services = intel.services()
        assert len(services) == 3

        # Filter by host
        services = intel.services(host="192.168.1.100")
        assert len(services) == 2

        # Filter by port
        services = intel.services(port=22)
        assert len(services) == 1

    def test_report_service(self, mock_msf):
        """report_service() should call db_report_service."""
        mock_msf.db_active.return_value = True
        mock_msf.db_report_service.return_value = 1
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.report_service("192.168.1.100", 22, name="ssh")
        assert result == 1
        mock_msf.db_report_service.assert_called_once()


class TestIntelCredentials:
    """Tests for credential management."""

    def test_creds_when_active(self, mock_msf):
        """creds() should return credentials from db_creds."""
        mock_msf.db_active.return_value = True
        mock_msf.db_creds.return_value = [
            {"host": "192.168.1.100", "user": "admin", "pass": "pass123", "sname": "ssh"},
            {"host": "192.168.1.100", "user": "root", "pass": "toor", "sname": "ssh"},
            {"host": "192.168.1.101", "user": "admin", "pass": "admin", "sname": "smb"},
        ]
        from assassinate.intel import Intel
        intel = Intel()

        # All creds
        creds = intel.creds()
        assert len(creds) == 3

        # Filter by host
        creds = intel.creds(host="192.168.1.100")
        assert len(creds) == 2

        # Filter by user
        creds = intel.creds(user="admin")
        assert len(creds) == 2

        # Filter by service
        creds = intel.creds(service="ssh")
        assert len(creds) == 2

    def test_store_cred(self, mock_msf):
        """store_cred() should call db_report_cred."""
        mock_msf.db_active.return_value = True
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.store_cred(
            host="192.168.1.100",
            port=22,
            user="admin",
            password="password123",
            service="ssh",
        )
        assert result is True
        mock_msf.db_report_cred.assert_called_once()

    def test_store_cred_when_inactive(self, mock_msf):
        """store_cred() should return False when database inactive."""
        mock_msf.db_active.return_value = False
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.store_cred("192.168.1.100", 22, "admin", "pass")
        assert result is False

    def test_find_creds_for_service(self, mock_msf):
        """find_creds_for_service() should filter by service name."""
        mock_msf.db_active.return_value = True
        mock_msf.db_creds.return_value = [
            {"host": "192.168.1.100", "user": "admin", "pass": "pass", "sname": "smb"},
        ]
        from assassinate.intel import Intel
        intel = Intel()
        creds = intel.find_creds_for_service("smb")
        assert len(creds) == 1
        assert creds[0]["sname"] == "smb"


class TestIntelVulnerabilities:
    """Tests for vulnerability management."""

    def test_vulns_when_active(self, mock_msf):
        """vulns() should return vulnerabilities from db_vulns."""
        mock_msf.db_active.return_value = True
        mock_msf.db_vulns.return_value = [
            {"host": "192.168.1.100", "name": "CVE-2017-7494"},
            {"host": "192.168.1.100", "name": "CVE-2019-0708"},
        ]
        from assassinate.intel import Intel
        intel = Intel()
        vulns = intel.vulns()
        assert len(vulns) == 2

    def test_vulns_filter_by_name(self, mock_msf):
        """vulns() should filter by vulnerability name."""
        mock_msf.db_active.return_value = True
        mock_msf.db_vulns.return_value = [
            {"host": "192.168.1.100", "name": "CVE-2017-7494"},
            {"host": "192.168.1.100", "name": "CVE-2019-0708"},
        ]
        from assassinate.intel import Intel
        intel = Intel()
        vulns = intel.vulns(name="2017")
        assert len(vulns) == 1

    def test_report_vuln(self, mock_msf):
        """report_vuln() should call db_report_vuln."""
        mock_msf.db_active.return_value = True
        mock_msf.db_report_vuln.return_value = 1
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.report_vuln("192.168.1.100", "CVE-2017-7494")
        assert result == 1
        mock_msf.db_report_vuln.assert_called_once()


class TestIntelWorkspaces:
    """Tests for workspace management."""

    def test_workspace_property(self, mock_msf):
        """workspace property should return current workspace."""
        mock_msf.db_active.return_value = True
        mock_msf.db_workspace.return_value = "default"
        from assassinate.intel import Intel
        intel = Intel()
        assert intel.workspace == "default"

    def test_workspaces_list(self, mock_msf):
        """workspaces() should list all workspaces."""
        mock_msf.db_active.return_value = True
        mock_msf.db_workspaces.return_value = ["default", "pentest", "client1"]
        from assassinate.intel import Intel
        intel = Intel()
        ws = intel.workspaces()
        assert len(ws) == 3
        assert "default" in ws

    def test_set_workspace(self, mock_msf):
        """set_workspace() should call db_set_workspace."""
        mock_msf.db_active.return_value = True
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.set_workspace("pentest")
        assert result is True
        mock_msf.db_set_workspace.assert_called_once_with("pentest")

    def test_create_workspace(self, mock_msf):
        """create_workspace() should call db_add_workspace."""
        mock_msf.db_active.return_value = True
        from assassinate.intel import Intel
        intel = Intel()
        result = intel.create_workspace("new_project")
        assert result is True
        mock_msf.db_add_workspace.assert_called_once_with("new_project")


class TestIntelSummary:
    """Tests for summary functionality."""

    def test_summary(self, mock_msf):
        """summary() should return counts of all intel types."""
        mock_msf.db_active.return_value = True
        mock_msf.db_hosts.return_value = [{"address": "192.168.1.100"}]
        mock_msf.db_services.return_value = [{"port": 22}, {"port": 80}]
        mock_msf.db_creds.return_value = [{"user": "admin"}]
        mock_msf.db_vulns.return_value = []
        mock_msf.db_loot.return_value = []

        from assassinate.intel import Intel
        intel = Intel()
        summary = intel.summary()

        assert summary["hosts"] == 1
        assert summary["services"] == 2
        assert summary["credentials"] == 1
        assert summary["vulnerabilities"] == 0
        assert summary["loot"] == 0
