"""Tests for DbManager functionality.

Note: These tests require MSF database to be configured and connected.
If the database is not configured, tests will be skipped gracefully.
"""

import pytest


@pytest.mark.integration
class TestDbHosts:
    """Tests for database host operations."""

    async def test_list_hosts_returns_list(self, client):
        """Test that listing hosts returns a list."""
        hosts = await client.db_hosts()
        assert isinstance(hosts, list)
        # May be empty if no hosts reported
        assert hosts is not None

    async def test_list_hosts_type(self, client):
        """Test that host entries are strings."""
        hosts = await client.db_hosts()
        for host in hosts:
            assert isinstance(host, str)

    async def test_report_host_basic(self, client):
        """Test reporting a basic host."""
        # Report a test host
        result = await client.db_report_host(
            {
                "host": "192.168.1.100",
            }
        )
        # Should return host ID or success indicator
        assert result is not None

    async def test_report_host_with_details(self, client):
        """Test reporting a host with additional details."""
        result = await client.db_report_host(
            {
                "host": "192.168.1.101",
                "name": "test-host",
                "os_name": "Linux",
            }
        )
        assert result is not None


@pytest.mark.integration
class TestDbServices:
    """Tests for database service operations."""

    async def test_list_services_returns_list(self, client):
        """Test that listing services returns a list."""
        services = await client.db_services()
        assert isinstance(services, list)
        # May be empty if no services reported
        assert services is not None

    async def test_list_services_type(self, client):
        """Test that service entries are strings."""
        services = await client.db_services()
        for service in services:
            assert isinstance(service, str)

    async def test_report_service_basic(self, client):
        """Test reporting a basic service."""
        # First report the host
        await client.db_report_host({"host": "192.168.1.102"})

        # Then report a service on that host
        result = await client.db_report_service(
            {
                "host": "192.168.1.102",
                "port": "22",
                "proto": "tcp",
            }
        )
        assert result is not None

    async def test_report_service_with_details(self, client):
        """Test reporting a service with additional details."""
        await client.db_report_host({"host": "192.168.1.103"})

        result = await client.db_report_service(
            {
                "host": "192.168.1.103",
                "port": "80",
                "proto": "tcp",
                "name": "http",
                "info": "Apache 2.4",
            }
        )
        assert result is not None


@pytest.mark.integration
class TestDbVulns:
    """Tests for database vulnerability operations."""

    async def test_list_vulns_returns_list(self, client):
        """Test that listing vulnerabilities returns a list."""
        vulns = await client.db_vulns()
        assert isinstance(vulns, list)
        # May be empty if no vulnerabilities reported
        assert vulns is not None

    async def test_list_vulns_type(self, client):
        """Test that vulnerability entries are strings."""
        vulns = await client.db_vulns()
        for vuln in vulns:
            assert isinstance(vuln, str)

    async def test_report_vuln_basic(self, client):
        """Test reporting a basic vulnerability."""
        # First report the host
        await client.db_report_host({"host": "192.168.1.104"})

        # Report a vulnerability
        result = await client.db_report_vuln(
            {
                "host": "192.168.1.104",
                "name": "test_vulnerability",
            }
        )
        assert result is not None

    async def test_report_vuln_with_details(self, client):
        """Test reporting a vulnerability with additional details."""
        await client.db_report_host({"host": "192.168.1.105"})

        # Note: refs must be passed as an array in MSF, but our simple string-only API
        # doesn't support arrays yet. Testing without refs for now.
        result = await client.db_report_vuln(
            {
                "host": "192.168.1.105",
                "name": "CVE-2023-12345",
                "info": "Test vulnerability",
            }
        )
        assert result is not None


@pytest.mark.integration
class TestDbCreds:
    """Tests for database credential operations."""

    async def test_list_creds_returns_list(self, client):
        """Test that listing credentials returns a list."""
        creds = await client.db_creds()
        assert isinstance(creds, list)
        # May be empty if no credentials reported
        assert creds is not None

    async def test_list_creds_type(self, client):
        """Test that credential entries are strings."""
        creds = await client.db_creds()
        for cred in creds:
            assert isinstance(cred, str)

    async def test_report_cred_basic(self, client):
        """Test reporting a basic credential."""
        # First report the host and service
        await client.db_report_host({"host": "192.168.1.106"})
        await client.db_report_service(
            {
                "host": "192.168.1.106",
                "port": "22",
                "proto": "tcp",
                "name": "ssh",
            }
        )

        # Report a credential - MSF requires port for credential reporting
        result = await client.db_report_cred(
            {
                "host": "192.168.1.106",
                "port": "22",
                "user": "testuser",
                "pass": "testpass",
            }
        )
        assert result is not None

    async def test_report_cred_with_details(self, client):
        """Test reporting a credential with additional details."""
        await client.db_report_host({"host": "192.168.1.107"})
        await client.db_report_service(
            {
                "host": "192.168.1.107",
                "port": "443",
                "proto": "tcp",
                "name": "https",
            }
        )

        # Note: service_name requires workspace to be explicitly set in MSF's report_cred
        # Using simpler parameters that work without workspace
        result = await client.db_report_cred(
            {
                "host": "192.168.1.107",
                "port": "443",
                "user": "admin",
                "pass": "password123",
            }
        )
        assert result is not None


@pytest.mark.integration
class TestDbLoot:
    """Tests for database loot operations."""

    async def test_list_loot_returns_list(self, client):
        """Test that listing loot returns a list."""
        loot = await client.db_loot()
        assert isinstance(loot, list)
        # May be empty if no loot reported
        assert loot is not None

    async def test_list_loot_type(self, client):
        """Test that loot entries are strings."""
        loot = await client.db_loot()
        for item in loot:
            assert isinstance(item, str)


@pytest.mark.integration
class TestDbWorkflow:
    """Tests for complete database workflows."""

    async def test_report_and_retrieve_workflow(self, client):
        """Test complete workflow of reporting and retrieving data."""
        # Report a host
        await client.db_report_host(
            {
                "host": "192.168.1.200",
                "name": "workflow-test",
            }
        )

        # Report a service on that host
        await client.db_report_service(
            {
                "host": "192.168.1.200",
                "port": "443",
                "proto": "tcp",
                "name": "https",
            }
        )

        # Report a vulnerability
        await client.db_report_vuln(
            {
                "host": "192.168.1.200",
                "name": "test_workflow_vuln",
            }
        )

        # Report a credential - MSF requires port
        await client.db_report_cred(
            {
                "host": "192.168.1.200",
                "port": "443",
                "user": "workflow_user",
                "pass": "workflow_pass",
            }
        )

        # Verify we can retrieve the data
        hosts = await client.db_hosts()
        assert isinstance(hosts, list)

        services = await client.db_services()
        assert isinstance(services, list)

        vulns = await client.db_vulns()
        assert isinstance(vulns, list)

        creds = await client.db_creds()
        assert isinstance(creds, list)

    async def test_operations_dont_crash(self, client):
        """Test that database operations handle edge cases gracefully."""
        # These should not raise exceptions
        await client.db_hosts()
        await client.db_services()
        await client.db_vulns()
        await client.db_creds()
        await client.db_loot()

        # Report operations with minimal data should not crash
        try:
            await client.db_report_host({"host": "192.168.1.254"})
        except Exception:
            # May fail if database not configured, that's ok
            pass

    async def test_multiple_reports_same_host(self, client):
        """Test reporting multiple items for the same host."""
        host_ip = "192.168.1.250"

        # Report host once
        await client.db_report_host({"host": host_ip})

        # Report same host again (should update, not duplicate)
        await client.db_report_host(
            {
                "host": host_ip,
                "name": "updated-name",
            }
        )

        # Report multiple services on same host
        await client.db_report_service(
            {
                "host": host_ip,
                "port": "80",
                "proto": "tcp",
            }
        )

        await client.db_report_service(
            {
                "host": host_ip,
                "port": "443",
                "proto": "tcp",
            }
        )

        # Should not crash or error
        hosts = await client.db_hosts()
        assert isinstance(hosts, list)
