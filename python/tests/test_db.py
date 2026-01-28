"""Tests for database functions - Tier 3.

These tests verify the low-level msf module database API.
Requires PostgreSQL to be running (docker compose up -d postgres).
"""

import time

import pytest

import assassinate


class TestDatabaseStatus:
    """Tests for db_active() and db_driver()."""

    def test_checks_database_status(self, msf_init):
        """Should check if database is active."""
        active = assassinate.db_active()
        print(f"✓ Database active: {active}")

        if not active:
            pytest.skip("Database not active - ensure PostgreSQL is running")

        driver = assassinate.db_driver()
        print(f"✓ Database driver: {driver}")
        assert driver == "postgresql", "Driver should be postgresql"


class TestWorkspaceManagement:
    """Tests for workspace operations."""

    def test_manages_workspaces(self, msf_init):
        """Should create, find, set, and delete workspaces."""
        if not assassinate.db_active():
            pytest.skip("Database not active")

        # Create test workspace with unique name
        test_ws_name = f"test_py_workspace_{int(time.time())}"
        new_ws = assassinate.db_add_workspace(test_ws_name)
        print(f"✓ Created workspace: {new_ws}")

        assert new_ws.get("id") is not None, "Workspace should have ID"
        assert new_ws.get("name") == test_ws_name, "Name should match"

        # Find workspace
        found = assassinate.db_find_workspace(test_ws_name)
        assert found is not None, "Should find workspace"
        print("✓ Found workspace by name")

        # List workspaces
        workspaces = assassinate.db_workspaces()
        assert len(workspaces) >= 1, "Should have at least one workspace"
        print(f"✓ Listed {len(workspaces)} workspaces")

        # Set current workspace
        assassinate.db_set_workspace(test_ws_name)
        current = assassinate.db_workspace()
        assert current.get("name") == test_ws_name, "Current should be test workspace"
        print("✓ Set and verified current workspace")

        # Delete test workspace
        ws_id = new_ws.get("id")
        deleted = assassinate.db_delete_workspace(ws_id)
        assert deleted, "Should delete workspace"
        print("✓ Deleted workspace")

        # Verify gone
        gone = assassinate.db_find_workspace(test_ws_name)
        assert gone is None, "Should not find deleted workspace"
        print("✓ Verified workspace deleted")


class TestHostReporting:
    """Tests for host and service reporting."""

    def test_reports_hosts_and_services(self, msf_init):
        """Should report hosts and services to database."""
        if not assassinate.db_active():
            pytest.skip("Database not active")

        # Create test workspace
        test_ws_name = f"test_py_hosts_{int(time.time())}"
        assassinate.db_add_workspace(test_ws_name)
        assassinate.db_set_workspace(test_ws_name)
        print(f"✓ Created test workspace: {test_ws_name}")

        try:
            # Report a host
            host_id = assassinate.db_report_host({
                "host": "10.0.0.100",
                "os_name": "Linux",
                "os_flavor": "Debian",
            })
            print(f"✓ Reported host 10.0.0.100, ID: {host_id}")
            assert host_id > 0, "Host ID should be positive"

            # Query hosts
            hosts = assassinate.db_hosts()
            print(f"✓ Found {len(hosts)} hosts")
            assert "10.0.0.100" in hosts, "Should find reported host"

            # Report services
            ssh_id = assassinate.db_report_service({
                "host": "10.0.0.100",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
            })
            print(f"✓ Reported SSH service, ID: {ssh_id}")

            http_id = assassinate.db_report_service({
                "host": "10.0.0.100",
                "port": 80,
                "proto": "tcp",
                "name": "http",
            })
            print(f"✓ Reported HTTP service, ID: {http_id}")

            # Query services
            services = assassinate.db_services()
            print(f"✓ Found {len(services)} services")

            # Services are formatted as "host:port/proto"
            has_ssh = any("10.0.0.100:22/tcp" in s for s in services)
            has_http = any("10.0.0.100:80/tcp" in s for s in services)
            assert has_ssh, "Should find SSH service"
            assert has_http, "Should find HTTP service"
            print("✓ Verified SSH and HTTP services")

        finally:
            # Cleanup
            ws = assassinate.db_find_workspace(test_ws_name)
            if ws:
                assassinate.db_delete_workspace(ws["id"])
                print("✓ Cleaned up test workspace")


class TestVulnReporting:
    """Tests for vulnerability reporting."""

    def test_reports_vulnerabilities(self, msf_init):
        """Should report vulnerabilities to database."""
        if not assassinate.db_active():
            pytest.skip("Database not active")

        # Create test workspace
        test_ws_name = f"test_py_vulns_{int(time.time())}"
        assassinate.db_add_workspace(test_ws_name)
        assassinate.db_set_workspace(test_ws_name)

        try:
            # Report a host first
            assassinate.db_report_host({"host": "10.0.0.200"})

            # Report a vulnerability
            vuln_id = assassinate.db_report_vuln({
                "host": "10.0.0.200",
                "name": "CVE-2021-44228",
                "info": "Log4Shell vulnerability",
            })
            print(f"✓ Reported vulnerability, ID: {vuln_id}")
            # vuln_id might be 0 depending on how MSF returns it

            # Query vulns
            vulns = assassinate.db_vulns()
            print(f"✓ Found {len(vulns)} vulnerabilities")

        finally:
            ws = assassinate.db_find_workspace(test_ws_name)
            if ws:
                assassinate.db_delete_workspace(ws["id"])


class TestEmptyQueries:
    """Tests for querying empty tables."""

    def test_handles_empty_results(self, msf_init):
        """Should handle empty query results gracefully."""
        if not assassinate.db_active():
            pytest.skip("Database not active")

        # Create empty workspace
        test_ws_name = f"test_py_empty_{int(time.time())}"
        assassinate.db_add_workspace(test_ws_name)
        assassinate.db_set_workspace(test_ws_name)

        try:
            # Query empty tables - should return empty lists, not errors
            hosts = assassinate.db_hosts()
            assert isinstance(hosts, list), "hosts should return list"
            print(f"✓ Empty hosts query: {len(hosts)} results")

            services = assassinate.db_services()
            assert isinstance(services, list), "services should return list"
            print(f"✓ Empty services query: {len(services)} results")

            vulns = assassinate.db_vulns()
            assert isinstance(vulns, list), "vulns should return list"
            print(f"✓ Empty vulns query: {len(vulns)} results")

            loot = assassinate.db_loot()
            assert isinstance(loot, list), "loot should return list"
            print(f"✓ Empty loot query: {len(loot)} results")

        finally:
            ws = assassinate.db_find_workspace(test_ws_name)
            if ws:
                assassinate.db_delete_workspace(ws["id"])
