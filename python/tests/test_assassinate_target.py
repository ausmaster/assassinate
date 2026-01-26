"""Tests for the Target class.

The Target class is a pure Python class that represents a host to be
compromised. It doesn't require MSF initialization, so these are unit tests.
"""

import pytest

from assassinate import Target


class TestTargetConstruction:
    """Tests for Target construction and initialization."""

    def test_basic_construction(self):
        """Target can be constructed with just a host."""
        target = Target("192.168.1.100")

        assert target.host == "192.168.1.100"
        assert target.ports == set()
        assert target.services == {}
        assert target.vulns == []
        assert target.profiled is False

    def test_construction_with_ports(self):
        """Target can be constructed with initial ports."""
        target = Target("192.168.1.100", ports=[22, 80, 443])

        assert target.host == "192.168.1.100"
        assert target.ports == {22, 80, 443}
        assert target.services == {}

    def test_construction_with_services(self):
        """Target can be constructed with initial services."""
        services = {22: "ssh", 80: "http", 443: "https"}
        target = Target("192.168.1.100", services=services)

        assert target.host == "192.168.1.100"
        # Services automatically populates ports
        assert target.ports == {22, 80, 443}
        assert target.services == services

    def test_construction_with_ports_and_services(self):
        """Target can be constructed with both ports and services."""
        target = Target(
            "192.168.1.100",
            ports=[21, 22],
            services={22: "ssh", 80: "http"}
        )

        # Should have union of both
        assert target.ports == {21, 22, 80}
        assert target.services == {22: "ssh", 80: "http"}

    def test_hostname_construction(self):
        """Target accepts hostnames, not just IPs."""
        target = Target("example.com")
        assert target.host == "example.com"


class TestTargetPortTracking:
    """Tests for port and service tracking."""

    def test_add_port(self):
        """Can add a port without service."""
        target = Target("192.168.1.100")
        target.add_port(445)

        assert 445 in target.ports
        assert 445 not in target.services

    def test_add_port_with_service(self):
        """Can add a port with service name."""
        target = Target("192.168.1.100")
        target.add_port(445, "smb")

        assert 445 in target.ports
        assert target.services[445] == "smb"

    def test_has_port_true(self):
        """has_port returns True for known ports."""
        target = Target("192.168.1.100", ports=[22, 80])

        assert target.has_port(22) is True
        assert target.has_port(80) is True

    def test_has_port_false(self):
        """has_port returns False for unknown ports."""
        target = Target("192.168.1.100", ports=[22, 80])

        assert target.has_port(443) is False
        assert target.has_port(21) is False

    def test_has_service_true(self):
        """has_service returns True for known services."""
        target = Target("192.168.1.100", services={22: "ssh", 80: "http"})

        assert target.has_service("ssh") is True
        assert target.has_service("http") is True

    def test_has_service_case_insensitive(self):
        """has_service is case-insensitive."""
        target = Target("192.168.1.100", services={445: "smb"})

        assert target.has_service("smb") is True
        assert target.has_service("SMB") is True
        assert target.has_service("Smb") is True

    def test_has_service_false(self):
        """has_service returns False for unknown services."""
        target = Target("192.168.1.100", services={22: "ssh"})

        assert target.has_service("ftp") is False

    def test_get_port_for_service(self):
        """Can retrieve port number for a service."""
        target = Target("192.168.1.100", services={22: "ssh", 80: "http"})

        assert target.get_port_for_service("ssh") == 22
        assert target.get_port_for_service("http") == 80

    def test_get_port_for_service_case_insensitive(self):
        """get_port_for_service is case-insensitive."""
        target = Target("192.168.1.100", services={445: "SMB"})

        assert target.get_port_for_service("smb") == 445
        assert target.get_port_for_service("SMB") == 445

    def test_get_port_for_service_not_found(self):
        """get_port_for_service returns None for unknown services."""
        target = Target("192.168.1.100", services={22: "ssh"})

        assert target.get_port_for_service("ftp") is None


class TestTargetVulnerabilities:
    """Tests for vulnerability tracking."""

    def test_add_vuln(self):
        """Can add vulnerabilities."""
        target = Target("192.168.1.100")
        target.add_vuln("CVE-2017-7494")

        assert "CVE-2017-7494" in target.vulns

    def test_add_vuln_no_duplicates(self):
        """Adding the same vuln twice doesn't create duplicates."""
        target = Target("192.168.1.100")
        target.add_vuln("CVE-2017-7494")
        target.add_vuln("CVE-2017-7494")

        assert target.vulns.count("CVE-2017-7494") == 1

    def test_multiple_vulns(self):
        """Can track multiple vulnerabilities."""
        target = Target("192.168.1.100")
        target.add_vuln("CVE-2017-7494")
        target.add_vuln("CVE-2011-2523")
        target.add_vuln("CVE-2014-6287")

        assert len(target.vulns) == 3
        assert "CVE-2017-7494" in target.vulns
        assert "CVE-2011-2523" in target.vulns
        assert "CVE-2014-6287" in target.vulns


class TestTargetNotes:
    """Tests for notes tracking."""

    def test_add_note(self):
        """Can add notes."""
        target = Target("192.168.1.100")
        target.add_note("Initial scan complete")

        assert "Initial scan complete" in target.notes

    def test_notes_returns_copy(self):
        """notes property returns a copy, not the original list."""
        target = Target("192.168.1.100")
        target.add_note("Note 1")

        notes = target.notes
        notes.append("Should not appear")

        assert "Should not appear" not in target.notes


class TestTargetProfiling:
    """Tests for profiling state."""

    def test_profiled_initially_false(self):
        """Targets are not profiled initially."""
        target = Target("192.168.1.100")
        assert target.profiled is False

    def test_mark_profiled(self):
        """Can mark a target as profiled."""
        target = Target("192.168.1.100")
        target.mark_profiled()

        assert target.profiled is True


class TestTargetSummary:
    """Tests for summary output."""

    def test_summary_minimal(self):
        """Summary works for minimal target."""
        target = Target("192.168.1.100")
        summary = target.summary()

        assert "192.168.1.100" in summary
        assert "Profiled: False" in summary
        assert "(none discovered)" in summary

    def test_summary_with_ports(self):
        """Summary includes ports."""
        target = Target("192.168.1.100", ports=[22, 80])
        summary = target.summary()

        assert "22" in summary
        assert "80" in summary

    def test_summary_with_services(self):
        """Summary includes service names."""
        target = Target("192.168.1.100", services={445: "smb"})
        summary = target.summary()

        assert "445/smb" in summary

    def test_summary_with_vulns(self):
        """Summary includes vulnerabilities."""
        target = Target("192.168.1.100")
        target.add_vuln("CVE-2017-7494")
        summary = target.summary()

        assert "CVE-2017-7494" in summary
        assert "Vulns:" in summary

    def test_summary_with_notes(self):
        """Summary includes notes."""
        target = Target("192.168.1.100")
        target.add_note("Test note")
        summary = target.summary()

        assert "Notes:" in summary
        assert "Test note" in summary


class TestTargetRepresentation:
    """Tests for string representations."""

    def test_repr_minimal(self):
        """repr works for minimal target."""
        target = Target("192.168.1.100")
        repr_str = repr(target)

        assert "<Target 192.168.1.100" in repr_str
        assert "profiled=False" in repr_str

    def test_repr_with_ports(self):
        """repr includes ports."""
        target = Target("192.168.1.100", ports=[22, 445])
        repr_str = repr(target)

        assert "22" in repr_str
        assert "445" in repr_str

    def test_str_returns_host(self):
        """str() returns just the host."""
        target = Target("192.168.1.100")
        assert str(target) == "192.168.1.100"


class TestTargetEquality:
    """Tests for equality and hashing."""

    def test_equality_same_host(self):
        """Targets with same host are equal."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.100")

        assert target1 == target2

    def test_equality_different_ports(self):
        """Targets with same host but different ports are still equal."""
        target1 = Target("192.168.1.100", ports=[22])
        target2 = Target("192.168.1.100", ports=[80, 443])

        # Equality is based on host only
        assert target1 == target2

    def test_inequality_different_host(self):
        """Targets with different hosts are not equal."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.101")

        assert target1 != target2

    def test_equality_with_string(self):
        """Target can be compared to string."""
        target = Target("192.168.1.100")

        assert target == "192.168.1.100"
        assert target != "192.168.1.101"

    def test_hash_same_host(self):
        """Targets with same host have same hash."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.100")

        assert hash(target1) == hash(target2)

    def test_hash_different_host(self):
        """Targets with different hosts have different hashes."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.101")

        assert hash(target1) != hash(target2)

    def test_usable_in_set(self):
        """Targets can be used in sets."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.100")
        target3 = Target("192.168.1.101")

        target_set = {target1, target2, target3}

        # target1 and target2 are the same, so set should have 2 items
        assert len(target_set) == 2

    def test_usable_as_dict_key(self):
        """Targets can be used as dictionary keys."""
        target1 = Target("192.168.1.100")
        target2 = Target("192.168.1.100")

        d = {target1: "compromised"}
        d[target2] = "owned"

        # Same target, so should have 1 entry
        assert len(d) == 1
        assert d[target1] == "owned"
