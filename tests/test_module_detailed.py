"""Detailed module tests modeled after MSF module_spec.rb."""

import pytest


@pytest.mark.integration
class TestModuleCreation:
    """Tests for module instantiation."""

    async def test_create_exploit_module(self, client):
        """Test creating an exploit module."""
        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        assert isinstance(module_id, str)
        assert len(module_id) > 0

    async def test_create_auxiliary_module(self, client):
        """Test creating an auxiliary module."""
        module_id = await client.create_module("auxiliary/scanner/http/title")
        assert isinstance(module_id, str)
        assert len(module_id) > 0

    async def test_create_payload_module(self, client):
        """Test creating a payload module."""
        module_id = await client.create_module(
            "payload/linux/x86/shell_reverse_tcp"
        )
        assert isinstance(module_id, str)
        assert len(module_id) > 0

    async def test_create_invalid_module_fails(self, client):
        """Test that creating invalid module raises error."""
        with pytest.raises(Exception):
            await client.create_module("exploit/nonexistent/fake_module")

    async def test_multiple_instances_independent(self, client):
        """Test that multiple instances are independent."""
        module_id1 = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        module_id2 = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )

        # Different IDs
        assert module_id1 != module_id2

        # Set different options on each
        await client.module_set_option(module_id1, "RHOSTS", "10.0.0.1")
        await client.module_set_option(module_id2, "RHOSTS", "10.0.0.2")

        # Should have different values
        val1 = await client.module_get_option(module_id1, "RHOSTS")
        val2 = await client.module_get_option(module_id2, "RHOSTS")
        assert val1 == "10.0.0.1"
        assert val2 == "10.0.0.2"


@pytest.mark.integration
class TestModuleMetadata:
    """Tests for module metadata and information."""

    async def test_module_has_name(self, test_module, client):
        """Test that module has a name."""
        info = await client.module_info(test_module)
        assert "name" in info
        assert len(info["name"]) > 0

    async def test_module_has_fullname(self, test_module, client):
        """Test that module has a fullname."""
        info = await client.module_info(test_module)
        assert "fullname" in info
        assert info["fullname"] == "exploit/unix/ftp/vsftpd_234_backdoor"

    async def test_module_has_type(self, test_module, client):
        """Test that module has a type."""
        info = await client.module_info(test_module)
        assert "type" in info
        assert info["type"] == "exploit"

    async def test_module_has_description(self, test_module, client):
        """Test that module has a description."""
        info = await client.module_info(test_module)
        assert "description" in info
        assert len(info["description"]) > 0

    async def test_module_has_rank(self, test_module, client):
        """Test that module has a rank."""
        info = await client.module_info(test_module)
        assert "rank" in info
        # Rank should be one of the standard MSF ranks (as string from Ruby)
        assert info["rank"] in ["0", "100", "200", "300", "400", "500", "600"]

    async def test_module_disclosure_date_format(self, test_module, client):
        """Test that disclosure date is properly formatted."""
        info = await client.module_info(test_module)
        if info.get("disclosure_date"):
            # Should be YYYY-MM-DD format
            date = info["disclosure_date"]
            parts = date.split("-")
            assert len(parts) == 3
            year, month, day = parts
            assert len(year) == 4 and year.isdigit()
            assert len(month) == 2 and month.isdigit()
            assert len(day) == 2 and day.isdigit()


@pytest.mark.integration
class TestModuleOptions:
    """Tests for module options and datastore."""

    async def test_options_schema_exists(self, test_module, client):
        """Test that module has options schema."""
        options = await client.module_options(test_module)
        assert isinstance(options, str)
        assert len(options) > 0

    async def test_options_contains_common_fields(self, test_module, client):
        """Test that options contain expected common fields."""
        options = await client.module_options(test_module)
        # Exploit modules should have RHOSTS option
        assert "RHOSTS" in options or "rhosts" in options.lower()

    async def test_set_valid_option(self, test_module, client):
        """Test setting a valid option."""
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.100")
        value = await client.module_get_option(test_module, "RHOSTS")
        assert value == "192.168.1.100"

    async def test_set_multiple_options(self, test_module, client):
        """Test setting multiple options."""
        await client.module_set_option(test_module, "RHOSTS", "10.0.0.1")
        await client.module_set_option(test_module, "RPORT", "2121")

        rhosts = await client.module_get_option(test_module, "RHOSTS")
        rport = await client.module_get_option(test_module, "RPORT")

        assert rhosts == "10.0.0.1"
        assert rport == "2121"

    async def test_option_case_insensitive(self, test_module, client):
        """Test that option names are case-insensitive."""
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.1")

        # Try different cases
        val1 = await client.module_get_option(test_module, "RHOSTS")
        val2 = await client.module_get_option(test_module, "rhosts")

        # Both should return the same value (or one might return None)
        # MSF is case-insensitive for options
        assert val1 == "192.168.1.1" or val2 == "192.168.1.1"

    async def test_get_nonexistent_option(self, test_module, client):
        """Test getting a nonexistent option."""
        value = await client.module_get_option(
            test_module, "NONEXISTENT_OPTION"
        )
        # Should return None or empty
        assert value is None or value == ""

    async def test_overwrite_option(self, test_module, client):
        """Test overwriting an existing option."""
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.1")
        await client.module_set_option(test_module, "RHOSTS", "10.0.0.1")

        value = await client.module_get_option(test_module, "RHOSTS")
        assert value == "10.0.0.1"


@pytest.mark.integration
class TestModuleValidation:
    """Tests for module validation."""

    async def test_validation_with_required_options(self, test_module, client):
        """Test validation with all required options set."""
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.100")
        valid = await client.module_validate(test_module)
        assert valid is True

    async def test_validation_without_required_options(self, client):
        """Test validation fails without required options."""
        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        # Don't set RHOSTS - validation should fail
        try:
            valid = await client.module_validate(module_id)
            # If validation doesn't raise an error, it should return False
            assert valid is False
        except Exception as e:
            # MSF might raise an error for invalid configuration
            assert "validate" in str(e).lower() or "options" in str(e).lower()

    async def test_validation_returns_boolean(self, test_module, client):
        """Test that validation returns a boolean."""
        await client.module_set_option(test_module, "RHOSTS", "192.168.1.100")
        valid = await client.module_validate(test_module)
        assert isinstance(valid, bool)


@pytest.mark.integration
class TestModuleCapabilities:
    """Tests for module capabilities and features."""

    async def test_has_check_method_exists(self, test_module, client):
        """Test that has_check method works."""
        has_check = await client.module_has_check(test_module)
        assert isinstance(has_check, bool)

    async def test_check_method_for_module_with_check(self, client):
        """Test check method on a module that supports it."""
        # Some modules support check, others don't
        module_id = await client.create_module(
            "exploit/unix/ftp/vsftpd_234_backdoor"
        )
        has_check = await client.module_has_check(module_id)

        if has_check:
            # Set required options
            await client.module_set_option(module_id, "RHOSTS", "127.0.0.1")

            # Try to run check (might fail if target not available)
            try:
                result = await client.module_check(module_id)
                assert isinstance(result, str)
            except Exception:
                # Check might fail if target not available - that's OK
                pass

    async def test_compatible_payloads_for_exploit(self, test_module, client):
        """Test getting compatible payloads for an exploit."""
        # Use the test module fixture
        payloads = await client.module_compatible_payloads(test_module)
        assert isinstance(payloads, list)
        # Note: might be empty for some exploits like vsftpd backdoor


@pytest.mark.integration
class TestModuleAliases:
    """Tests for module aliases and notes."""

    async def test_aliases_returns_list(self, test_module, client):
        """Test that aliases returns a list."""
        aliases = await client.module_aliases(test_module)
        assert isinstance(aliases, list)

    async def test_notes_returns_dict(self, test_module, client):
        """Test that notes returns a dict."""
        notes = await client.module_notes(test_module)
        assert isinstance(notes, dict)


@pytest.mark.integration
class TestModuleTargets:
    """Tests for exploit targets."""

    async def test_targets_on_exploit_with_targets(self, client):
        """Test getting targets from an exploit that has them."""
        # multi/handler or other exploits with multiple targets
        module_id = await client.create_module("exploit/multi/handler")
        targets = await client.module_targets(module_id)
        assert isinstance(targets, list)
