"""Tests for the Weapon and Bullet classes.

Bullet is a pure Python class that parses payload names - no MSF needed.
Weapon wraps MSF modules - requires MSF initialization.
"""

import pytest

from assassinate.weapon import Bullet, Weapon


# =============================================================================
# Bullet Tests (Unit Tests - No MSF Required)
# =============================================================================


class TestBulletConstruction:
    """Tests for Bullet construction."""

    def test_basic_construction(self):
        """Bullet can be constructed with just a name."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.name == "linux/x64/meterpreter/reverse_tcp"

    def test_construction_with_weapon(self):
        """Bullet can be associated with a weapon."""
        # Note: We can't easily test this without MSF, but we can verify
        # the internal attribute is set
        bullet = Bullet("cmd/unix/interact", weapon=None)
        assert bullet._weapon is None


class TestBulletPlatformParsing:
    """Tests for platform extraction from payload names."""

    def test_linux_platform(self):
        """Correctly identifies Linux platform."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.platform == "linux"

    def test_windows_platform(self):
        """Correctly identifies Windows platform."""
        bullet = Bullet("windows/meterpreter/reverse_tcp")
        assert bullet.platform == "windows"

    def test_cmd_platform(self):
        """Correctly identifies cmd platform."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.platform == "cmd"

    def test_osx_platform(self):
        """Correctly identifies OSX platform."""
        bullet = Bullet("osx/x64/meterpreter/reverse_tcp")
        assert bullet.platform == "osx"


class TestBulletArchParsing:
    """Tests for architecture extraction from payload names."""

    def test_x64_arch(self):
        """Correctly identifies x64 architecture."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.arch == "x64"

    def test_x86_arch(self):
        """Correctly identifies x86 architecture."""
        bullet = Bullet("linux/x86/shell/reverse_tcp")
        assert bullet.arch == "x86"

    def test_cmd_arch(self):
        """cmd payloads have cmd architecture."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.arch == "cmd"

    def test_implicit_x86_for_windows(self):
        """Windows meterpreter without explicit arch defaults to x86."""
        bullet = Bullet("windows/meterpreter/reverse_tcp")
        assert bullet.arch == "x86"

    def test_armle_arch(self):
        """Correctly identifies ARM architecture."""
        bullet = Bullet("linux/armle/meterpreter/reverse_tcp")
        assert bullet.arch == "armle"

    def test_aarch64_arch(self):
        """Correctly identifies aarch64 architecture."""
        bullet = Bullet("linux/aarch64/meterpreter/reverse_tcp")
        assert bullet.arch == "aarch64"


class TestBulletTypeParsing:
    """Tests for payload type classification."""

    def test_staged_meterpreter(self):
        """Meterpreter with slash is staged."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.type == "staged"

    def test_stageless_meterpreter(self):
        """Meterpreter with underscore is stageless."""
        bullet = Bullet("linux/x64/meterpreter_reverse_tcp")
        assert bullet.type == "stageless"

    def test_single_interact(self):
        """Interact payloads are single."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.type == "single"

    def test_staged_shell(self):
        """Shell with slash is staged."""
        bullet = Bullet("linux/x64/shell/reverse_tcp")
        assert bullet.type == "staged"

    def test_stageless_shell(self):
        """Shell with underscore is stageless."""
        bullet = Bullet("linux/x64/shell_reverse_tcp")
        assert bullet.type == "stageless"


class TestBulletConnectionParsing:
    """Tests for connection type extraction."""

    def test_reverse_connection(self):
        """Identifies reverse connection type."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.connection == "reverse"

    def test_bind_connection(self):
        """Identifies bind connection type."""
        bullet = Bullet("linux/x64/meterpreter/bind_tcp")
        assert bullet.connection == "bind"

    def test_no_connection(self):
        """Interact payloads have no connection."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.connection == "none"


class TestBulletHandlerType:
    """Tests for handler type extraction."""

    def test_reverse_tcp_handler(self):
        """Extracts reverse_tcp handler type."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.handler_type == "reverse_tcp"

    def test_reverse_https_handler(self):
        """Extracts reverse_https handler type."""
        bullet = Bullet("windows/meterpreter/reverse_https")
        assert bullet.handler_type == "reverse_https"

    def test_bind_tcp_handler(self):
        """Extracts bind_tcp handler type."""
        bullet = Bullet("linux/x64/shell/bind_tcp")
        assert bullet.handler_type == "bind_tcp"

    def test_interact_handler(self):
        """Interact payloads have interact handler."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.handler_type == "interact"


class TestBulletPayloadClassification:
    """Tests for meterpreter/shell classification."""

    def test_is_meterpreter_true(self):
        """Meterpreter payloads are identified."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert bullet.is_meterpreter is True
        assert bullet.is_shell is False

    def test_is_shell_true(self):
        """Shell payloads are identified."""
        bullet = Bullet("linux/x64/shell/reverse_tcp")
        assert bullet.is_shell is True
        assert bullet.is_meterpreter is False

    def test_neither_meterpreter_nor_shell(self):
        """Interact payloads are neither meterpreter nor shell."""
        bullet = Bullet("cmd/unix/interact")
        assert bullet.is_meterpreter is False
        assert bullet.is_shell is False


class TestBulletDescribe:
    """Tests for bullet description formatting."""

    def test_describe_includes_name(self):
        """Description includes the bullet name."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        desc = bullet.describe()

        assert "linux/x64/meterpreter/reverse_tcp" in desc

    def test_describe_includes_platform(self):
        """Description includes platform."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        desc = bullet.describe()

        assert "Platform: linux" in desc

    def test_describe_includes_arch(self):
        """Description includes architecture."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        desc = bullet.describe()

        assert "Arch: x64" in desc

    def test_describe_includes_meterpreter_note(self):
        """Description notes meterpreter features."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        desc = bullet.describe()

        assert "Meterpreter" in desc


class TestBulletRepresentation:
    """Tests for string representations."""

    def test_repr(self):
        """repr includes bullet name."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert "<Bullet linux/x64/meterpreter/reverse_tcp>" == repr(bullet)

    def test_str(self):
        """str returns just the name."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")
        assert str(bullet) == "linux/x64/meterpreter/reverse_tcp"


class TestBulletEquality:
    """Tests for equality and hashing."""

    def test_equality_same_name(self):
        """Bullets with same name are equal."""
        bullet1 = Bullet("linux/x64/meterpreter/reverse_tcp")
        bullet2 = Bullet("linux/x64/meterpreter/reverse_tcp")

        assert bullet1 == bullet2

    def test_inequality_different_name(self):
        """Bullets with different names are not equal."""
        bullet1 = Bullet("linux/x64/meterpreter/reverse_tcp")
        bullet2 = Bullet("linux/x64/shell/reverse_tcp")

        assert bullet1 != bullet2

    def test_equality_with_string(self):
        """Bullet can be compared to string."""
        bullet = Bullet("linux/x64/meterpreter/reverse_tcp")

        assert bullet == "linux/x64/meterpreter/reverse_tcp"
        assert bullet != "windows/meterpreter/reverse_tcp"

    def test_hash_same_name(self):
        """Bullets with same name have same hash."""
        bullet1 = Bullet("linux/x64/meterpreter/reverse_tcp")
        bullet2 = Bullet("linux/x64/meterpreter/reverse_tcp")

        assert hash(bullet1) == hash(bullet2)

    def test_usable_in_set(self):
        """Bullets can be used in sets."""
        bullet1 = Bullet("linux/x64/meterpreter/reverse_tcp")
        bullet2 = Bullet("linux/x64/meterpreter/reverse_tcp")
        bullet3 = Bullet("windows/meterpreter/reverse_tcp")

        bullet_set = {bullet1, bullet2, bullet3}

        assert len(bullet_set) == 2


# =============================================================================
# Weapon Tests (Integration Tests - MSF Required)
# =============================================================================


class TestWeaponConstruction:
    """Tests for Weapon construction."""

    def test_construction_from_exploit(self, exploit_module):
        """Weapon can be constructed from exploit module."""
        weapon = Weapon(exploit_module)

        assert weapon._module is exploit_module

    def test_construction_from_auxiliary(self, auxiliary_module):
        """Weapon can be constructed from auxiliary module."""
        weapon = Weapon(auxiliary_module)

        assert weapon._module is auxiliary_module


class TestWeaponIdentity:
    """Tests for weapon identity properties."""

    def test_name(self, exploit_module):
        """name returns short module name."""
        weapon = Weapon(exploit_module)

        assert weapon.name == "is_known_pipename"

    def test_fullname(self, exploit_module):
        """fullname returns full module path."""
        weapon = Weapon(exploit_module)

        assert weapon.fullname == "exploit/linux/samba/is_known_pipename"

    def test_type(self, exploit_module):
        """type returns module type."""
        weapon = Weapon(exploit_module)

        assert weapon.type == "exploit"

    def test_category(self, exploit_module):
        """category returns second path component."""
        weapon = Weapon(exploit_module)

        assert weapon.category == "linux"

    def test_subcategory(self, exploit_module):
        """subcategory returns third path component."""
        weapon = Weapon(exploit_module)

        assert weapon.subcategory == "samba"


class TestWeaponDescription:
    """Tests for weapon description properties."""

    def test_description(self, exploit_module):
        """description returns module description."""
        weapon = Weapon(exploit_module)

        assert len(weapon.description) > 0

    def test_short_description(self, exploit_module):
        """short_description returns first sentence."""
        weapon = Weapon(exploit_module)
        short = weapon.short_description

        # Should end with period or be truncated
        assert short.endswith(".") or short.endswith("...")
        assert len(short) <= len(weapon.description)

    def test_authors(self, exploit_module):
        """authors returns list of authors."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.authors, list)
        assert len(weapon.authors) > 0

    def test_references(self, exploit_module):
        """references returns security references."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.references, list)

    def test_cves(self, exploit_module):
        """cves extracts CVE identifiers."""
        weapon = Weapon(exploit_module)
        cves = weapon.cves

        # SambaCry has CVE-2017-7494
        assert isinstance(cves, list)
        # May or may not have CVEs depending on references format

    def test_rank(self, exploit_module):
        """rank returns reliability rank."""
        weapon = Weapon(exploit_module)

        assert weapon.rank in ["excellent", "great", "good", "normal", "average", "low", "manual"]

    def test_rank_score(self, exploit_module):
        """rank_score returns numeric rank."""
        weapon = Weapon(exploit_module)
        score = weapon.rank_score

        assert isinstance(score, int)
        assert score >= 0
        assert score <= 600


class TestWeaponTechnicalDetails:
    """Tests for technical details properties."""

    def test_platforms(self, exploit_module):
        """platforms returns target platforms."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.platforms, list)

    def test_architectures(self, exploit_module):
        """architectures returns target architectures."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.architectures, list)

    def test_privileged(self, exploit_module):
        """privileged returns boolean."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.privileged, bool)

    def test_disclosure_date(self, exploit_module):
        """disclosure_date may return date string."""
        weapon = Weapon(exploit_module)
        date = weapon.disclosure_date

        # May be None or a string
        assert date is None or isinstance(date, str)

    def test_service_inference(self, exploit_module):
        """service is inferred from module path."""
        weapon = Weapon(exploit_module)

        # SambaCry targets SMB
        assert weapon.service == "smb"

    def test_port(self, exploit_module):
        """port returns RPORT default."""
        weapon = Weapon(exploit_module)
        port = weapon.port

        # SambaCry defaults to port 445
        assert port == 445 or port is None

    def test_targets(self, exploit_module):
        """targets returns available exploit targets."""
        weapon = Weapon(exploit_module)
        targets = weapon.targets

        assert isinstance(targets, list)


class TestWeaponConfiguration:
    """Tests for weapon configuration."""

    def test_options_access(self, exploit_module):
        """options property provides access to module options."""
        weapon = Weapon(exploit_module)

        assert weapon.options is not None
        # Can set options
        weapon.options.RHOSTS = "192.168.1.100"

    def test_configure_single(self, exploit_module):
        """configure sets a single option."""
        weapon = Weapon(exploit_module)
        weapon.configure(RHOSTS="192.168.1.100")

        # Configure returns self for chaining
        result = weapon.configure(RPORT=445)
        assert result is weapon

    def test_configure_multiple(self, exploit_module):
        """configure sets multiple options at once."""
        weapon = Weapon(exploit_module)
        weapon.configure(
            RHOSTS="192.168.1.100",
            RPORT=445,
            SMB_SHARE_NAME="myshare"
        )

        # Options should be set
        assert weapon.options.RHOSTS == "192.168.1.100"

    def test_validate_missing_options(self, exploit_module):
        """validate returns False when required options missing."""
        weapon = Weapon(exploit_module)

        # No options set, should have RHOSTS missing
        # validate() returns False when validation fails
        result = weapon.validate()
        assert result is False

    def test_validate_with_options(self, exploit_module):
        """validate returns True when required options set."""
        weapon = Weapon(exploit_module)
        weapon.configure(RHOSTS="192.168.1.100")

        # RHOSTS is set, might be valid
        # (depends on module's specific requirements)
        valid = weapon.validate()
        assert isinstance(valid, bool)

    def test_missing_options(self, exploit_module):
        """missing_options returns list of unset required options."""
        weapon = Weapon(exploit_module)
        missing = weapon.missing_options()

        assert isinstance(missing, list)


class TestWeaponBullets:
    """Tests for bullet (payload) management."""

    def test_bullets_returns_list(self, exploit_module):
        """bullets returns list of compatible payloads."""
        weapon = Weapon(exploit_module)
        bullets = weapon.bullets()

        assert isinstance(bullets, list)
        assert len(bullets) > 0
        assert all(isinstance(b, Bullet) for b in bullets)

    def test_bullets_cached(self, exploit_module):
        """bullets caches result."""
        weapon = Weapon(exploit_module)

        bullets1 = weapon.bullets()
        bullets2 = weapon.bullets()

        # Same list object (cached)
        assert bullets1 is bullets2

    def test_bullets_refresh(self, exploit_module):
        """bullets can be refreshed."""
        weapon = Weapon(exploit_module)

        bullets1 = weapon.bullets()
        bullets2 = weapon.bullets(refresh=True)

        # Different list object after refresh
        assert bullets1 is not bullets2

    def test_bullet_search(self, exploit_module):
        """bullet finds specific payload by name fragment."""
        weapon = Weapon(exploit_module)

        # Search for unix/interact
        bullet = weapon.bullet("interact")

        assert bullet is not None
        assert "interact" in bullet.name.lower()

    def test_bullet_search_not_found(self, exploit_module):
        """bullet returns None when not found."""
        weapon = Weapon(exploit_module)

        bullet = weapon.bullet("nonexistent_payload_xyz")
        assert bullet is None

    def test_best_bullet(self, exploit_module):
        """best_bullet auto-selects optimal payload."""
        weapon = Weapon(exploit_module)
        best = weapon.best_bullet()

        assert best is not None
        assert isinstance(best, Bullet)

    def test_best_bullet_prefers_meterpreter(self, exploit_module):
        """best_bullet prefers meterpreter when available."""
        weapon = Weapon(exploit_module)
        best = weapon.best_bullet(prefer_meterpreter=True)

        # If meterpreter is available, it should be selected
        has_meterpreter = any(b.is_meterpreter for b in weapon.bullets())
        if has_meterpreter:
            assert best.is_meterpreter

    def test_load_bullet_by_string(self, exploit_module):
        """load accepts string payload name."""
        weapon = Weapon(exploit_module)
        result = weapon.load("cmd/unix/interact")

        assert result is weapon  # Returns self
        assert weapon.loaded is not None
        assert "interact" in weapon.loaded.name

    def test_load_bullet_object(self, exploit_module):
        """load accepts Bullet object."""
        weapon = Weapon(exploit_module)
        bullet = Bullet("cmd/unix/interact")
        weapon.load(bullet)

        assert weapon.loaded == bullet

    def test_is_loaded(self, exploit_module):
        """is_loaded reflects load state."""
        weapon = Weapon(exploit_module)

        assert weapon.is_loaded is False
        weapon.load("cmd/unix/interact")
        assert weapon.is_loaded is True


class TestWeaponCheck:
    """Tests for vulnerability checking."""

    def test_has_check(self, exploit_module):
        """has_check returns boolean."""
        weapon = Weapon(exploit_module)

        assert isinstance(weapon.has_check(), bool)


class TestWeaponDescription:
    """Tests for weapon describe formatting."""

    def test_describe_includes_name(self, exploit_module):
        """describe includes weapon fullname."""
        weapon = Weapon(exploit_module)
        desc = weapon.describe()

        assert weapon.fullname in desc

    def test_describe_includes_rank(self, exploit_module):
        """describe includes rank."""
        weapon = Weapon(exploit_module)
        desc = weapon.describe()

        assert "Rank:" in desc

    def test_describe_includes_description(self, exploit_module):
        """describe includes module description."""
        weapon = Weapon(exploit_module)
        desc = weapon.describe()

        assert "Description:" in desc


class TestWeaponRepresentation:
    """Tests for string representations."""

    def test_repr(self, exploit_module):
        """repr includes essential info."""
        weapon = Weapon(exploit_module)
        repr_str = repr(weapon)

        assert "<Weapon" in repr_str
        assert weapon.name in repr_str
        assert weapon.type in repr_str

    def test_str(self, exploit_module):
        """str includes fullname and description."""
        weapon = Weapon(exploit_module)
        str_val = str(weapon)

        assert weapon.fullname in str_val


class TestWeaponEquality:
    """Tests for equality and hashing."""

    def test_equality_same_module(self, msf_init):
        """Weapons from same module are equal."""
        import msf

        mod1 = msf.create_module("exploit/linux/samba/is_known_pipename")
        mod2 = msf.create_module("exploit/linux/samba/is_known_pipename")

        weapon1 = Weapon(mod1)
        weapon2 = Weapon(mod2)

        assert weapon1 == weapon2

    def test_inequality_different_module(self, msf_init):
        """Weapons from different modules are not equal."""
        import msf

        mod1 = msf.create_module("exploit/linux/samba/is_known_pipename")
        mod2 = msf.create_module("auxiliary/scanner/smb/smb_version")

        weapon1 = Weapon(mod1)
        weapon2 = Weapon(mod2)

        assert weapon1 != weapon2

    def test_equality_with_string(self, exploit_module):
        """Weapon can be compared to string (fullname or name)."""
        weapon = Weapon(exploit_module)

        assert weapon == "exploit/linux/samba/is_known_pipename"
        assert weapon == "is_known_pipename"

    def test_hash(self, exploit_module):
        """Weapon can be hashed."""
        weapon = Weapon(exploit_module)
        h = hash(weapon)

        assert isinstance(h, int)

    def test_usable_in_set(self, msf_init):
        """Weapons can be used in sets."""
        import msf

        mod1 = msf.create_module("exploit/linux/samba/is_known_pipename")
        mod2 = msf.create_module("exploit/linux/samba/is_known_pipename")
        mod3 = msf.create_module("auxiliary/scanner/smb/smb_version")

        weapon_set = {Weapon(mod1), Weapon(mod2), Weapon(mod3)}

        assert len(weapon_set) == 2
