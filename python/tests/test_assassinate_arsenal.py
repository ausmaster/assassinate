"""Tests for the Arsenal and Catalog classes.

Arsenal provides weapon search/discovery. Catalogs provide fast filtering
over indexed collections of weapons and bullets.

All tests require MSF initialization.
"""

import pytest

from assassinate.arsenal import Arsenal
from assassinate.catalog import WeaponCatalog, BulletCatalog, WeaponInfo, BulletInfo
from assassinate.weapon import Weapon, Bullet


# =============================================================================
# WeaponInfo Tests (Unit Tests)
# =============================================================================


class TestWeaponInfoConstruction:
    """Tests for WeaponInfo dataclass."""

    def test_basic_construction(self):
        """WeaponInfo can be constructed with required fields."""
        info = WeaponInfo(
            fullname="exploit/linux/samba/is_known_pipename",
            name="is_known_pipename",
            type="exploit",
            rank="excellent",
            rank_score=600,
        )

        assert info.fullname == "exploit/linux/samba/is_known_pipename"
        assert info.name == "is_known_pipename"
        assert info.type == "exploit"
        assert info.rank == "excellent"
        assert info.rank_score == 600

    def test_optional_fields(self):
        """WeaponInfo has optional fields with defaults."""
        info = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="normal",
            rank_score=300,
        )

        assert info.platforms == []
        assert info.service is None
        assert info.port is None
        assert info.cves == []
        assert info.description == ""
        assert info.authors == []


class TestWeaponInfoMatching:
    """Tests for WeaponInfo.matches() method."""

    def test_matches_type(self):
        """matches filters by type."""
        info = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="normal",
            rank_score=300,
        )

        assert info.matches(type="exploit") is True
        assert info.matches(type="auxiliary") is False

    def test_matches_service(self):
        """matches filters by service."""
        info = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="normal",
            rank_score=300,
            service="smb",
        )

        assert info.matches(service="smb") is True
        assert info.matches(service="ftp") is False

    def test_matches_platform(self):
        """matches filters by platform (any match)."""
        info = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="normal",
            rank_score=300,
            platforms=["linux", "unix"],
        )

        assert info.matches(platform="linux") is True
        assert info.matches(platform="unix") is True
        assert info.matches(platform="windows") is False

    def test_matches_min_rank(self):
        """matches filters by minimum rank."""
        info_excellent = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="excellent",
            rank_score=600,
        )
        info_normal = WeaponInfo(
            fullname="exploit/test2",
            name="test2",
            type="exploit",
            rank="normal",
            rank_score=300,
        )

        assert info_excellent.matches(min_rank="excellent") is True
        assert info_excellent.matches(min_rank="good") is True
        assert info_normal.matches(min_rank="excellent") is False
        assert info_normal.matches(min_rank="normal") is True

    def test_matches_query(self):
        """matches filters by fuzzy query."""
        info = WeaponInfo(
            fullname="exploit/linux/samba/is_known_pipename",
            name="is_known_pipename",
            type="exploit",
            rank="excellent",
            rank_score=600,
            description="Samba vulnerability",
            cves=["CVE-2017-7494"],
        )

        assert info.matches(query="samba") is True
        assert info.matches(query="pipename") is True
        assert info.matches(query="CVE-2017") is True
        assert info.matches(query="nonexistent") is False

    def test_matches_multiple_criteria(self):
        """matches requires all criteria to match."""
        info = WeaponInfo(
            fullname="exploit/linux/samba/test",
            name="test",
            type="exploit",
            rank="excellent",
            rank_score=600,
            service="smb",
            platforms=["linux"],
        )

        assert info.matches(type="exploit", service="smb") is True
        assert info.matches(type="exploit", service="ftp") is False
        assert info.matches(type="auxiliary", service="smb") is False

    def test_str(self):
        """str returns fullname and rank."""
        info = WeaponInfo(
            fullname="exploit/test",
            name="test",
            type="exploit",
            rank="excellent",
            rank_score=600,
        )

        assert "exploit/test" in str(info)
        assert "excellent" in str(info)


# =============================================================================
# BulletInfo Tests (Unit Tests)
# =============================================================================


class TestBulletInfoConstruction:
    """Tests for BulletInfo dataclass."""

    def test_basic_construction(self):
        """BulletInfo can be constructed with required fields."""
        info = BulletInfo(
            name="linux/x64/meterpreter/reverse_tcp",
            platform="linux",
            arch="x64",
            type="staged",
            connection="reverse",
            is_meterpreter=True,
            is_shell=False,
            handler="reverse_tcp",
        )

        assert info.name == "linux/x64/meterpreter/reverse_tcp"
        assert info.platform == "linux"
        assert info.arch == "x64"
        assert info.is_meterpreter is True


class TestBulletInfoMatching:
    """Tests for BulletInfo.matches() method."""

    def test_matches_platform(self):
        """matches filters by platform."""
        info = BulletInfo(
            name="linux/x64/meterpreter/reverse_tcp",
            platform="linux",
            arch="x64",
            type="staged",
            connection="reverse",
            is_meterpreter=True,
            is_shell=False,
            handler="reverse_tcp",
        )

        assert info.matches(platform="linux") is True
        assert info.matches(platform="windows") is False

    def test_matches_is_meterpreter(self):
        """matches filters by is_meterpreter."""
        info = BulletInfo(
            name="linux/x64/meterpreter/reverse_tcp",
            platform="linux",
            arch="x64",
            type="staged",
            connection="reverse",
            is_meterpreter=True,
            is_shell=False,
            handler="reverse_tcp",
        )

        assert info.matches(is_meterpreter=True) is True
        assert info.matches(is_meterpreter=False) is False

    def test_matches_query(self):
        """matches filters by fuzzy query."""
        info = BulletInfo(
            name="linux/x64/meterpreter/reverse_tcp",
            platform="linux",
            arch="x64",
            type="staged",
            connection="reverse",
            is_meterpreter=True,
            is_shell=False,
            handler="reverse_tcp",
        )

        assert info.matches(query="meterpreter") is True
        assert info.matches(query="linux") is True
        assert info.matches(query="windows") is False

    def test_bullet_method(self):
        """bullet() returns Bullet object."""
        info = BulletInfo(
            name="linux/x64/meterpreter/reverse_tcp",
            platform="linux",
            arch="x64",
            type="staged",
            connection="reverse",
            is_meterpreter=True,
            is_shell=False,
            handler="reverse_tcp",
        )

        bullet = info.bullet()

        assert isinstance(bullet, Bullet)
        assert bullet.name == "linux/x64/meterpreter/reverse_tcp"


# =============================================================================
# BulletCatalog Tests (Unit Tests for basic functionality)
# =============================================================================


class TestBulletCatalogUnit:
    """Unit tests for BulletCatalog (no MSF needed for basic ops)."""

    def test_construction(self):
        """BulletCatalog can be constructed."""
        catalog = BulletCatalog()

        assert catalog._loaded is False
        assert catalog._entries == []

    def test_repr_not_loaded(self):
        """repr shows not loaded state."""
        catalog = BulletCatalog()

        assert "not loaded" in repr(catalog)


# =============================================================================
# WeaponCatalog Tests (Integration - MSF Required)
# =============================================================================


class TestWeaponCatalogIntegration:
    """Integration tests for WeaponCatalog."""

    @pytest.fixture
    def arsenal(self, msf_init):
        """Create Arsenal for testing."""
        # Create a mock hideout-like object
        class MockHideout:
            pass

        hideout = MockHideout()
        return Arsenal(hideout)

    def test_weapons_catalog_lazy_load(self, arsenal):
        """Weapon catalog lazy loads on first access."""
        catalog = arsenal.weapons

        assert isinstance(catalog, WeaponCatalog)
        # Not loaded yet
        assert catalog._loaded is False

    def test_weapons_catalog_loads_on_access(self, arsenal):
        """Catalog loads when entries are accessed."""
        catalog = arsenal.weapons

        # Trigger load
        _ = len(catalog)

        assert catalog._loaded is True
        assert len(catalog._entries) > 0

    def test_filter_by_type(self, arsenal):
        """Can filter weapons by type."""
        exploits = arsenal.weapons.filter(type="exploit")

        # All results should be exploits
        for info in exploits:
            assert info.type == "exploit"

    def test_filter_by_service(self, arsenal):
        """Can filter weapons by service."""
        smb_weapons = arsenal.weapons.filter(service="smb")

        for info in smb_weapons:
            assert info.service == "smb"

    def test_filter_chaining(self, arsenal):
        """Filters can be chained."""
        result = arsenal.weapons.filter(type="exploit").filter(service="smb")

        for info in result:
            assert info.type == "exploit"
            assert info.service == "smb"

    def test_exploits_convenience(self, arsenal):
        """exploits() is shorthand for filter(type='exploit')."""
        exploits = arsenal.weapons.exploits()

        for info in exploits:
            assert info.type == "exploit"

    def test_by_service_convenience(self, arsenal):
        """by_service() is shorthand for filter(service=...)."""
        smb = arsenal.weapons.by_service("smb")

        for info in smb:
            assert info.service == "smb"

    def test_sorted_by_rank(self, arsenal):
        """sorted_by_rank orders by rank score."""
        sorted_cat = arsenal.weapons.filter(type="exploit").sorted_by_rank()
        entries = list(sorted_cat)

        if len(entries) >= 2:
            # First should have higher or equal rank than last
            assert entries[0].rank_score >= entries[-1].rank_score

    def test_limit(self, arsenal):
        """limit() restricts number of results."""
        limited = arsenal.weapons.limit(5)

        assert len(limited) <= 5

    def test_first(self, arsenal):
        """first() returns first entry or None."""
        first = arsenal.weapons.filter(type="exploit").first()

        if first is not None:
            assert isinstance(first, WeaponInfo)

    def test_iteration(self, arsenal):
        """Catalog is iterable."""
        catalog = arsenal.weapons.filter(type="exploit").limit(3)

        count = 0
        for info in catalog:
            assert isinstance(info, WeaponInfo)
            count += 1

        assert count <= 3

    def test_indexing(self, arsenal):
        """Catalog supports indexing."""
        catalog = arsenal.weapons.filter(type="exploit").limit(5)
        catalog._ensure_loaded()

        if len(catalog) > 0:
            first = catalog[0]
            assert isinstance(first, WeaponInfo)

    def test_slicing(self, arsenal):
        """Catalog supports slicing."""
        catalog = arsenal.weapons.filter(type="exploit").limit(10)
        catalog._ensure_loaded()

        if len(catalog) >= 3:
            slice_result = catalog[0:3]
            assert isinstance(slice_result, list)
            assert len(slice_result) == 3

    def test_bool(self, arsenal):
        """Catalog is truthy if has entries."""
        exploits = arsenal.weapons.filter(type="exploit")
        empty = arsenal.weapons.filter(type="nonexistent_type_xyz")

        assert bool(exploits) is True
        assert bool(empty) is False

    def test_weapon_info_to_weapon(self, arsenal):
        """WeaponInfo.weapon() returns full Weapon object."""
        # Use a specific filter to avoid loading too many modules
        info = arsenal.weapons.search("is_known_pipename").first()

        if info is not None:
            weapon = info.weapon()
            assert isinstance(weapon, Weapon)
            # Check weapon name is contained in the fullname (info might have partial name)
            assert "is_known_pipename" in weapon.fullname


# =============================================================================
# BulletCatalog Tests (Integration - MSF Required)
# =============================================================================


class TestBulletCatalogIntegration:
    """Integration tests for BulletCatalog."""

    @pytest.fixture
    def bullet_catalog(self, msf_init):
        """Create BulletCatalog for testing."""
        return BulletCatalog()

    def test_loads_on_access(self, bullet_catalog):
        """Catalog loads when entries accessed."""
        _ = len(bullet_catalog)

        assert bullet_catalog._loaded is True
        assert len(bullet_catalog._entries) > 0

    def test_filter_by_platform(self, bullet_catalog):
        """Can filter bullets by platform."""
        linux = bullet_catalog.filter(platform="linux")

        for info in linux:
            assert info.platform == "linux"

    def test_filter_is_meterpreter(self, bullet_catalog):
        """Can filter meterpreter bullets."""
        meterpreter = bullet_catalog.filter(is_meterpreter=True)

        for info in meterpreter:
            assert info.is_meterpreter is True

    def test_meterpreter_convenience(self, bullet_catalog):
        """meterpreter() is shorthand for filter(is_meterpreter=True)."""
        meterpreter = bullet_catalog.meterpreter()

        for info in meterpreter:
            assert info.is_meterpreter is True

    def test_shells_convenience(self, bullet_catalog):
        """shells() returns shell payloads."""
        shells = bullet_catalog.shells()

        for info in shells:
            assert info.is_shell is True

    def test_reverse_convenience(self, bullet_catalog):
        """reverse() returns reverse connection payloads."""
        reverse = bullet_catalog.reverse()

        for info in reverse:
            assert info.connection == "reverse"

    def test_bind_convenience(self, bullet_catalog):
        """bind() returns bind payloads."""
        bind = bullet_catalog.bind()

        for info in bind:
            assert info.connection == "bind"

    def test_for_platform_convenience(self, bullet_catalog):
        """for_platform() filters by platform."""
        linux = bullet_catalog.for_platform("linux")

        for info in linux:
            assert info.platform == "linux"

    def test_for_arch_convenience(self, bullet_catalog):
        """for_arch() filters by architecture."""
        x64 = bullet_catalog.for_arch("x64")

        for info in x64:
            assert info.arch == "x64"

    def test_staged_convenience(self, bullet_catalog):
        """staged() returns staged payloads."""
        staged = bullet_catalog.staged()

        for info in staged:
            assert info.type == "staged"

    def test_stageless_convenience(self, bullet_catalog):
        """stageless() returns stageless payloads."""
        stageless = bullet_catalog.stageless()

        for info in stageless:
            assert info.type == "stageless"

    def test_filter_chaining(self, bullet_catalog):
        """Filters can be chained."""
        result = bullet_catalog.meterpreter().reverse().for_platform("linux")

        for info in result:
            assert info.is_meterpreter is True
            assert info.connection == "reverse"
            assert info.platform == "linux"

    def test_limit(self, bullet_catalog):
        """limit() restricts results."""
        limited = bullet_catalog.limit(5)

        assert len(limited) <= 5

    def test_first(self, bullet_catalog):
        """first() returns first entry."""
        first = bullet_catalog.first()

        assert first is None or isinstance(first, BulletInfo)


# =============================================================================
# Arsenal Tests (Integration - MSF Required)
# =============================================================================


class TestArsenalIntegration:
    """Integration tests for Arsenal."""

    @pytest.fixture
    def arsenal(self, msf_init):
        """Create Arsenal for testing."""
        class MockHideout:
            pass

        hideout = MockHideout()
        return Arsenal(hideout)

    def test_weapons_property(self, arsenal):
        """weapons property returns WeaponCatalog."""
        assert isinstance(arsenal.weapons, WeaponCatalog)

    def test_bullets_property(self, arsenal):
        """bullets property returns BulletCatalog."""
        assert isinstance(arsenal.bullets, BulletCatalog)

    def test_find_specific_query(self, arsenal):
        """find() searches by specific query to limit results."""
        # Use a very specific query to limit module loading
        weapons = arsenal.find("is_known_pipename", type="exploit", limit=3)

        assert isinstance(weapons, list)
        for w in weapons:
            assert isinstance(w, Weapon)

    def test_get_specific_weapon(self, arsenal):
        """get() retrieves specific weapon by name."""
        weapon = arsenal.get("exploit/linux/samba/is_known_pipename")

        assert isinstance(weapon, Weapon)
        assert weapon.fullname == "exploit/linux/samba/is_known_pipename"

    def test_get_not_found(self, arsenal):
        """get() raises ValueError for unknown module."""
        with pytest.raises(ValueError):
            arsenal.get("nonexistent/module/xyz")

    def test_count(self, arsenal):
        """count() returns number of weapons."""
        total = arsenal.count()
        exploits = arsenal.count("exploit")

        assert total > 0
        assert exploits > 0
        assert exploits <= total

    def test_stats(self, arsenal):
        """stats() returns counts by type."""
        stats = arsenal.stats()

        assert isinstance(stats, dict)
        assert "exploit" in stats
        assert stats["exploit"] > 0

    def test_repr(self, arsenal):
        """repr shows summary."""
        repr_str = repr(arsenal)

        assert "<Arsenal:" in repr_str
        assert "exploits" in repr_str
