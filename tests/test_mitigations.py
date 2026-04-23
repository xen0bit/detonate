"""Tests for MITRE ATT&CK mitigation mappings."""

import pytest
from src.detonate.mapping.mitigations import (
    get_mitigations_for_technique,
    get_all_mitigations,
    get_mitigation_by_id,
    get_mitigation_coverage_stats,
)


class TestMitigationLookup:
    """Test mitigation lookup functionality."""

    def test_mitigation_lookup_t1055_001(self):
        """Test mitigation lookup for T1055.001 (Process Injection)."""
        mitigations = get_mitigations_for_technique("T1055.001")
        assert len(mitigations) > 0
        assert all("mitigation_id" in m for m in mitigations)
        assert all("name" in m for m in mitigations)
        assert all("description" in m for m in mitigations)
        assert all("url" in m for m in mitigations)

    def test_mitigation_lookup_t1059_001(self):
        """Test mitigation lookup for T1059.001 (PowerShell)."""
        mitigations = get_mitigations_for_technique("T1059.001")
        assert len(mitigations) > 0
        mitigation_ids = [m["mitigation_id"] for m in mitigations]
        # Should include M1049 (Antivirus) and M1054 (Script Blocking)
        assert "M1049" in mitigation_ids or "M1054" in mitigation_ids

    def test_mitigation_lookup_t1003_001(self):
        """Test mitigation lookup for T1003.001 (LSASS)."""
        mitigations = get_mitigations_for_technique("T1003.001")
        assert len(mitigations) > 0
        # Should include M1040 (Behavior Prevention)
        mitigation_ids = [m["mitigation_id"] for m in mitigations]
        assert "M1040" in mitigation_ids

    def test_mitigation_lookup_empty(self):
        """Test mitigation lookup for unknown technique returns empty list."""
        mitigations = get_mitigations_for_technique("T9999.999")
        assert mitigations == []

    def test_mitigation_lookup_parent_fallback(self):
        """Test that sub-technique falls back to parent if not found."""
        # T1055.999 doesn't exist, but T1055 should have mitigations
        mitigations = get_mitigations_for_technique("T1055.999")
        # Should fall back to parent T1055 mitigations
        assert len(mitigations) > 0


class TestGetAllMitigations:
    """Test get_all_mitigations functionality."""

    def test_get_all_mitigations_returns_list(self):
        """Test that get_all_mitigations returns a list."""
        all_mitigations = get_all_mitigations()
        assert isinstance(all_mitigations, list)
        assert len(all_mitigations) > 0

    def test_all_mitigations_have_required_fields(self):
        """Test that all mitigations have required fields."""
        all_mitigations = get_all_mitigations()
        for mitigation in all_mitigations:
            assert "mitigation_id" in mitigation
            assert "name" in mitigation
            assert "description" in mitigation
            assert "stix_id" in mitigation
            assert "url" in mitigation

    def test_all_mitigations_unique(self):
        """Test that all mitigations are unique by ID."""
        all_mitigations = get_all_mitigations()
        mitigation_ids = [m["mitigation_id"] for m in all_mitigations]
        assert len(mitigation_ids) == len(set(mitigation_ids))

    def test_all_mitigations_count(self):
        """Test that we have all 268 course-of-action objects."""
        all_mitigations = get_all_mitigations()
        assert len(all_mitigations) == 268, f"Expected 268 mitigations, got {len(all_mitigations)}"


class TestGetMitigationById:
    """Test get_mitigation_by_id functionality."""

    def test_get_known_mitigation(self):
        """Test getting a known mitigation by ID."""
        mitigation = get_mitigation_by_id("M1049")
        assert mitigation is not None
        assert mitigation["mitigation_id"] == "M1049"
        assert mitigation["name"] == "Antivirus/Antimalware"

    def test_get_unknown_mitigation(self):
        """Test getting an unknown mitigation returns None."""
        mitigation = get_mitigation_by_id("M9999")
        assert mitigation is None


class TestMitigationCoverage:
    """Test mitigation coverage for detected techniques."""

    def test_all_detected_techniques_have_mitigations(self):
        """Test that all techniques from Windows and Linux mappings have valid mitigations."""
        from src.detonate.mapping.windows_map import API_TO_TECHNIQUE
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE

        # Collect all technique IDs
        all_techniques = set()
        for api, data in API_TO_TECHNIQUE.items():
            all_techniques.add(data['technique_id'])
            if 'param_checks' in data:
                for param_check in data['param_checks'].values():
                    for technique in param_check.values():
                        if 'id' in technique:
                            all_techniques.add(technique['id'])

        for syscall, data in SYSCALL_TO_TECHNIQUE.items():
            all_techniques.add(data['technique_id'])
            if 'param_checks' in data:
                for param_check in data['param_checks'].values():
                    for technique in param_check.values():
                        if 'id' in technique:
                            all_techniques.add(technique['id'])

        missing = []
        for tech_id in all_techniques:
            mitigations = get_mitigations_for_technique(tech_id)
            if not mitigations:
                missing.append(tech_id)

        # All techniques should have mitigations (with fallbacks)
        assert len(missing) == 0, f"Techniques without mitigations: {missing}"

    def test_common_techniques_covered(self):
        """Test that common techniques have mitigation coverage."""
        common_techniques = [
            "T1055.001",  # DLL Injection
            "T1059.001",  # PowerShell
            "T1059.003",  # CMD
            "T1003.001",  # LSASS
            "T1547.001",  # Registry Run Keys
            "T1071.001",  # Web Protocols
            "T1486",  # Data Encrypted for Impact
        ]

        for tech_id in common_techniques:
            mitigations = get_mitigations_for_technique(tech_id)
            assert len(mitigations) > 0, f"Technique {tech_id} has no mitigations"


class TestMitigationStructure:
    """Test mitigation data structure integrity."""

    def test_mitigation_urls_valid_format(self):
        """Test that all mitigation URLs have valid format."""
        all_mitigations = get_all_mitigations()
        for mitigation in all_mitigations:
            url = mitigation["url"]
            assert url.startswith("https://attack.mitre.org/mitigations/")

    def test_mitigation_ids_valid_format(self):
        """Test that all mitigation IDs have valid format."""
        all_mitigations = get_all_mitigations()
        for mitigation in all_mitigations:
            mid = mitigation["mitigation_id"]
            # ATT&CK v18.1 uses M-style IDs (M1040), but older versions used T-style
            # Accept both formats for backward compatibility
            assert mid.startswith("M") or mid.startswith("T"), f"Invalid mitigation ID format: {mid}"

    def test_stix_ids_valid_format(self):
        """Test that all STIX IDs have valid format."""
        all_mitigations = get_all_mitigations()
        for mitigation in all_mitigations:
            stix_id = mitigation["stix_id"]
            assert stix_id.startswith("course-of-action--")


class TestMitigationCoverageStats:
    """Test mitigation coverage statistics."""

    def test_coverage_stats_returns_dict(self):
        """Test that coverage stats returns a dictionary."""
        stats = get_mitigation_coverage_stats()
        assert isinstance(stats, dict)

    def test_coverage_stats_has_required_fields(self):
        """Test that coverage stats has required fields."""
        stats = get_mitigation_coverage_stats()
        assert "total_mitigations" in stats
        assert "techniques_with_mitigations" in stats
        assert "total_techniques" in stats
        assert "mitigates_relationships" in stats

    def test_coverage_stats_values(self):
        """Test that coverage stats has expected values."""
        stats = get_mitigation_coverage_stats()
        assert stats["total_mitigations"] == 268
        assert stats["total_techniques"] > 0
        assert stats["mitigates_relationships"] > 0
