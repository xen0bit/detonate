"""Tests for MITRE ATT&CK data source mappings."""

import pytest
from src.detonate.mapping.data_sources import (
    get_data_sources_for_technique,
    get_all_data_sources,
    get_all_data_components,
    get_data_source,
    get_data_component,
)


class TestDataSourceLookup:
    """Test data source lookup functionality."""

    def test_data_source_lookup_t1055_001(self):
        """Test data source lookup for T1055.001 (DLL Injection)."""
        sources = get_data_sources_for_technique("T1055.001")
        assert len(sources) > 0
        assert all("source_id" in s for s in sources)
        assert all("component_id" in s for s in sources)
        assert all("source_name" in s for s in sources)
        assert all("component_name" in s for s in sources)

    def test_data_source_lookup_t1059_001(self):
        """Test data source lookup for T1059.001 (PowerShell)."""
        sources = get_data_sources_for_technique("T1059.001")
        assert len(sources) > 0
        # Should include script logs or command logs
        component_names = [s["component_name"] for s in sources]
        assert any("Script" in c or "Command" in c for c in component_names)

    def test_data_source_lookup_t1003_001(self):
        """Test data source lookup for T1003.001 (LSASS)."""
        sources = get_data_sources_for_technique("T1003.001")
        assert len(sources) > 0
        # Should include process monitoring
        component_names = [s["component_name"] for s in sources]
        assert any("Process" in c or "Memory" in c for c in component_names)

    def test_data_source_lookup_empty(self):
        """Test data source lookup for unknown technique returns empty or fallback."""
        sources = get_data_sources_for_technique("T9999.999")
        # Should return fallback for unknown category
        assert isinstance(sources, list)

    def test_data_source_lookup_parent_fallback(self):
        """Test that sub-technique falls back to parent if not found."""
        # T1055.999 doesn't exist, but T1055 category should have fallback
        sources = get_data_sources_for_technique("T1055.999")
        assert len(sources) > 0


class TestGetAllDataSources:
    """Test get_all_data_sources functionality."""

    def test_get_all_data_sources_returns_list(self):
        """Test that get_all_data_sources returns a list."""
        all_sources = get_all_data_sources()
        assert isinstance(all_sources, list)
        assert len(all_sources) > 0

    def test_all_data_sources_have_required_fields(self):
        """Test that all data sources have required fields."""
        all_sources = get_all_data_sources()
        for source in all_sources:
            assert "source_id" in source
            assert "name" in source
            assert "stix_id" in source

    def test_all_data_sources_count(self):
        """Test that we have all 38 data sources."""
        all_sources = get_all_data_sources()
        assert len(all_sources) == 38, f"Expected 38 data sources, got {len(all_sources)}"


class TestGetAllDataComponents:
    """Test get_all_data_components functionality."""

    def test_get_all_data_components_returns_list(self):
        """Test that get_all_data_components returns a list."""
        all_components = get_all_data_components()
        assert isinstance(all_components, list)
        assert len(all_components) > 0

    def test_all_data_components_have_required_fields(self):
        """Test that all data components have required fields."""
        all_components = get_all_data_components()
        for component in all_components:
            assert "component_id" in component
            assert "name" in component
            assert "stix_id" in component

    def test_all_data_components_count(self):
        """Test that we have all 109 data components."""
        all_components = get_all_data_components()
        assert len(all_components) == 109, f"Expected 109 data components, got {len(all_components)}"


class TestGetDataSource:
    """Test get_data_source functionality."""

    def test_get_known_data_source(self):
        """Test getting a known data source by ID."""
        source = get_data_source("DS0009")
        assert source is not None
        assert source["source_id"] == "DS0009"
        assert source["name"] == "Process"

    def test_get_unknown_data_source(self):
        """Test getting an unknown data source returns None."""
        source = get_data_source("DS9999")
        assert source is None


class TestGetDataComponent:
    """Test get_data_component functionality."""

    def test_get_known_data_component(self):
        """Test getting a known data component by ID."""
        component = get_data_component("DC0016")
        assert component is not None
        assert component["component_id"] == "DC0016"
        assert "Module" in component["name"]

    def test_get_unknown_data_component(self):
        """Test getting an unknown data component returns None."""
        component = get_data_component("DC9999")
        assert component is None


class TestDataSourceCoverage:
    """Test data source coverage for detected techniques."""

    def test_common_techniques_covered(self):
        """Test that common techniques have data source coverage."""
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
            sources = get_data_sources_for_technique(tech_id)
            assert len(sources) > 0, f"Technique {tech_id} has no data sources"

    def test_discovery_techniques_have_fallback(self):
        """Test that discovery techniques have fallback data sources."""
        discovery_techniques = [
            "T1082",  # System Information Discovery
            "T1016",  # System Network Configuration Discovery
            "T1083",  # File and Directory Discovery
        ]

        for tech_id in discovery_techniques:
            sources = get_data_sources_for_technique(tech_id)
            assert len(sources) > 0, f"Discovery technique {tech_id} has no data sources"


class TestDataSourceStructure:
    """Test data source data structure integrity."""

    def test_data_source_ids_valid_format(self):
        """Test that all data source IDs have valid format."""
        all_sources = get_all_data_sources()
        for source in all_sources:
            source_id = source["source_id"]
            assert source_id.startswith("DS")
            assert source_id[2:].isdigit()

    def test_data_component_ids_valid_format(self):
        """Test that all data component IDs have valid format."""
        all_components = get_all_data_components()
        for component in all_components:
            component_id = component["component_id"]
            assert component_id.startswith("DC")
            assert component_id[2:].isdigit()

    def test_stix_ids_valid_format(self):
        """Test that all STIX IDs have valid format."""
        all_sources = get_all_data_sources()
        for source in all_sources:
            stix_id = source["stix_id"]
            assert stix_id.startswith("x-mitre-data-source--")

        all_components = get_all_data_components()
        for component in all_components:
            stix_id = component["stix_id"]
            assert stix_id.startswith("x-mitre-data-component--")
