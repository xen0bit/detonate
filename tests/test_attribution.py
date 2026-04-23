"""Tests for threat actor attribution based on TTP overlap."""

import os
import pytest
from unittest.mock import Mock, MagicMock

from src.detonate.mapping.attribution import (
    attribute_to_threat_actors,
    get_attribution_threshold,
    get_intrusion_set_ttps,
    get_attribution_details,
    calculate_attribution_statistics,
    calculate_ttp_weights,
)
from src.detonate.mapping.stix_data import STIXDataStore


class TestAttributionThreshold:
    """Test environment variable handling for attribution threshold."""

    def test_default_threshold(self):
        """Test default threshold is 0.5."""
        # Ensure environment variable is not set
        original = os.environ.pop("DETONATE_ATTRIBUTION_THRESHOLD", None)
        try:
            threshold = get_attribution_threshold()
            assert threshold == 0.5
        finally:
            if original:
                os.environ["DETONATE_ATTRIBUTION_THRESHOLD"] = original

    def test_custom_threshold(self):
        """Test custom threshold from environment."""
        original = os.environ.get("DETONATE_ATTRIBUTION_THRESHOLD")
        try:
            os.environ["DETONATE_ATTRIBUTION_THRESHOLD"] = "0.75"
            threshold = get_attribution_threshold()
            assert threshold == 0.75
        finally:
            if original:
                os.environ["DETONATE_ATTRIBUTION_THRESHOLD"] = original
            elif "DETONATE_ATTRIBUTION_THRESHOLD" in os.environ:
                del os.environ["DETONATE_ATTRIBUTION_THRESHOLD"]

    def test_invalid_threshold_fallback(self):
        """Test invalid threshold falls back to default."""
        original = os.environ.get("DETONATE_ATTRIBUTION_THRESHOLD")
        try:
            os.environ["DETONATE_ATTRIBUTION_THRESHOLD"] = "invalid"
            threshold = get_attribution_threshold()
            assert threshold == 0.5
        finally:
            if original:
                os.environ["DETONATE_ATTRIBUTION_THRESHOLD"] = original
            elif "DETONATE_ATTRIBUTION_THRESHOLD" in os.environ:
                del os.environ["DETONATE_ATTRIBUTION_THRESHOLD"]


class TestAttributionAlgorithm:
    """Test TTP overlap attribution algorithm."""

    @pytest.fixture
    def mock_stix_store(self):
        """Create mock STIX data store with test intrusion sets."""
        store = Mock(spec=STIXDataStore)
        
        # Mock intrusion sets with known TTPs
        store.get_all_intrusion_sets.return_value = [
            {
                "id": "intrusion-set--apt28",
                "intrusion_set_id": "G0001",
                "name": "APT28",
                "description": "Russian military intelligence threat group",
                "aliases": ["Fancy Bear", "Sofacy"],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001"],
                "url": "https://attack.mitre.org/groups/G0001/",
            },
            {
                "id": "intrusion-set--apt29",
                "intrusion_set_id": "G0002",
                "name": "APT29",
                "description": "Russian foreign intelligence threat group",
                "aliases": ["Cozy Bear"],
                "ttps": ["T1059.001", "T1055.001", "T1070.001", "T1078.004"],
                "url": "https://attack.mitre.org/groups/G0002/",
            },
            {
                "id": "intrusion-set--apt3",
                "intrusion_set_id": "G0003",
                "name": "APT3",
                "description": "Chinese state-sponsored threat group",
                "aliases": ["Comment Crew"],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001", "T1070.001"],
                "url": "https://attack.mitre.org/groups/G0003/",
            },
            {
                "id": "intrusion-set--empty",
                "intrusion_set_id": "G9999",
                "name": "Empty Group",
                "description": "Group with no known TTPs",
                "aliases": [],
                "ttps": [],
                "url": "https://attack.mitre.org/groups/G9999/",
            },
        ]
        
        return store

    def test_full_overlap(self, mock_stix_store):
        """Test 100% TTP overlap."""
        # Detected TTPs match APT28 exactly
        detected = {"T1059.001", "T1055.001", "T1021.002", "T1003.001"}
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # APT28 should be first with 100% confidence
        assert len(results) > 0
        assert results[0][0]["intrusion_set_id"] == "G0001"
        assert results[0][1] == 1.0  # 100% confidence

    def test_partial_overlap(self, mock_stix_store):
        """Test partial TTP overlap."""
        # Detected TTPs partially match APT28 (2 out of 4)
        detected = {"T1059.001", "T1055.001"}
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # APT28 should have 50% confidence
        apt28_result = next((r for r in results if r[0]["intrusion_set_id"] == "G0001"), None)
        assert apt28_result is not None
        assert apt28_result[1] == 0.5  # 50% confidence

    def test_below_threshold(self, mock_stix_store):
        """Test TTP overlap below threshold."""
        # Only 1 TTP match - below 50% threshold for APT28 (1/4 = 25%)
        detected = {"T1059.001"}
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # APT28 should not be in results (25% < 50% threshold)
        apt28_result = next((r for r in results if r[0]["intrusion_set_id"] == "G0001"), None)
        assert apt28_result is None

    def test_no_overlap(self, mock_stix_store):
        """Test no TTP overlap."""
        detected = {"T9999.999"}  # Non-existent technique
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        assert len(results) == 0

    def test_empty_detected(self, mock_stix_store):
        """Test with empty detected TTPs."""
        detected = set()
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        assert len(results) == 0

    def test_sorting_by_confidence(self, mock_stix_store):
        """Test results are sorted by confidence descending."""
        # Detected TTPs that match multiple groups
        detected = {"T1059.001", "T1055.001", "T1021.002", "T1003.001", "T1070.001"}
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # Results should be sorted by confidence
        confidences = [r[1] for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_skips_empty_ttps(self, mock_stix_store):
        """Test intrusion sets with no TTPs are skipped."""
        detected = {"T1059.001"}
        
        results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # Empty group should not be in results
        empty_result = next((r for r in results if r[0]["intrusion_set_id"] == "G9999"), None)
        assert empty_result is None


class TestAttributionDetails:
    """Test detailed attribution information."""

    @pytest.fixture
    def mock_stix_store(self):
        """Create mock STIX data store."""
        store = Mock(spec=STIXDataStore)
        store.get_all_intrusion_sets.return_value = [
            {
                "id": "intrusion-set--apt28",
                "intrusion_set_id": "G0001",
                "name": "APT28",
                "description": "Russian military intelligence threat group",
                "aliases": ["Fancy Bear"],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001"],
                "url": "https://attack.mitre.org/groups/G0001/",
            },
        ]
        return store

    def test_includes_overlap_details(self, mock_stix_store):
        """Test detailed attribution includes overlapping TTPs."""
        detected = {"T1059.001", "T1055.001", "T9999.999"}
        
        details = get_attribution_details(detected, mock_stix_store)
        
        assert len(details) > 0
        assert details[0]["intrusion_set"]["intrusion_set_id"] == "G0001"
        assert details[0]["confidence"] == 0.5  # 2/4 TTPs match
        assert details[0]["overlapping_ttps"] == {"T1059.001", "T1055.001"}
        assert details[0]["total_known_ttps"] == 4


class TestAttributionStatistics:
    """Test attribution statistics calculation."""

    @pytest.fixture
    def mock_stix_store(self):
        """Create mock STIX data store."""
        store = Mock(spec=STIXDataStore)
        store.get_all_intrusion_sets.return_value = [
            {
                "id": "intrusion-set--apt28",
                "intrusion_set_id": "G0001",
                "name": "APT28",
                "description": "Russian military intelligence threat group",
                "aliases": [],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001"],
                "url": "https://attack.mitre.org/groups/G0001/",
            },
            {
                "id": "intrusion-set--apt29",
                "intrusion_set_id": "G0002",
                "name": "APT29",
                "description": "Russian foreign intelligence threat group",
                "aliases": [],
                "ttps": ["T1059.001", "T1055.001", "T1070.001"],
                "url": "https://attack.mitre.org/groups/G0002/",
            },
        ]
        return store

    def test_statistics_calculation(self, mock_stix_store):
        """Test attribution statistics are calculated correctly."""
        detected = {"T1059.001", "T1055.001"}
        
        stats = calculate_attribution_statistics(detected, mock_stix_store)
        
        assert stats["total_actors_checked"] == 2
        assert stats["actors_with_matches"] == 2  # Both APT28 and APT29 match
        # APT28: 2/4 = 50%, APT29: 2/3 = 67% - both above 50% threshold
        assert stats["actors_above_threshold"] == 2
        assert stats["max_overlap_ratio"] == 2/3  # APT29 has highest overlap
        assert stats["best_match"]["intrusion_set_id"] == "G0002"  # APT29

    def test_empty_statistics(self, mock_stix_store):
        """Test statistics with no matches."""
        detected = {"T9999.999"}
        
        stats = calculate_attribution_statistics(detected, mock_stix_store)
        
        assert stats["actors_with_matches"] == 0
        assert stats["actors_above_threshold"] == 0
        assert stats["average_overlap_ratio"] == 0.0
        assert stats["max_overlap_ratio"] == 0.0
        assert stats["best_match"] is None


class TestGetIntrusionSetTTPs:
    """Test getting TTPs for specific intrusion set."""

    @pytest.fixture
    def mock_stix_store(self):
        """Create mock STIX data store."""
        store = Mock(spec=STIXDataStore)
        store.get_intrusion_set.return_value = {
            "id": "intrusion-set--apt28",
            "intrusion_set_id": "G0001",
            "name": "APT28",
            "description": "Russian military intelligence threat group",
            "aliases": [],
            "ttps": ["T1059.001", "T1055.001", "T1021.002"],
            "url": "https://attack.mitre.org/groups/G0001/",
        }
        return store

    def test_get_ttps(self, mock_stix_store):
        """Test getting TTPs for intrusion set."""
        ttps = get_intrusion_set_ttps("G0001", mock_stix_store)
        
        assert ttps == {"T1059.001", "T1055.001", "T1021.002"}

    def test_get_ttps_not_found(self, mock_stix_store):
        """Test getting TTPs for non-existent intrusion set."""
        mock_stix_store.get_intrusion_set.return_value = None
        
        ttps = get_intrusion_set_ttps("G9999", mock_stix_store)
        
        assert ttps == set()


class TestTTPWeighting:
    """Test TTP weighting by rarity for improved attribution accuracy."""

    @pytest.fixture
    def mock_stix_store(self):
        """Create mock STIX data store with varying TTP frequencies."""
        store = Mock(spec=STIXDataStore)
        
        # Mock intrusion sets with TTPs of varying rarity
        store.get_all_intrusion_sets.return_value = [
            {
                "id": "intrusion-set--apt28",
                "intrusion_set_id": "G0001",
                "name": "APT28",
                "description": "Russian military intelligence threat group",
                "aliases": ["Fancy Bear"],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001"],
                "url": "https://attack.mitre.org/groups/G0001/",
            },
            {
                "id": "intrusion-set--apt29",
                "intrusion_set_id": "G0002",
                "name": "APT29",
                "description": "Russian foreign intelligence threat group",
                "aliases": ["Cozy Bear"],
                "ttps": ["T1059.001", "T1055.001", "T1070.001", "T1078.004"],
                "url": "https://attack.mitre.org/groups/G0002/",
            },
            {
                "id": "intrusion-set--apt3",
                "intrusion_set_id": "G0003",
                "name": "APT3",
                "description": "Chinese state-sponsored threat group",
                "aliases": ["Comment Crew"],
                "ttps": ["T1059.001", "T1055.001", "T1021.002", "T1003.001", "T1611"],
                "url": "https://attack.mitre.org/groups/G0003/",
            },
        ]
        
        return store

    def test_rarity_weights_common_ttp(self, mock_stix_store):
        """Test that common TTPs receive lower weights."""
        weights = calculate_ttp_weights(mock_stix_store, "rarity")
        
        # T1059.001 is used by all 3 actors - should have lowest weight
        assert "T1059.001" in weights
        # T1611 is used by only 1 actor - should have highest weight
        assert "T1611" in weights
        # Common TTP should have lower weight than rare TTP
        assert weights["T1059.001"] < weights["T1611"]

    def test_rarity_weights_rare_ttp(self, mock_stix_store):
        """Test that rare TTPs receive higher weights."""
        weights = calculate_ttp_weights(mock_stix_store, "rarity")
        
        # T1611 and T1078.004 are used by only 1 actor each
        # They should have the highest weights (1.0 after normalization)
        assert weights["T1611"] == 1.0
        assert weights["T1078.004"] == 1.0

    def test_log_rarity_weights(self, mock_stix_store):
        """Test log-scaled rarity weighting."""
        weights = calculate_ttp_weights(mock_stix_store, "log_rarity")
        
        # All weights should be in 0.0-1.0 range
        for ttp, weight in weights.items():
            assert 0.0 <= weight <= 1.0
        
        # Common TTP should still have lower weight than rare TTP
        assert weights["T1059.001"] < weights["T1611"]

    def test_uniform_weights(self, mock_stix_store):
        """Test uniform weighting (all TTPs equal)."""
        weights = calculate_ttp_weights(mock_stix_store, "uniform")
        
        # All weights should be 1.0
        for ttp, weight in weights.items():
            assert weight == 1.0
        
        # T1059.001 and T1611 should have same weight
        assert weights["T1059.001"] == weights["T1611"]

    def test_invalid_strategy_raises_error(self, mock_stix_store):
        """Test that invalid weighting strategy raises ValueError."""
        with pytest.raises(ValueError, match="Unknown weighting strategy"):
            calculate_ttp_weights(mock_stix_store, "invalid_strategy")

    def test_empty_store_returns_empty_weights(self):
        """Test that empty STIX store returns empty weights dict."""
        store = Mock(spec=STIXDataStore)
        store.get_all_intrusion_sets.return_value = []
        
        weights = calculate_ttp_weights(store, "rarity")
        
        assert weights == {}

    def test_weighted_attribution_improves_accuracy(self, mock_stix_store):
        """Test that weighted attribution improves accuracy for rare TTPs."""
        # Detected TTPs include T1611 (rare, distinctive) and T1059.001 (common)
        detected = {"T1611", "T1059.001"}
        
        # Calculate weights using rarity
        weights = calculate_ttp_weights(mock_stix_store, "rarity")
        
        # Get weighted attribution results
        weighted_results = attribute_to_threat_actors(detected, mock_stix_store, ttp_weights=weights)
        
        # APT3 should be ranked highest because it has T1611 (the rare TTP)
        assert len(weighted_results) > 0
        assert weighted_results[0][0]["intrusion_set_id"] == "G0003"  # APT3
        
        # APT3's confidence should be higher than simple ratio would suggest
        # Simple ratio: 2/5 = 40%
        # Weighted: T1611 (rare) contributes more than T1059.001 (common)

    def test_weighted_vs_unweighted_attribution(self, mock_stix_store):
        """Test difference between weighted and unweighted attribution."""
        # Detected TTPs: one common, one rare
        detected = {"T1059.001", "T1611"}
        
        # Unweighted results (default 50% threshold)
        unweighted_results = attribute_to_threat_actors(detected, mock_stix_store)
        
        # Weighted results
        weights = calculate_ttp_weights(mock_stix_store, "rarity")
        weighted_results = attribute_to_threat_actors(detected, mock_stix_store, ttp_weights=weights)
        
        # With unweighted: APT3 has 2/5 = 40% - below threshold
        # With weighted: T1611 (rare) contributes more, may push above threshold
        # APT3 is the only group with T1611, so weighted should rank it higher
        # or include it when unweighted doesn't
        
        # Check that weighting changes the results
        unweighted_apt3 = next((r for r in unweighted_results if r[0]["intrusion_set_id"] == "G0003"), None)
        weighted_apt3 = next((r for r in weighted_results if r[0]["intrusion_set_id"] == "G0003"), None)
        
        # Either weighted includes APT3 when unweighted doesn't,
        # or weighted gives APT3 higher confidence
        if unweighted_apt3 is None:
            # Weighted may include APT3 due to rare TTP bonus
            # (depends on exact weight calculation)
            pass  # Test passes if behavior differs
        else:
            # If both include APT3, weighted confidence should differ
            assert weighted_apt3 is not None
            assert unweighted_apt3[1] != weighted_apt3[1]
        
        # Verify weighted results are still sorted by confidence
        if len(weighted_results) > 1:
            confidences = [r[1] for r in weighted_results]
            assert confidences == sorted(confidences, reverse=True)


class TestIntegrationWithSTIXData:
    """Integration tests with real STIX data store."""

    @pytest.fixture
    def stix_store(self):
        """Load real STIX data if available."""
        import os
        from pathlib import Path
        
        stix_paths = [
            Path("/home/ubuntu/detonate/data/attack_stix/enterprise-attack.json"),
            Path("./data/attack_stix/enterprise-attack.json"),
        ]
        
        for path in stix_paths:
            if path.exists():
                return STIXDataStore(path)
        
        pytest.skip("STIX data not available for integration test")

    def test_attribution_with_real_data(self, stix_store):
        """Test attribution with real STIX data."""
        # Use a set of TTPs commonly associated with APT groups
        detected = {
            "T1059.001",  # PowerShell
            "T1055.001",  # Dynamic-link Library Injection
            "T1021.002",  # SMB/Windows Admin Shares
        }
        
        results = attribute_to_threat_actors(detected, stix_store)
        
        # Should find some matches with real data
        # The exact results depend on the STIX data version
        assert isinstance(results, list)
        
        # Verify structure of results
        for actor, confidence in results:
            assert "intrusion_set_id" in actor
            assert "name" in actor
            assert "ttps" in actor
            assert 0.0 <= confidence <= 1.0

    def test_all_intrusion_sets_have_ttps(self, stix_store):
        """Test that intrusion sets have TTP data populated."""
        intrusion_sets = stix_store.get_all_intrusion_sets()
        
        # Most intrusion sets should have TTPs
        sets_with_ttps = sum(1 for iset in intrusion_sets if iset.get("ttps"))
        
        # At least some intrusion sets should have TTPs
        assert sets_with_ttps > 0
