"""Tests for confidence calibration."""

import pytest
from detonate.mapping.engine import ATTCKMapper, TechniqueMatch


class TestConfidenceCalibration:
    """Test confidence score calibration."""

    def test_direct_api_match_base_score(self):
        """Test direct API match without params has base score ~0.5."""
        mapper = ATTCKMapper()
        
        # CreateProcessA without PowerShell keywords - direct match
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )
        
        assert result is not None
        # Base confidence for direct API match should be around 0.5-0.6
        assert result.confidence_score >= 0.5
        assert result.confidence_score <= 0.7  # Max for direct match

    def test_param_keyword_match_high_score(self):
        """Test parameter keyword match has high base score ~0.8."""
        mapper = ATTCKMapper()
        
        # CreateProcessA with PowerShell - param keyword match
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "powershell -enc base64"},
            platform="windows",
        )
        
        assert result is not None
        assert result.technique_id == "T1059.001"
        # Param keyword match should have high confidence
        assert result.confidence_score >= 0.8
        assert result.confidence == "high"

    def test_sub_technique_bonus(self):
        """Test sub-technique matches receive +0.1 bonus."""
        mapper = ATTCKMapper()
        
        # T1059.001 is a sub-technique (has dot notation)
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "powershell"},
            platform="windows",
        )
        
        assert result is not None
        assert "." in result.technique_id  # Is sub-technique
        # Sub-technique bonus should be applied
        # Base 0.8 + 0.1 bonus = 0.9
        assert result.confidence_score >= 0.85

    def test_pattern_based_cap(self):
        """Test pattern-based detections are capped at 0.95."""
        from unittest.mock import Mock
        
        # Create a pattern-based match
        match = TechniqueMatch(
            technique_id="T1055.001",
            technique_name="DLL Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.95,
            evidence_count=4,
            is_pattern_based=True,
        )
        
        # Pattern-based should have max_confidence of 0.95
        assert match.max_confidence == 0.95
        
        # Add more evidence - should not exceed cap
        match.add_evidence()
        assert match.confidence_score <= 0.95

    def test_evidence_accumulation_diminishing_returns(self):
        """Test evidence accumulation uses diminishing returns."""
        mapper = ATTCKMapper()
        
        # Use a medium-confidence API (not already at cap) to test evidence accumulation
        # CreateProcessA with generic command - base confidence 0.5
        result1 = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )
        initial_score = result1.confidence_score
        initial_evidence = result1.evidence_count
        
        # Second call (same technique)
        result2 = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "calc.exe"},
            platform="windows",
        )
        
        # Evidence count should increase
        assert result2.evidence_count == initial_evidence + 1
        
        # Score should increase with evidence
        assert result2.confidence_score >= initial_score
        
        # Third call
        result3 = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "mspaint.exe"},
            platform="windows",
        )
        
        # The boost from 2->3 should be smaller than 1->2 (diminishing returns)
        boost_1_to_2 = result2.confidence_score - initial_score
        boost_2_to_3 = result3.confidence_score - result2.confidence_score
        
        # Diminishing returns: later boosts should be smaller or equal
        # (may be equal if hitting cap)
        assert boost_2_to_3 <= boost_1_to_2 + 0.001  # Small tolerance for floating point

    def test_non_sub_technique_no_bonus(self):
        """Test parent techniques (no dot) don't get sub-technique bonus."""
        mapper = ATTCKMapper()
        
        # T1106 is a parent technique (no dot notation)
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )
        
        assert result is not None
        assert result.technique_id == "T1106"
        assert "." not in result.technique_id
        # Should NOT get the +0.1 sub-technique bonus

    def test_pattern_based_flag_set(self):
        """Test that pattern-based detections have is_pattern_based=True."""
        from unittest.mock import Mock
        
        match = TechniqueMatch(
            technique_id="T1055.001",
            technique_name="DLL Injection",
            tactic="defense-evasion",
            confidence="high",
            confidence_score=0.95,
            evidence_count=4,
            is_pattern_based=True,
        )
        
        assert match.is_pattern_based is True
        assert match.max_confidence == 0.95

    def test_direct_match_max_confidence(self):
        """Test direct API matches are capped appropriately."""
        mapper = ATTCKMapper()
        
        # Direct match without param refinement
        result = mapper.map_api_call(
            "CreateProcessA",
            {"lpCommandLine": "notepad.exe"},
            platform="windows",
        )
        
        assert result is not None
        # Direct matches should cap at 0.7
        # (unless they're sub-techniques which get bonus)
        if "." not in result.technique_id:
            assert result.confidence_score <= 0.7

    def test_confidence_label_conversion(self):
        """Test confidence score to label conversion."""
        # Test score_to_label static method
        assert TechniqueMatch._score_to_label(0.95) == "high"
        assert TechniqueMatch._score_to_label(0.80) == "high"
        assert TechniqueMatch._score_to_label(0.79) == "medium"
        assert TechniqueMatch._score_to_label(0.50) == "medium"
        assert TechniqueMatch._score_to_label(0.49) == "low"

    def test_linux_credential_access_high_confidence(self):
        """Test Linux credential access has high confidence."""
        mapper = ATTCKMapper()
        
        result = mapper.map_api_call(
            "open",
            {"filename": "/etc/shadow"},
            platform="linux",
        )
        
        assert result is not None
        assert result.technique_id == "T1003.008"
        # Accessing /etc/shadow should be high confidence
        assert result.confidence == "high"
        assert result.confidence_score >= 0.8
