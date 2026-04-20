"""Tests for ATT&CK Navigator layer generator."""

import json
import math
from datetime import datetime
from pathlib import Path

import pytest

from detonate.core.session import APICallRecord, TechniqueMatch
from detonate.output.navigator import (
    _build_evidence_summary,
    _calculate_score,
    _CONFIDENCE_COLORS,
    generate_navigator_layer,
    save_navigator_layer,
)


class TestCalculateScore:
    """Test score calculation with proper bounds."""

    def test_high_confidence_single_evidence(self):
        """High confidence (1.0) with 1 evidence should give reasonable score."""
        score = _calculate_score(1.0, 1)
        # log(2) ≈ 0.693, so score ≈ 6.93 → 7
        assert 6 <= score <= 8

    def test_low_confidence_single_evidence(self):
        """Low confidence (0.3) with 1 evidence should give low score."""
        score = _calculate_score(0.3, 1)
        # log(2) ≈ 0.693, so score ≈ 2.08 → 2
        assert 1 <= score <= 3

    def test_score_clamped_to_maximum(self):
        """Score should never exceed 10 even with many evidence items."""
        # log(1000) ≈ 6.9, so raw score would be 69 without clamping
        score = _calculate_score(1.0, 999)
        assert score == 10

    def test_score_clamped_to_minimum(self):
        """Score should never be negative."""
        score = _calculate_score(0.0, 1)
        assert score == 0

    def test_zero_evidence(self):
        """Zero evidence should give score of 0."""
        score = _calculate_score(1.0, 0)
        # log(1) = 0, so score = 0
        assert score == 0

    def test_medium_confidence_medium_evidence(self):
        """Medium confidence with moderate evidence."""
        score = _calculate_score(0.6, 5)
        # log(6) ≈ 1.79, so score ≈ 10.7 → clamped to 10
        assert score <= 10

    def test_invalid_negative_evidence_count(self):
        """Negative evidence count should raise ValueError."""
        with pytest.raises(ValueError, match="evidence_count must be non-negative"):
            _calculate_score(1.0, -1)

    def test_invalid_confidence_above_range(self):
        """Confidence > 1.0 should raise ValueError."""
        with pytest.raises(ValueError, match="confidence_score must be in range"):
            _calculate_score(1.5, 5)

    def test_invalid_confidence_below_range(self):
        """Confidence < 0.0 should raise ValueError."""
        with pytest.raises(ValueError, match="confidence_score must be in range"):
            _calculate_score(-0.1, 5)


class TestBuildEvidenceSummary:
    """Test evidence summary building with deduplication."""

    def test_empty_evidence(self):
        """Empty evidence list returns appropriate message."""
        summary = _build_evidence_summary([])
        assert "No evidence" in summary

    def test_single_api_call(self):
        """Single API call returns just that API name."""
        record = APICallRecord(
            timestamp=datetime.utcnow(),
            api_name="CreateProcessA",
            syscall_name=None,
            params={},
            return_value=True,
            address="0x1000",
        )
        summary = _build_evidence_summary([record])
        assert summary == "CreateProcessA"

    def test_duplicate_apis_shows_count(self):
        """Duplicate API calls show count suffix."""
        records = [
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name="CreateProcessA",
                syscall_name=None,
                params={},
                return_value=True,
                address="0x1000",
            ),
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name="CreateProcessA",
                syscall_name=None,
                params={},
                return_value=True,
                address="0x1000",
            ),
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name="CreateProcessA",
                syscall_name=None,
                params={},
                return_value=True,
                address="0x1000",
            ),
        ]
        summary = _build_evidence_summary(records)
        assert "CreateProcessA ×3" in summary

    def test_multiple_unique_apis(self):
        """Multiple unique APIs are listed."""
        records = [
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name="CreateProcessA",
                syscall_name=None,
                params={},
                return_value=True,
                address="0x1000",
            ),
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name="VirtualAllocEx",
                syscall_name=None,
                params={},
                return_value="0x2000",
                address="0x1004",
            ),
        ]
        summary = _build_evidence_summary(records)
        assert "CreateProcessA" in summary
        assert "VirtualAllocEx" in summary

    def test_truncation_with_indicator(self):
        """More than 5 unique APIs are truncated with indicator."""
        records = [
            APICallRecord(
                timestamp=datetime.utcnow(),
                api_name=f"API_{i}",
                syscall_name=None,
                params={},
                return_value=0,
                address="0x1000",
            )
            for i in range(8)
        ]
        summary = _build_evidence_summary(records)
        assert "more" in summary.lower()
        # Should mention 3 more (8 - 5 = 3)
        assert "3 more" in summary

    def test_uses_syscall_when_api_name_missing(self):
        """Uses syscall_name when api_name is None."""
        record = APICallRecord(
            timestamp=datetime.utcnow(),
            api_name=None,
            syscall_name="execve",
            params={},
            return_value=0,
            address="0x1000",
        )
        summary = _build_evidence_summary([record])
        assert "execve" in summary

    def test_unknown_when_both_missing(self):
        """Uses 'unknown' when both api_name and syscall_name are None."""
        record = APICallRecord(
            timestamp=datetime.utcnow(),
            api_name=None,
            syscall_name=None,
            params={},
            return_value=0,
            address="0x1000",
        )
        summary = _build_evidence_summary([record])
        assert "unknown" in summary


class TestGenerateNavigatorLayer:
    """Test full Navigator layer generation."""

    def test_basic_layer_structure(self):
        """Generated layer has required top-level fields."""
        findings = []
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        assert layer["version"] == "4.5"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert "gradient" in layer
        assert "filters" in layer
        assert "legendItems" in layer

    def test_layer_name_includes_hash(self):
        """Layer name includes truncated sample hash."""
        sample_hash = "abcd1234" * 16
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256=sample_hash,
            findings=[],
            platform="windows",
        )
        assert sample_hash[:16] in layer["name"]

    def test_platform_filter_windows(self):
        """Windows platform sets correct filter."""
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=[],
            platform="windows",
        )
        assert layer["filters"]["platforms"] == ["Windows"]

    def test_platform_filter_linux(self):
        """Linux platform sets correct filter."""
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=[],
            platform="linux",
        )
        assert layer["filters"]["platforms"] == ["Linux"]

    def test_invalid_platform_raises(self):
        """Invalid platform raises ValueError."""
        with pytest.raises(ValueError, match="platform must be"):
            generate_navigator_layer(
                session_id="test-session",
                sample_sha256="abcd1234" * 16,
                findings=[],
                platform="macos",
            )

    def test_technique_entries(self):
        """Technique entries have all required fields."""
        findings = [
            TechniqueMatch(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                confidence="high",
                confidence_score=1.0,
                evidence_count=3,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                evidence=[
                    APICallRecord(
                        timestamp=datetime.utcnow(),
                        api_name="CreateProcessA",
                        syscall_name=None,
                        params={"cmd": "powershell"},
                        return_value=True,
                        address="0x1000",
                    )
                ],
            )
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        assert len(layer["techniques"]) == 1
        tech = layer["techniques"][0]
        assert tech["techniqueID"] == "T1059.001"
        assert tech["tactic"] == "execution"
        assert "score" in tech
        assert "color" in tech
        assert "comment" in tech
        assert "metadata" in tech
        assert tech["enabled"] is True

    def test_technique_color_by_confidence(self):
        """Technique color matches confidence level."""
        findings = [
            TechniqueMatch(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                confidence="high",
                confidence_score=1.0,
                evidence_count=1,
            ),
            TechniqueMatch(
                technique_id="T1055.001",
                technique_name="DLL Injection",
                tactic="defense-evasion",
                confidence="low",
                confidence_score=0.3,
                evidence_count=1,
            ),
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        # Find techniques by ID
        techs_by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert techs_by_id["T1059.001"]["color"] == _CONFIDENCE_COLORS["high"]
        assert techs_by_id["T1055.001"]["color"] == _CONFIDENCE_COLORS["low"]

    def test_techniques_sorted_by_score(self):
        """Techniques are sorted by score descending."""
        findings = [
            TechniqueMatch(
                technique_id="T1",
                technique_name="Low Score",
                tactic="tactic1",
                confidence="low",
                confidence_score=0.3,
                evidence_count=1,
            ),
            TechniqueMatch(
                technique_id="T2",
                technique_name="High Score",
                tactic="tactic2",
                confidence="high",
                confidence_score=1.0,
                evidence_count=5,
            ),
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        scores = [t["score"] for t in layer["techniques"]]
        assert scores == sorted(scores, reverse=True)

    def test_metadata_includes_apis(self):
        """Technique metadata includes API names."""
        findings = [
            TechniqueMatch(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                confidence="high",
                confidence_score=1.0,
                evidence_count=2,
                evidence=[
                    APICallRecord(
                        timestamp=datetime.utcnow(),
                        api_name="CreateProcessA",
                        syscall_name=None,
                        params={},
                        return_value=True,
                        address="0x1000",
                    ),
                    APICallRecord(
                        timestamp=datetime.utcnow(),
                        api_name="VirtualAllocEx",
                        syscall_name=None,
                        params={},
                        return_value="0x2000",
                        address="0x1004",
                    ),
                ],
            )
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        tech = layer["techniques"][0]
        api_metadata = [m for m in tech["metadata"] if m["name"] == "apis"]
        assert len(api_metadata) == 1
        assert "CreateProcessA" in api_metadata[0]["value"]
        assert "VirtualAllocEx" in api_metadata[0]["value"]

    def test_description_includes_counts(self):
        """Description includes technique and tactic counts."""
        findings = [
            TechniqueMatch(
                technique_id="T1",
                technique_name="Tech1",
                tactic="execution",
                confidence="high",
                confidence_score=1.0,
                evidence_count=1,
            ),
            TechniqueMatch(
                technique_id="T2",
                technique_name="Tech2",
                tactic="persistence",
                confidence="high",
                confidence_score=1.0,
                evidence_count=1,
            ),
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )

        assert "2 ATT&CK techniques" in layer["description"]
        assert "2 tactics" in layer["description"]


class TestSaveNavigatorLayer:
    """Test saving Navigator layer to file."""

    def test_save_creates_file(self, temp_dir):
        """Save function creates JSON file."""
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=[],
            platform="windows",
        )
        output_path = str(temp_dir / "navigator.json")

        save_navigator_layer(layer, output_path)

        assert Path(output_path).exists()

    def test_save_creates_parent_directories(self, temp_dir):
        """Save function creates parent directories if needed."""
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=[],
            platform="windows",
        )
        output_path = str(temp_dir / "subdir" / "nested" / "navigator.json")

        save_navigator_layer(layer, output_path)

        assert Path(output_path).exists()

    def test_saved_file_is_valid_json(self, temp_dir):
        """Saved file contains valid JSON."""
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=[],
            platform="windows",
        )
        output_path = str(temp_dir / "navigator.json")

        save_navigator_layer(layer, output_path)

        with open(output_path) as f:
            loaded = json.load(f)

        assert loaded == layer

    def test_saved_file_uses_utf8(self, temp_dir):
        """Saved file uses UTF-8 encoding."""
        # Use a custom API name with UTF-8 character to verify encoding
        # The API name appears in the metadata section
        findings = [
            TechniqueMatch(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="execution",
                confidence="high",
                confidence_score=1.0,
                evidence_count=1,
                evidence=[
                    APICallRecord(
                        timestamp=datetime.utcnow(),
                        api_name="CréateProcessA",  # UTF-8 char in API name
                        syscall_name=None,
                        params={},
                        return_value=True,
                        address="0x1000",
                    )
                ],
            )
        ]
        layer = generate_navigator_layer(
            session_id="test-session",
            sample_sha256="abcd1234" * 16,
            findings=findings,
            platform="windows",
        )
        output_path = str(temp_dir / "navigator.json")

        save_navigator_layer(layer, output_path)

        # Should not raise UnicodeDecodeError
        with open(output_path, encoding="utf-8") as f:
            content = f.read()
        assert "é" in content
