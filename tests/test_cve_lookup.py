"""Tests for CVE lookup functionality."""

import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from src.detonate.utils.cve_lookup import CVELookup, lookup_cve, is_cve_lookup_enabled
from src.detonate.core.session import AnalysisSession, APICallRecord, VulnerabilityRecord


class TestCVELookupDisabled:
    """Test CVE lookup when disabled."""

    def test_lookup_returns_none_when_disabled(self):
        """Test that lookup returns None when DETONATE_CVE_LOOKUP is not set."""
        # Ensure env var is not set
        original = os.environ.pop("DETONATE_CVE_LOOKUP", None)
        try:
            lookup = CVELookup()
            assert lookup.enabled is False
            result = lookup.lookup("CVE-2023-1234")
            assert result is None
        finally:
            if original:
                os.environ["DETONATE_CVE_LOOKUP"] = original

    def test_is_cve_lookup_enabled_returns_false(self):
        """Test helper function returns False when disabled."""
        original = os.environ.pop("DETONATE_CVE_LOOKUP", None)
        try:
            assert is_cve_lookup_enabled() is False
        finally:
            if original:
                os.environ["DETONATE_CVE_LOOKUP"] = original


class TestCVELookupEnabled:
    """Test CVE lookup when enabled."""

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_successful_lookup(self, mock_get):
        """Test successful CVE lookup returns expected data."""
        # Mock NVD API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability description"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                        "published": "2023-01-15T00:00:00Z",
                        "lastModified": "2023-02-20T00:00:00Z",
                        "references": [
                            {"url": "https://example.com/advisory"}
                        ],
                    }
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        # Enable CVE lookup
        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            result = lookup.lookup("CVE-2023-1234")

            assert result is not None
            assert result["cve_id"] == "CVE-2023-1234"
            assert result["description"] == "Test vulnerability description"
            assert result["cvss_score"] == 7.5
            assert result["severity"] == "HIGH"
            assert result["published"] == "2023-01-15T00:00:00Z"
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_lookup_with_api_key(self, mock_get):
        """Test that API key is included in request headers when provided."""
        mock_response = Mock()
        mock_response.json.return_value = {"totalResults": 0}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        os.environ["DETONATE_NVD_API_KEY"] = "test-api-key-12345"
        try:
            lookup = CVELookup()
            lookup.lookup("CVE-2023-1234")

            # Verify API key was included in request
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert call_args[1]["headers"]["apiKey"] == "test-api-key-12345"
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)
            os.environ.pop("DETONATE_NVD_API_KEY", None)

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_lookup_not_found(self, mock_get):
        """Test lookup returns None when CVE not found."""
        mock_response = Mock()
        mock_response.json.return_value = {"totalResults": 0}
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            result = lookup.lookup("CVE-9999-9999")
            assert result is None
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_lookup_api_error(self, mock_get):
        """Test lookup returns None on API error."""
        mock_get.side_effect = Exception("Network error")

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            result = lookup.lookup("CVE-2023-1234")
            assert result is None
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_lookup_caching(self, mock_get):
        """Test that results are cached."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2023-1234", "descriptions": []}}],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            # First call
            lookup.lookup("CVE-2023-1234")
            # Second call (should use cache)
            lookup.lookup("CVE-2023-1234")

            # Should only have made one API call
            assert mock_get.call_count == 1
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    def test_rate_limiting_without_api_key(self):
        """Test rate limiting enforces 0.6s interval without API key."""
        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        os.environ.pop("DETONATE_NVD_API_KEY", None)
        try:
            lookup = CVELookup()
            assert lookup.min_request_interval == 0.6
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    def test_rate_limiting_with_api_key(self):
        """Test rate limiting enforces 0.06s interval with API key."""
        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        os.environ["DETONATE_NVD_API_KEY"] = "test-key"
        try:
            lookup = CVELookup()
            assert lookup.min_request_interval == 0.06
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)
            os.environ.pop("DETONATE_NVD_API_KEY", None)


class TestVulnerabilityRecord:
    """Test VulnerabilityRecord dataclass."""

    def test_vulnerability_record_creation(self):
        """Test creating a VulnerabilityRecord."""
        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateFileA",
            syscall_name=None,
            params={"lpFileName": "C:\\vulnerable.dll"},
            return_value=0,
            address="0x401000",
        )
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "description": "Test vulnerability",
            "cvss_score": 7.5,
            "severity": "HIGH",
        }

        record = VulnerabilityRecord(
            cve_id="CVE-2023-1234",
            cve_data=cve_data,
            related_api_call=api_call,
            technique_id="T1059.001",
        )

        assert record.cve_id == "CVE-2023-1234"
        assert record.cve_data == cve_data
        assert record.related_api_call == api_call
        assert record.technique_id == "T1059.001"


class TestAnalysisSessionWithVulnerabilities:
    """Test AnalysisSession vulnerability tracking."""

    def test_add_vulnerability(self, tmp_path):
        """Test adding vulnerability to session."""
        # Create a temporary test file
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test binary content")
        
        session = AnalysisSession(
            sample_path=str(test_file),
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )

        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateFileA",
            syscall_name=None,
            params={"lpFileName": "C:\\vulnerable.dll"},
            return_value=0,
            address="0x401000",
        )
        cve_data = {
            "cve_id": "CVE-2023-1234",
            "description": "Test vulnerability",
            "cvss_score": 7.5,
            "severity": "HIGH",
        }

        session.add_vulnerability(
            cve_id="CVE-2023-1234",
            cve_data=cve_data,
            related_api_call=api_call,
            technique_id="T1059.001",
        )

        assert len(session.vulnerabilities) == 1
        vuln = session.vulnerabilities[0]
        assert vuln.cve_id == "CVE-2023-1234"
        assert vuln.technique_id == "T1059.001"

    def test_to_result_includes_vulnerabilities(self, tmp_path):
        """Test that to_result includes vulnerabilities."""
        # Create a temporary test file
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test binary content")
        
        session = AnalysisSession(
            sample_path=str(test_file),
            sample_sha256="abc123",
            platform="windows",
            architecture="x86",
        )

        api_call = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name="CreateFileA",
            syscall_name=None,
            params={},
            return_value=0,
            address="0x401000",
        )

        session.add_vulnerability(
            cve_id="CVE-2023-1234",
            cve_data={"description": "Test"},
            related_api_call=api_call,
        )

        result = session.to_result()
        assert len(result.vulnerabilities) == 1


class TestCVEDescriptionExtraction:
    """Test CVE description extraction edge cases."""

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_fallback_to_non_english_description(self, mock_get):
        """Test fallback when no English description available."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [
                            {"lang": "es", "value": "Descripción en español"},
                            {"lang": "fr", "value": "Description en français"},
                        ],
                        "metrics": {},
                    }
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            result = lookup.lookup("CVE-2023-1234")
            # Should fall back to first description
            assert result["description"] == "Descripción en español"
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)

    @patch("src.detonate.utils.cve_lookup.requests.get")
    def test_cvss_v30_fallback(self, mock_get):
        """Test CVSS v3.0 fallback when v3.1 not available."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-1234",
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "metrics": {
                            "cvssMetricV30": [
                                {
                                    "cvssData": {
                                        "baseScore": 6.5,
                                        "baseSeverity": "MEDIUM",
                                    }
                                }
                            ]
                        },
                    }
                }
            ],
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response

        os.environ["DETONATE_CVE_LOOKUP"] = "true"
        try:
            lookup = CVELookup()
            result = lookup.lookup("CVE-2023-1234")
            assert result["cvss_score"] == 6.5
            assert result["severity"] == "MEDIUM"
        finally:
            os.environ.pop("DETONATE_CVE_LOOKUP", None)
