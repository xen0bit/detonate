"""Live CVE lookup via NVD API."""

import os
import time
from functools import lru_cache
from typing import Optional

import requests
import structlog


class CVELookup:
    """NVD API client with rate limiting and caching."""

    def __init__(self):
        """Initialize NVD API client."""
        self.enabled = os.getenv("DETONATE_CVE_LOOKUP", "false").lower() == "true"
        self.api_key = os.getenv("DETONATE_NVD_API_KEY")
        self.cache: dict[str, Optional[dict]] = {}
        self.last_request_time: float = 0
        # Rate limiting: 5 requests per 30 seconds without API key, 50 per 30 seconds with key
        self.min_request_interval: float = 0.6 if not self.api_key else 0.06
        self.log = structlog.get_logger()

    def _rate_limit(self) -> None:
        """Enforce rate limiting."""
        if not self.enabled:
            return

        current_time = time.time()
        elapsed = current_time - self.last_request_time

        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)

        self.last_request_time = time.time()

    @lru_cache(maxsize=1000)
    def lookup(self, cve_id: str) -> Optional[dict]:
        """
        Lookup CVE information from NVD API.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-1234")

        Returns:
            Dictionary with CVE information, or None if:
            - CVE lookup is disabled
            - CVE not found
            - API error occurs
        """
        if not self.enabled:
            return None

        # Check in-memory cache first (lru_cache handles this automatically)
        if cve_id in self.cache:
            return self.cache[cve_id]

        self._rate_limit()

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()

            data = response.json()
            if data.get("totalResults", 0) > 0:
                cve_data = data["vulnerabilities"][0]["cve"]
                result = {
                    "cve_id": cve_id,
                    "description": self._extract_description(cve_data),
                    "cvss_score": self._extract_cvss(cve_data),
                    "severity": self._extract_severity(cve_data),
                    "published": cve_data.get("published"),
                    "modified": cve_data.get("lastModified"),
                    "references": cve_data.get("references", []),
                }
                self.cache[cve_id] = result
                return result
        except requests.exceptions.RequestException as e:
            self.log.warning("cve_lookup_failed", cve_id=cve_id, error=str(e))
        except Exception as e:
            self.log.warning("cve_lookup_unexpected_error", cve_id=cve_id, error=str(e))

        return None

    def _extract_description(self, cve_data: dict) -> str:
        """Extract primary English description from CVE."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        # Fallback to any description if no English one
        if descriptions:
            return descriptions[0].get("value", "")
        return ""

    def _extract_cvss(self, cve_data: dict) -> Optional[float]:
        """Extract CVSS v3.1 base score."""
        metrics = cve_data.get("metrics", {})
        # Try CVSS v3.1 first, then v3.0, then v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            cvss_data = metrics.get(metric_key, [{}])[0]
            base_score = cvss_data.get("cvssData", {}).get("baseScore")
            if base_score is not None:
                return base_score
        return None

    def _extract_severity(self, cve_data: dict) -> str:
        """Extract severity rating."""
        metrics = cve_data.get("metrics", {})
        # Try CVSS v3.1 first, then v3.0, then v2
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            cvss_data = metrics.get(metric_key, [{}])[0]
            severity = cvss_data.get("cvssData", {}).get("baseSeverity")
            if severity:
                return severity
        return "UNKNOWN"


# Global instance
cve_lookup = CVELookup()


def lookup_cve(cve_id: str) -> Optional[dict]:
    """
    Convenience function for CVE lookup.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2023-1234")

    Returns:
        Dictionary with CVE information, or None if lookup failed/disabled
    """
    return cve_lookup.lookup(cve_id)


def is_cve_lookup_enabled() -> bool:
    """Check if CVE lookup is enabled via environment variable."""
    return cve_lookup.enabled
