"""ATT&CK mapping engine with confidence scoring."""

from typing import Any

import structlog

# Cache platform mappings at module level to avoid repeated imports
from .windows_map import API_TO_TECHNIQUE as WINDOWS_MAP
from .linux_map import SYSCALL_TO_TECHNIQUE as LINUX_MAP

log = structlog.get_logger()


class TechniqueMatch:
    """Represents a technique match with confidence."""

    def __init__(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        confidence: str,
        confidence_score: float,
        evidence_count: int = 1,
        is_sub_technique: bool = False,
        is_pattern_based: bool = False,
        is_param_match: bool = False,
    ):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.confidence = confidence
        self.confidence_score = confidence_score
        self.evidence_count = evidence_count
        self.is_sub_technique = is_sub_technique
        self.is_pattern_based = is_pattern_based
        self.is_param_match = is_param_match
        
        # Set max confidence based on detection type per calibration rules:
        # - Direct API match (no params): max 0.7
        # - Parameter keyword match: max 0.95
        # - Pattern-based (multi-call): max 0.95
        # - Sub-technique: can reach 1.0 with bonus
        if self.is_pattern_based:
            self.max_confidence = 0.95
        elif self.is_param_match:
            self.max_confidence = 0.95
        else:
            # Direct API match without param refinement
            self.max_confidence = 0.7
        
        # Apply sub-technique bonus after setting max_confidence
        # This allows sub-techniques to exceed the base max (e.g., 0.95 + 0.1 = 1.0)
        if self.is_sub_technique and "." in self.technique_id:
            # Sub-technique bonus can push to 1.0
            self.max_confidence = max(self.max_confidence, 1.0)
            self.confidence_score = min(1.0, self.confidence_score + 0.1)
            self.confidence = self._score_to_label(self.confidence_score)

    def add_evidence(self) -> None:
        """Increment evidence count and recalculate confidence with diminishing returns."""
        self.evidence_count += 1
        import math

        # Diminishing returns formula: log-based boost
        # log(2)/log(10) ≈ 0.301, log(3)/log(10) ≈ 0.477, etc.
        # Multiplied by 0.1 for conservative boost
        boost = math.log(self.evidence_count + 1) / math.log(10)
        
        # Recalculate base score (without sub-technique bonus) then apply bonus
        # This ensures sub-technique bonus is preserved on evidence accumulation
        base_score = self.confidence_score
        if self.is_sub_technique and "." in self.technique_id:
            # Remove the bonus temporarily to calculate boost on base
            base_score = max(0, self.confidence_score - 0.1)
        
        new_score = min(
            self.max_confidence if not self.is_sub_technique else 1.0,
            base_score + boost * 0.1
        )
        
        # Re-apply sub-technique bonus if applicable
        if self.is_sub_technique and "." in self.technique_id:
            new_score = min(1.0, new_score + 0.1)
        
        self.confidence_score = new_score
        self.confidence = self._score_to_label(self.confidence_score)

    @staticmethod
    def _score_to_label(score: float) -> str:
        """Convert numeric confidence to label."""
        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "evidence_count": self.evidence_count,
        }


class ATTCKMapper:
    """
    ATT&CK mapping engine.

    Maps API calls and syscalls to ATT&CK techniques with
    confidence scoring based on evidence strength.
    """

    def __init__(self, stix_store: Any | None = None):
        """
        Initialize mapper.

        Args:
            stix_store: Optional STIX data store for technique metadata
        """
        self.stix_store = stix_store
        self.findings: dict[str, TechniqueMatch] = {}

    def map_api_call(
        self,
        api_name: str,
        params: dict[str, Any],
        platform: str = "windows",
    ) -> TechniqueMatch | None:
        """
        Map a single API call to ATT&CK technique(s).

        Args:
            api_name: Name of API or syscall
            params: API parameters
            platform: Target platform (windows/linux)

        Returns:
            TechniqueMatch if mapping found, None otherwise
        """
        # Select platform mapping
        mapping = WINDOWS_MAP if platform == "windows" else LINUX_MAP

        # Check if API/syscall exists in mapping
        if api_name not in mapping:
            log.debug(
                "api_mapping_miss",
                api_name=api_name,
                platform=platform,
            )
            return None

        api_entry = mapping[api_name]
        technique_id = api_entry["technique_id"]
        technique_name = api_entry["technique_name"]
        tactic = api_entry["tactic"]
        confidence_score = api_entry["confidence"]

        # Check for parameter-based refinement
        param_checks = api_entry.get("param_checks", {})

        final_technique_id = technique_id
        final_technique_name = technique_name
        final_tactic = tactic
        final_confidence = confidence_score

        # Iterate through param_checks: {param_name: {keyword: technique_dict}}
        for param_name, keyword_map in param_checks.items():
            # Get parameter value (case-insensitive)
            param_value = params.get(param_name, "")
            if not param_value:
                continue

            param_value_lower = str(param_value).lower()

            # Check each keyword in the keyword_map
            for keyword, technique_dict in keyword_map.items():
                # Case-insensitive substring match
                if keyword.lower() in param_value_lower:
                    # This is a refined match - use the technique from param_checks
                    refined_technique = technique_dict
                    final_technique_id = refined_technique["id"]
                    final_technique_name = refined_technique["name"]
                    final_tactic = refined_technique["tactic"]
                    final_confidence = refined_technique["confidence"]

                    log.debug(
                        "api_param_match",
                        api_name=api_name,
                        param_name=param_name,
                        keyword=keyword,
                        param_value=param_value_lower,
                        technique_id=final_technique_id,
                        confidence=final_confidence,
                    )

                    # Early return for high-confidence matches (>= 0.9)
                    if final_confidence >= 0.9:
                        match = TechniqueMatch(
                            technique_id=final_technique_id,
                            technique_name=final_technique_name,
                            tactic=final_tactic,
                            confidence=TechniqueMatch._score_to_label(final_confidence),
                            confidence_score=final_confidence,
                            is_sub_technique="." in final_technique_id,
                            is_param_match=True,
                        )
                        self._add_or_update_finding(match)
                        # Return the updated finding from storage (with correct evidence count)
                        return self.findings[final_technique_id]

        # Log the final mapping decision
        log.debug(
            "api_mapped",
            api_name=api_name,
            platform=platform,
            technique_id=final_technique_id,
            technique_name=final_technique_name,
            tactic=final_tactic,
            confidence=final_confidence,
        )

        # Determine if this is a sub-technique (has dot notation)
        is_sub_technique = "." in final_technique_id
        
        # Determine if this was a param-based match (refined from default)
        # A param match occurs when final_confidence differs from the base API confidence
        is_param_match = final_confidence != api_entry["confidence"]
        
        # Create and store the technique match
        match = TechniqueMatch(
            technique_id=final_technique_id,
            technique_name=final_technique_name,
            tactic=final_tactic,
            confidence=TechniqueMatch._score_to_label(final_confidence),
            confidence_score=final_confidence,
            is_sub_technique=is_sub_technique,
            is_param_match=is_param_match,
        )

        self._add_or_update_finding(match)
        # Return the updated finding from storage (with correct evidence count)
        return self.findings[final_technique_id]

    def _add_or_update_finding(self, match: TechniqueMatch) -> None:
        """Add a new finding or update existing one with more evidence."""
        if match.technique_id in self.findings:
            self.findings[match.technique_id].add_evidence()
        else:
            self.findings[match.technique_id] = match

    def detect_patterns(self, api_calls: list[Any]) -> list[TechniqueMatch]:
        """
        Detect multi-call patterns (e.g., process injection chain).

        Args:
            api_calls: List of APICallRecord objects

        Returns:
            List of pattern-based technique matches
        """
        from .patterns import detect_injection_pattern, detect_persistence_pattern

        pattern_matches = []

        # Detect process injection patterns
        injection_matches = detect_injection_pattern(api_calls)
        pattern_matches.extend(injection_matches)

        # Detect persistence patterns
        persistence_matches = detect_persistence_pattern(api_calls)
        pattern_matches.extend(persistence_matches)

        return pattern_matches

    def get_technique_metadata(self, technique_id: str) -> dict[str, Any] | None:
        """
        Retrieve technique metadata from STIX data.

        Args:
            technique_id: ATT&CK technique ID (e.g., T1059.001)

        Returns:
            Dictionary with technique metadata or None if not found
        """
        if not self.stix_store:
            return None

        # Query STIX store for technique
        # This would use the stix2 library to query the loaded STIX data
        # For now, return basic structure
        return {
            "technique_id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        }

    def get_all_findings(self) -> list[TechniqueMatch]:
        """Get all technique findings."""
        return list(self.findings.values())

    def clear(self) -> None:
        """Clear all findings."""
        self.findings.clear()
