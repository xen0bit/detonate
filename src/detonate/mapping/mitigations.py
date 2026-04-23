"""MITRE ATT&CK mitigation mappings for course-of-action objects.

This module provides mitigation recommendations by loading data dynamically
from the STIX 2.1 enterprise-attack.json file. It indexes all 268 course-of-action
objects and their relationships to techniques via 'mitigates' relationships.
"""

from typing import Any

import structlog

from .stix_data import STIXDataStore, load_stix_data

log = structlog.get_logger()

# Global STIX data store instance
_stix_store: STIXDataStore | None = None


def get_stix_store() -> STIXDataStore:
    """Get or create the global STIX data store instance."""
    global _stix_store
    if _stix_store is None:
        try:
            _stix_store = load_stix_data()
        except FileNotFoundError as e:
            log.warning("stix_data_not_found", error=str(e))
            # Return empty store for graceful degradation
            _stix_store = STIXDataStore()
    return _stix_store


def get_mitigations_for_technique(technique_id: str) -> list[dict[str, Any]]:
    """
    Return list of mitigations for a given technique.

    Loads mitigations dynamically from STIX data. Falls back to parent
    technique for sub-techniques if no direct mapping exists. For discovery
    techniques without explicit mitigations, provides sensible default
    mitigations based on MITRE ATT&CK guidance.

    Args:
        technique_id: ATT&CK technique ID (e.g., "T1055.001")

    Returns:
        List of mitigation dictionaries. Empty list if no mitigations found.

    Example:
        >>> mitigations = get_mitigations_for_technique("T1055.001")
        >>> for m in mitigations:
        ...     print(f"{m['mitigation_id']}: {m['name']}")
    """
    store = get_stix_store()
    mitigations = store.get_mitigations_for_technique(technique_id)

    # Fallback for discovery techniques that don't have explicit mitigations in STIX
    # These are based on MITRE ATT&CK's general guidance for detection/prevention
    if not mitigations:
        fallback = _get_fallback_mitigations(technique_id)
        if fallback:
            return fallback

    return mitigations


def _get_fallback_mitigations(technique_id: str) -> list[dict[str, Any]]:
    """
    Provide fallback mitigations for techniques without STIX mappings.

    Discovery techniques and some others don't have explicit mitigations
    in ATT&CK because they're difficult to prevent. We provide sensible
    defaults based on general security practices.
    """
    store = get_stix_store()

    # Discovery techniques - focus on detection and limiting access
    discovery_techniques = {
        "T1082",  # System Information Discovery
        "T1016",  # System Network Configuration Discovery
        "T1083",  # File and Directory Discovery
        "T1057",  # Process Discovery
        "T1012",  # Query Registry
        "T1115",  # Clipboard Data
        "T1033",  # System Owner/User Discovery
        "T1007",  # System Service Discovery
        "T1049",  # System Network Connections Discovery
        "T1046",  # Network Service Scanning
        "T1018",  # Remote System Discovery
        "T1040",  # Network Sniffing
        "T1069",  # Permission Groups Discovery
        "T1135",  # Network Share Discovery
    }

    if technique_id in discovery_techniques:
        # Discovery techniques: focus on limiting attack surface and detection
        fallback = []
        for mid in ["M1040", "M1026", "M1028"]:
            m = store.get_mitigation(mid)
            if m:
                fallback.append(m)
        return fallback

    # Persistence techniques without explicit mitigations
    if technique_id.startswith("T1547"):
        fallback = []
        for mid in ["M1040", "M1042", "M1055"]:
            m = store.get_mitigation(mid)
            if m:
                fallback.append(m)
        return fallback

    return []


def get_all_mitigations() -> list[dict[str, Any]]:
    """
    Return all unique mitigations from STIX data.

    Returns:
        List of all course-of-action dictionaries.
    """
    store = get_stix_store()
    return store.get_all_mitigations()


def get_mitigation_by_id(mitigation_id: str) -> dict[str, Any] | None:
    """
    Get a specific mitigation by ID.

    Args:
        mitigation_id: Mitigation ID (e.g., "M1049")

    Returns:
        Mitigation dictionary or None if not found.
    """
    store = get_stix_store()
    return store.get_mitigation(mitigation_id)


def get_mitigation_coverage_stats() -> dict[str, Any]:
    """
    Get statistics about mitigation coverage.

    Returns:
        Dictionary with coverage statistics including:
        - total_mitigations: Number of course-of-action objects
        - techniques_with_mitigations: Number of techniques with at least one mitigation
        - total_techniques: Total number of techniques indexed
    """
    store = get_stix_store()
    return {
        "total_mitigations": len(store.course_of_action),
        "techniques_with_mitigations": len(store.technique_to_mitigations),
        "total_techniques": len(store.techniques),
        "mitigates_relationships": len(store.mitigates_relationships),
    }
