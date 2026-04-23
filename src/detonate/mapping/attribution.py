"""Threat actor attribution based on TTP overlap."""

import os
from typing import List, Tuple
from .stix_data import STIXDataStore


def get_attribution_threshold() -> float:
    """
    Get attribution threshold from environment.

    Returns:
        Minimum confidence threshold (0.0-1.0) for attribution.
        Default is 0.5 (50% TTP overlap required).
    """
    try:
        return float(os.getenv("DETONATE_ATTRIBUTION_THRESHOLD", "0.5"))
    except ValueError:
        return 0.5


def calculate_ttp_weights(
    stix_store: STIXDataStore,
    weighting_strategy: str = "rarity",
) -> dict[str, float]:
    """
    Calculate weights for TTPs based on their rarity across threat actors.

    Rarer TTPs (used by fewer actors) receive higher weights, making them
    more distinctive for attribution purposes.

    Args:
        stix_store: STIX data store with intrusion-set objects
        weighting_strategy: Strategy for weight calculation:
            - "rarity": Inverse frequency (1/count) - rare TTPs weighted higher
            - "log_rarity": Log-scaled rarity (log(total/count)) - smoother weighting
            - "uniform": All TTPs weighted equally (1.0)

    Returns:
        Dict mapping technique IDs to weights (0.0-1.0, normalized).

    Example:
        >>> weights = calculate_ttp_weights(stix_store, "rarity")
        >>> weights["T1059.001"]  # PowerShell - common, low weight
        0.15
        >>> weights["T1059.004"]  # Unix Shell - rare, high weight
        0.85
    """
    intrusion_sets = stix_store.get_all_intrusion_sets()

    # Count TTP frequency across all actors
    ttp_frequency: dict[str, int] = {}
    for intrusion_set in intrusion_sets:
        for ttp in intrusion_set.get("ttps", []):
            ttp_frequency[ttp] = ttp_frequency.get(ttp, 0) + 1

    if not ttp_frequency:
        return {}

    total_actors = len(intrusion_sets)

    # Calculate raw weights based on strategy
    raw_weights: dict[str, float] = {}
    import math

    for ttp, count in ttp_frequency.items():
        if weighting_strategy == "rarity":
            # Inverse frequency: rarer = higher weight
            raw_weights[ttp] = 1.0 / count
        elif weighting_strategy == "log_rarity":
            # Log-scaled: smoother weighting, avoids extreme values
            raw_weights[ttp] = math.log(total_actors / count) / math.log(total_actors)
        elif weighting_strategy == "uniform":
            raw_weights[ttp] = 1.0
        else:
            raise ValueError(f"Unknown weighting strategy: {weighting_strategy}")

    # Normalize to 0.0-1.0 range
    if raw_weights:
        max_weight = max(raw_weights.values())
        if max_weight > 0:
            return {ttp: weight / max_weight for ttp, weight in raw_weights.items()}

    return {}


def attribute_to_threat_actors(
    detected_techniques: set[str],
    stix_store: STIXDataStore,
    ttp_weights: dict[str, float] | None = None,
) -> List[Tuple[dict, float]]:
    """
    Attribute detected TTPs to known threat actors.

    Uses a TTP overlap algorithm to calculate confidence scores based on
    the ratio of detected techniques to known techniques for each intrusion set.
    Optionally weights TTPs by rarity (less common TTPs contribute more to confidence).

    Args:
        detected_techniques: Set of technique IDs detected during analysis
                            (e.g., {"T1059.001", "T1055.001", "T1021.002"})
        stix_store: STIX data store with intrusion-set objects
        ttp_weights: Optional dict mapping technique IDs to weights (0.0-1.0).
                     Higher weights for rarer/more distinctive TTPs.
                     If None, all TTPs weighted equally (1.0).

    Returns:
        List of (intrusion_set_data, confidence_score) tuples, sorted by
        confidence descending. Only includes actors meeting the threshold.

    Example:
        >>> detected = {"T1059.001", "T1055.001", "T1021.002"}
        >>> actors = attribute_to_threat_actors(detected, stix_store)
        >>> for actor, confidence in actors:
        ...     print(f"{actor['name']}: {confidence:.0%}")
        APT29: 75%
        APT28: 50%
    """
    threshold = get_attribution_threshold()
    results = []

    # Get all intrusion sets from STIX data
    intrusion_sets = stix_store.get_all_intrusion_sets()

    for intrusion_set in intrusion_sets:
        # Get known TTPs for this intrusion set
        known_ttps = set(intrusion_set.get("ttps", []))

        if not known_ttps:
            # Skip intrusion sets without TTP data
            continue

        # Calculate overlap
        overlap = detected_techniques & known_ttps
        overlap_count = len(overlap)

        if overlap_count == 0:
            # No matching TTPs
            continue

        # Calculate confidence with optional TTP weighting
        if ttp_weights:
            # Weighted confidence: sum of weights for matched TTPs / sum of weights for all known TTPs
            matched_weight = sum(ttp_weights.get(t, 1.0) for t in overlap)
            total_weight = sum(ttp_weights.get(t, 1.0) for t in known_ttps)
            confidence = matched_weight / total_weight if total_weight > 0 else 0.0
        else:
            # Simple ratio: detected TTPs / known TTPs for this actor
            confidence = overlap_count / len(known_ttps)

        if confidence >= threshold:
            # Include overlap details in result for reporting
            results.append((intrusion_set, confidence, overlap))

    # Sort by confidence descending
    results.sort(key=lambda x: x[1], reverse=True)

    # Return without overlap details (clean interface)
    return [(is_data, confidence) for is_data, confidence, _ in results]


def get_intrusion_set_ttps(
    intrusion_set_id: str,
    stix_store: STIXDataStore,
) -> set[str]:
    """
    Get all TTPs associated with an intrusion set.

    Args:
        intrusion_set_id: MITRE ATT&CK intrusion set ID (e.g., "G0001")
        stix_store: STIX data store

    Returns:
        Set of technique IDs associated with the intrusion set.
        Empty set if intrusion set not found.
    """
    intrusion_set = stix_store.get_intrusion_set(intrusion_set_id)
    if not intrusion_set:
        return set()

    return set(intrusion_set.get("ttps", []))


def get_attribution_details(
    detected_techniques: set[str],
    stix_store: STIXDataStore,
) -> List[dict]:
    """
    Get detailed attribution information including overlapping TTPs.

    This is an extended version of attribute_to_threat_actors that includes
    the specific TTPs that matched for each attribution.

    Args:
        detected_techniques: Set of technique IDs detected during analysis
        stix_store: STIX data store with intrusion-set objects

    Returns:
        List of dicts with keys:
            - intrusion_set: dict with intrusion set metadata
            - confidence: float (0.0-1.0)
            - overlapping_ttps: set of technique IDs that matched
            - total_known_ttps: int count of known TTPs for this actor

    Example:
        >>> details = get_attribution_details(detected, stix_store)
        >>> for item in details:
        ...     print(f"{item['intrusion_set']['name']}: "
        ...           f"{len(item['overlapping_ttps'])}/{item['total_known_ttps']} TTPs match")
    """
    threshold = get_attribution_threshold()
    results = []

    intrusion_sets = stix_store.get_all_intrusion_sets()

    for intrusion_set in intrusion_sets:
        known_ttps = set(intrusion_set.get("ttps", []))

        if not known_ttps:
            continue

        overlap = detected_techniques & known_ttps
        overlap_count = len(overlap)

        if overlap_count == 0:
            continue

        confidence = overlap_count / len(known_ttps)

        if confidence >= threshold:
            results.append({
                "intrusion_set": intrusion_set,
                "confidence": confidence,
                "overlapping_ttps": overlap,
                "total_known_ttps": len(known_ttps),
            })

    # Sort by confidence descending
    results.sort(key=lambda x: x["confidence"], reverse=True)

    return results


def calculate_attribution_statistics(
    detected_techniques: set[str],
    stix_store: STIXDataStore,
) -> dict:
    """
    Calculate statistics about attribution results.

    Useful for understanding how well the detected TTPs map to known actors.

    Args:
        detected_techniques: Set of technique IDs detected during analysis
        stix_store: STIX data store

    Returns:
        Dict with statistics:
            - total_actors_checked: int
            - actors_with_matches: int
            - actors_above_threshold: int
            - average_overlap_ratio: float
            - max_overlap_ratio: float
            - best_match: dict or None (intrusion set with highest confidence)
    """
    intrusion_sets = stix_store.get_all_intrusion_sets()
    threshold = get_attribution_threshold()

    total_checked = len(intrusion_sets)
    actors_with_matches = 0
    actors_above_threshold = 0
    overlap_ratios = []
    best_match = None
    best_confidence = 0.0

    for intrusion_set in intrusion_sets:
        known_ttps = set(intrusion_set.get("ttps", []))

        if not known_ttps:
            continue

        overlap = detected_techniques & known_ttps
        overlap_count = len(overlap)

        if overlap_count > 0:
            actors_with_matches += 1
            confidence = overlap_count / len(known_ttps)
            overlap_ratios.append(confidence)

            if confidence >= threshold:
                actors_above_threshold += 1

            if confidence > best_confidence:
                best_confidence = confidence
                best_match = intrusion_set

    average_overlap = sum(overlap_ratios) / len(overlap_ratios) if overlap_ratios else 0.0
    max_overlap = max(overlap_ratios) if overlap_ratios else 0.0

    return {
        "total_actors_checked": total_checked,
        "actors_with_matches": actors_with_matches,
        "actors_above_threshold": actors_above_threshold,
        "average_overlap_ratio": average_overlap,
        "max_overlap_ratio": max_overlap,
        "best_match": best_match,
    }
