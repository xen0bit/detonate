"""Multi-call pattern detection for ATT&CK mapping."""

from datetime import datetime
from typing import Any

from .engine import TechniqueMatch


def detect_injection_pattern(api_calls: list[Any]) -> list[TechniqueMatch]:
    """
    Detect process injection patterns from API call sequences.

    Patterns detected:
    - Classic injection: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
    - Process hollowing: CreateProcess(suspended) → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread

    Args:
        api_calls: List of APICallRecord objects

    Returns:
        List of TechniqueMatch objects for detected patterns
    """
    matches = []

    # Track API sequences by target process
    process_sequences: dict[str, list[str]] = {}

    for call in api_calls:
        api_name = call.api_name or ""
        params = call.params or {}

        # Extract target process handle if available
        hProcess = params.get("hProcess", "")

        if hProcess:
            if hProcess not in process_sequences:
                process_sequences[hProcess] = []
            process_sequences[hProcess].append(api_name)

    # Check for injection patterns
    for handle, sequence in process_sequences.items():
        # Classic injection pattern
        if _matches_classic_injection(sequence):
            matches.append(
                TechniqueMatch(
                    technique_id="T1055.001",
                    technique_name="Dynamic-link Library Injection",
                    tactic="defense-evasion",
                    confidence="high",
                    confidence_score=0.95,
                    evidence_count=len(sequence),
                )
            )

        # Process hollowing pattern
        if _matches_process_hollowing(sequence):
            matches.append(
                TechniqueMatch(
                    technique_id="T1055.012",
                    technique_name="Process Hollowing",
                    tactic="defense-evasion",
                    confidence="high",
                    confidence_score=0.95,
                    evidence_count=len(sequence),
                )
            )

    return matches


def detect_persistence_pattern(api_calls: list[Any]) -> list[TechniqueMatch]:
    """
    Detect persistence patterns from API call sequences.

    Patterns detected:
    - Registry Run key persistence: RegOpenKey(Run) → RegSetValueEx
    - Service persistence: CreateService → StartService

    Args:
        api_calls: List of APICallRecord objects

    Returns:
        List of TechniqueMatch objects for detected patterns
    """
    matches = []

    # Track registry operations
    registry_ops: list[tuple[datetime, str, dict]] = []
    service_ops: list[tuple[datetime, str, dict]] = []

    for call in api_calls:
        api_name = call.api_name or ""
        params = call.params or {}

        if api_name.startswith("Reg"):
            registry_ops.append((call.timestamp, api_name, params))
        elif api_name in ("CreateServiceA", "CreateServiceW", "StartServiceA"):
            service_ops.append((call.timestamp, api_name, params))

    # Check for registry persistence
    if _matches_registry_persistence(registry_ops):
        matches.append(
            TechniqueMatch(
                technique_id="T1547.001",
                technique_name="Registry Run Keys / Startup Folder",
                tactic="persistence",
                confidence="high",
                confidence_score=0.9,
                evidence_count=len(registry_ops),
            )
        )

    # Check for service persistence
    if _matches_service_persistence(service_ops):
        matches.append(
            TechniqueMatch(
                technique_id="T1543.003",
                technique_name="Windows Service",
                tactic="persistence",
                confidence="high",
                confidence_score=0.9,
                evidence_count=len(service_ops),
            )
        )

    return matches


def _matches_classic_injection(sequence: list[str]) -> bool:
    """Check if sequence matches classic injection pattern."""
    required = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]

    # Check if all required APIs are present in order
    indices = []
    for api in required:
        try:
            idx = sequence.index(api)
            indices.append(idx)
        except ValueError:
            return False

    # Verify order
    return indices == sorted(indices)


def _matches_process_hollowing(sequence: list[str]) -> bool:
    """Check if sequence matches process hollowing pattern."""
    required = [
        "CreateProcessA",
        "NtUnmapViewOfSection",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "SetThreadContext",
    ]

    # Check if all required APIs are present in order
    indices = []
    for api in required:
        try:
            idx = sequence.index(api)
            indices.append(idx)
        except ValueError:
            return False

    # Verify order
    return indices == sorted(indices)


def _matches_registry_persistence(ops: list[tuple[datetime, str, dict]]) -> bool:
    """Check if registry operations indicate persistence."""
    # Look for Run key access followed by value set
    run_key_accessed = False

    for _, api_name, params in ops:
        if api_name in ("RegOpenKeyExA", "RegOpenKeyExW"):
            sub_key = params.get("lpSubKey", "").lower()
            if "run" in sub_key or "runonce" in sub_key:
                run_key_accessed = True

        if api_name in ("RegSetValueExA", "RegSetValueExW") and run_key_accessed:
            return True

    return False


def _matches_service_persistence(ops: list[tuple[datetime, str, dict]]) -> bool:
    """Check if service operations indicate persistence."""
    service_created = False

    for _, api_name, _ in ops:
        if api_name.startswith("CreateService"):
            service_created = True

        if api_name.startswith("StartService") and service_created:
            return True

    return False
