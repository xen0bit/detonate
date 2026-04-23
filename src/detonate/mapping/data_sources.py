"""MITRE ATT&CK data source mappings for detection opportunities.

This module provides data source and data component mappings for techniques,
loaded dynamically from the STIX 2.1 enterprise-attack.json file. It indexes
all 38 data sources and 109 data components.

Data sources represent categories of information that can be collected
(e.g., Process, File, Network Traffic). Data components are specific types
of events or data within a source (e.g., Process Creation, File Creation).
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
            _stix_store = STIXDataStore()
    return _stix_store


def get_data_sources_for_technique(technique_id: str) -> list[dict[str, Any]]:
    """
    Return list of data sources for detecting a given technique.

    Maps techniques to relevant data sources and components based on
    ATT&CK detection guidance. Falls back to parent technique for
    sub-techniques if no direct mapping exists.

    Args:
        technique_id: ATT&CK technique ID (e.g., "T1055.001")

    Returns:
        List of data source dictionaries. Empty list if none found.

    Example:
        >>> sources = get_data_sources_for_technique("T1055.001")
        >>> for ds in sources:
        ...     print(f"{ds['source_id']}: {ds['source_name']} - {ds['component_name']}")
    """
    store = get_stix_store()

    # Try technique-specific mapping first
    if technique_id in TECHNIQUE_TO_DATA_SOURCE:
        return _enrich_data_sources(TECHNIQUE_TO_DATA_SOURCE[technique_id], store)

    # Fall back to parent technique for sub-techniques
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in TECHNIQUE_TO_DATA_SOURCE:
            return _enrich_data_sources(TECHNIQUE_TO_DATA_SOURCE[parent_id], store)

    # Fallback based on technique category
    category = _get_technique_category(technique_id)
    if category in CATEGORY_TO_DATA_SOURCE:
        return _enrich_data_sources(CATEGORY_TO_DATA_SOURCE[category], store)

    return []


def _enrich_data_sources(
    source_list: list[dict[str, str]], store: STIXDataStore
) -> list[dict[str, Any]]:
    """
    Enrich data source references with full metadata from STIX store.

    Args:
        source_list: List of dicts with source_id and component_id
        store: STIX data store

    Returns:
        List of enriched data source dictionaries
    """
    enriched = []
    for item in source_list:
        source_id = item.get("source_id")
        component_id = item.get("component_id")

        # Get data source metadata
        source_data = store.data_sources.get(source_id, {})
        component_data = store.data_components.get(component_id, {})

        if source_data or component_data:
            enriched.append({
                "source_id": source_id,
                "source_name": source_data.get("name", item.get("source_name", "")),
                "component_id": component_id,
                "component_name": component_data.get("name", item.get("component_name", "")),
                "description": component_data.get("description", item.get("description", "")),
                "stix_refs": {
                    "data_source": source_data.get("stix_id", ""),
                    "data_component": component_data.get("stix_id", ""),
                },
            })
        else:
            # Use provided names if STIX data not available
            enriched.append({
                "source_id": source_id,
                "source_name": item.get("source_name", ""),
                "component_id": component_id,
                "component_name": item.get("component_name", ""),
                "description": item.get("description", ""),
                "stix_refs": {},
            })

    return enriched


def _get_technique_category(technique_id: str) -> str:
    """
    Infer technique category from ID for fallback mappings.

    Uses explicit technique ID prefix lists per category for accurate matching.
    Falls back to tactic-based lookup from STIX data when ID prefix is unrecognized.

    Args:
        technique_id: ATT&CK technique ID

    Returns:
        Category string or 'unknown'
    """
    # Normalize to parent technique ID (strip sub-technique suffix)
    parent_id = technique_id.split(".")[0] if "." in technique_id else technique_id

    # ========================================================================
    # EXECUTION - T1053, T1055, T1059, T1106, T1204
    # ========================================================================
    if parent_id in ("T1053", "T1055", "T1059", "T1106", "T1204"):
        return "execution"

    # ========================================================================
    # PERSISTENCE - T1053, T1543, T1546, T1547, T1548
    # ========================================================================
    if parent_id in ("T1543", "T1546", "T1547", "T1548"):
        return "persistence"

    # ========================================================================
    # PRIVILEGE ESCALATION - T1134, T1548, T1611
    # ========================================================================
    if parent_id in ("T1134", "T1548", "T1611"):
        return "privilege_escalation"

    # ========================================================================
    # DEFENSE EVASION - T1027, T1036, T1055, T1070, T1134, T1548, T1564
    # ========================================================================
    if parent_id in ("T1027", "T1036", "T1055", "T1070", "T1134", "T1548", "T1564"):
        return "defense_evasion"

    # ========================================================================
    # CREDENTIAL ACCESS - T1003, T1552, T1555, T1556, T1557, T1558
    # ========================================================================
    if parent_id in ("T1003", "T1552", "T1555", "T1556", "T1557", "T1558"):
        return "credential_access"

    # ========================================================================
    # DISCOVERY - T1012, T1016, T1018, T1033, T1040, T1046, T1049, T1057,
    #             T1069, T1078, T1082, T1083, T1087, T1120, T1124, T1135,
    #             T1201, T1217
    # ========================================================================
    if parent_id in (
        "T1012", "T1016", "T1018", "T1033", "T1040", "T1046", "T1049",
        "T1057", "T1069", "T1078", "T1082", "T1083", "T1087", "T1120",
        "T1124", "T1135", "T1201", "T1217"
    ):
        return "discovery"

    # ========================================================================
    # LATERAL MOVEMENT - T1021, T1028, T1534, T1550, T1563, T1570
    # ========================================================================
    if parent_id in ("T1021", "T1028", "T1534", "T1550", "T1563", "T1570"):
        return "lateral_movement"

    # ========================================================================
    # COLLECTION - T1005, T1009, T1025, T1039, T1056, T1113, T1114, T1115,
    #              T1119, T1123, T1185, T1125
    # ========================================================================
    if parent_id in ("T1005", "T1009", "T1025", "T1039", "T1056", "T1113",
                     "T1114", "T1115", "T1119", "T1123", "T1185", "T1125"):
        return "collection"

    # ========================================================================
    # COMMAND AND CONTROL - T1001, T1008, T1010, T1024, T1029, T1030,
    #                       T1041, T1071, T1090, T1092, T1095, T1102,
    #                       T1104, T1105, T1132, T1219, T1568, T1573
    # ========================================================================
    if parent_id in ("T1001", "T1008", "T1010", "T1024", "T1029", "T1030",
                     "T1041", "T1071", "T1090", "T1092", "T1095", "T1102",
                     "T1104", "T1105", "T1132", "T1219", "T1568", "T1573"):
        return "command_and_control"

    # ========================================================================
    # EXFILTRATION - T1020, T1029, T1030, T1041, T1048, T1052
    # ========================================================================
    if parent_id in ("T1020", "T1029", "T1030", "T1041", "T1048", "T1052"):
        return "exfiltration"

    # ========================================================================
    # IMPACT - T1485, T1486, T1487, T1488, T1489, T1490, T1491, T1495,
    #          T1496, T1497, T1498, T1499, T1500
    # ========================================================================
    if parent_id in ("T1485", "T1486", "T1487", "T1488", "T1489", "T1490",
                     "T1491", "T1495", "T1496", "T1497", "T1498", "T1499", "T1500"):
        return "impact"

    # ========================================================================
    # INITIAL ACCESS - T1133, T1189, T1190, T1195, T1199, T1200
    # ========================================================================
    if parent_id in ("T1133", "T1189", "T1190", "T1195", "T1199", "T1200"):
        return "initial_access"

    # ========================================================================
    # FALLBACK: Query STIX data for tactic information
    # ========================================================================
    try:
        store = get_stix_store()
        technique_data = store.get_technique(technique_id)
        if technique_data:
            tactic = technique_data.get("tactic", "").lower()
            # Map tactic to category
            tactic_to_category = {
                "execution": "execution",
                "persistence": "persistence",
                "privilege-escalation": "privilege_escalation",
                "defense-evasion": "defense_evasion",
                "credential-access": "credential_access",
                "discovery": "discovery",
                "lateral-movement": "lateral_movement",
                "collection": "collection",
                "command-and-control": "command_and_control",
                "exfiltration": "exfiltration",
                "impact": "impact",
                "initial-access": "initial_access",
            }
            return tactic_to_category.get(tactic, "unknown")
    except Exception:
        pass  # Fall through to unknown

    return "unknown"


def get_all_data_sources() -> list[dict[str, Any]]:
    """
    Return all data sources from STIX data.

    Returns:
        List of all data source dictionaries.
    """
    store = get_stix_store()
    return list(store.data_sources.values())


def get_all_data_components() -> list[dict[str, Any]]:
    """
    Return all data components from STIX data.

    Returns:
        List of all data component dictionaries.
    """
    store = get_stix_store()
    return list(store.data_components.values())


def get_data_source(source_id: str) -> dict[str, Any] | None:
    """Get a specific data source by ID."""
    store = get_stix_store()
    return store.data_sources.get(source_id)


def get_data_component(component_id: str) -> dict[str, Any] | None:
    """Get a specific data component by ID."""
    store = get_stix_store()
    return store.data_components.get(component_id)


# Technique to data source mappings
# Based on ATT&CK v18.1 detection guidance
# Structure: {technique_id: [{"source_id": "DSxxx", "component_id": "DCxxx", ...}, ...]}

TECHNIQUE_TO_DATA_SOURCE: dict[str, list[dict[str, str]]] = {
    # ========================================================================
    # T1055 - Process Injection
    # ========================================================================
    "T1055.001": [
        {
            "source_id": "DS0009",
            "component_id": "DC0016",
            "description": "Monitor for DLL loading into unexpected processes.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0035",
            "description": "Monitor process memory access patterns.",
        },
    ],
    "T1055.012": [
        {
            "source_id": "DS0009",
            "component_id": "DC0032",
            "description": "Monitor for process creation with suspicious parent-child relationships.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor for process hollowing indicators.",
        },
    ],
    # ========================================================================
    # T1059 - Command and Scripting Interpreter
    # ========================================================================
    "T1059.001": [
        {
            "source_id": "DS0012",
            "component_id": "DC0029",
            "description": "Enable PowerShell script block logging.",
        },
        {
            "source_id": "DS0017",
            "component_id": "DC0064",
            "description": "Log PowerShell command line arguments.",
        },
    ],
    "T1059.003": [
        {
            "source_id": "DS0017",
            "component_id": "DC0053",
            "description": "Monitor command line execution.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0019",
            "description": "Monitor cmd.exe process creation.",
        },
    ],
    "T1059.005": [
        {
            "source_id": "DS0012",
            "component_id": "DC0061",
            "description": "Monitor VBScript execution.",
        },
    ],
    "T1059.007": [
        {
            "source_id": "DS0012",
            "component_id": "DC0061",
            "description": "Monitor JavaScript execution.",
        },
    ],
    # ========================================================================
    # T1003 - OS Credential Dumping
    # ========================================================================
    "T1003.001": [
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor for LSASS memory access.",
        },
        {
            "source_id": "DS0028",
            "component_id": "DC0084",
            "description": "Monitor for credential requests from unexpected processes.",
        },
    ],
    "T1003.002": [
        {
            "source_id": "DS0022",
            "component_id": "DC0046",
            "description": "Monitor for SAM file access.",
        },
    ],
    "T1003.008": [
        {
            "source_id": "DS0022",
            "component_id": "DC0046",
            "description": "Monitor for /etc/shadow and /etc/passwd access.",
        },
    ],
    # ========================================================================
    # T1070 - Indicator Removal
    # ========================================================================
    "T1070.001": [
        {
            "source_id": "DS0015",
            "component_id": "DC0062",
            "description": "Monitor for event log clearing.",
        },
    ],
    "T1070.003": [
        {
            "source_id": "DS0022",
            "component_id": "DC0047",
            "description": "Monitor for command history file deletion.",
        },
    ],
    "T1070.004": [
        {
            "source_id": "DS0022",
            "component_id": "DC0047",
            "description": "Monitor for file deletion activity.",
        },
    ],
    # ========================================================================
    # T1547 - Boot or Logon Autostart Execution
    # ========================================================================
    "T1547.001": [
        {
            "source_id": "DS0024",
            "component_id": "DC0063",
            "description": "Monitor registry run key modifications.",
        },
    ],
    # ========================================================================
    # T1543 - Create or Modify System Process
    # ========================================================================
    "T1543.003": [
        {
            "source_id": "DS0019",
            "component_id": "DC0060",
            "description": "Monitor Windows service creation.",
        },
    ],
    "T1543.002": [
        {
            "source_id": "DS0019",
            "component_id": "DC0060",
            "description": "Monitor systemd service creation.",
        },
    ],
    # ========================================================================
    # T1053 - Scheduled Task/Job
    # ========================================================================
    "T1053.005": [
        {
            "source_id": "DS0003",
            "component_id": "DC0001",
            "description": "Monitor scheduled task creation.",
        },
    ],
    "T1053.003": [
        {
            "source_id": "DS0003",
            "component_id": "DC0001",
            "description": "Monitor cron job creation.",
        },
    ],
    # ========================================================================
    # T1071 - Application Layer Protocol
    # ========================================================================
    "T1071.001": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor HTTP/HTTPS traffic patterns.",
        },
    ],
    # ========================================================================
    # T1486 - Data Encrypted for Impact
    # ========================================================================
    "T1486": [
        {
            "source_id": "DS0022",
            "component_id": "DC0061",
            "description": "Monitor for mass file modifications.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor for encryption process behavior.",
        },
    ],
    # ========================================================================
    # T1021 - Remote Services
    # ========================================================================
    "T1021.002": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor SMB traffic.",
        },
    ],
    "T1021.004": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor SSH connections.",
        },
    ],
    # ========================================================================
    # T1082 - System Information Discovery
    # ========================================================================
    "T1082": [
        {
            "source_id": "DS0009",
            "component_id": "DC0032",
            "description": "Monitor process execution for system enumeration.",
        },
        {
            "source_id": "DS0017",
            "component_id": "DC0064",
            "description": "Monitor command line arguments.",
        },
    ],
    # ========================================================================
    # T1012 - Query Registry
    # ========================================================================
    "T1012": [
        {
            "source_id": "DS0024",
            "component_id": "DC0050",
            "description": "Monitor registry query operations.",
        },
    ],
    # ========================================================================
    # T1083 - File and Directory Discovery
    # ========================================================================
    "T1083": [
        {
            "source_id": "DS0022",
            "component_id": "DC0055",
            "description": "Monitor file enumeration activity.",
        },
    ],
    # ========================================================================
    # T1135 - Network Share Discovery
    # ========================================================================
    "T1135": [
        {
            "source_id": "DS0033",
            "component_id": "DC0102",
            "description": "Monitor network share enumeration.",
        },
    ],
    # ========================================================================
    # T1115 - Clipboard Data
    # ========================================================================
    "T1115": [
        {
            "source_id": "DS0009",
            "component_id": "DC0035",
            "description": "Monitor process access to clipboard.",
        },
    ],
    # ========================================================================
    # T1048 - Exfiltration Over Alternative Protocol
    # ========================================================================
    "T1048": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor network traffic for exfiltration patterns.",
        },
    ],
    # ========================================================================
    # T1041 - Exfiltration Over C2 Channel
    # ========================================================================
    "T1041": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor C2 channel traffic.",
        },
    ],
    # ========================================================================
    # T1611 - Escape to Host (Container)
    # ========================================================================
    "T1611": [
        {
            "source_id": "DS0032",
            "component_id": "DC0091",
            "description": "Monitor container operations.",
        },
        {
            "source_id": "DS0008",
            "component_id": "DC0031",
            "description": "Monitor kernel-level operations.",
        },
    ],
    # ========================================================================
    # T1592.004 - Client Configuration Gathering: Cloud
    # ========================================================================
    "T1592.004": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor network traffic to cloud metadata endpoints.",
        },
    ],
    # ========================================================================
    # T1016 - System Network Configuration Discovery
    # ========================================================================
    "T1016": [
        {
            "source_id": "DS0009",
            "component_id": "DC0032",
            "description": "Monitor network enumeration commands.",
        },
    ],
    # ========================================================================
    # T1057 - Process Discovery
    # ========================================================================
    "T1057": [
        {
            "source_id": "DS0009",
            "component_id": "DC0034",
            "description": "Monitor process enumeration.",
        },
    ],
    # ========================================================================
    # T1134 - Access Token Manipulation
    # ========================================================================
    "T1134": [
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor token manipulation.",
        },
        {
            "source_id": "DS0028",
            "component_id": "DC0067",
            "description": "Monitor logon session anomalies.",
        },
    ],
    # ========================================================================
    # T1106 - Native API
    # ========================================================================
    "T1106": [
        {
            "source_id": "DS0009",
            "component_id": "DC0021",
            "description": "Monitor API usage patterns.",
        },
    ],
    # ========================================================================
    # T1005 - Data from Local System
    # ========================================================================
    "T1005": [
        {
            "source_id": "DS0022",
            "component_id": "DC0055",
            "description": "Monitor file access patterns.",
        },
    ],
}

# Category-based fallback mappings for techniques without explicit mappings
CATEGORY_TO_DATA_SOURCE: dict[str, list[dict[str, str]]] = {
    "process_injection": [
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor process memory modifications.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0035",
            "description": "Monitor process memory access patterns.",
        },
    ],
    "command_execution": [
        {
            "source_id": "DS0017",
            "component_id": "DC0053",
            "description": "Monitor command line execution.",
        },
        {
            "source_id": "DS0012",
            "component_id": "DC0061",
            "description": "Monitor script execution.",
        },
    ],
    "execution": [
        {
            "source_id": "DS0009",
            "component_id": "DC0019",
            "description": "Monitor process creation.",
        },
        {
            "source_id": "DS0017",
            "component_id": "DC0053",
            "description": "Monitor command line execution.",
        },
    ],
    "credential_access": [
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor for credential access attempts.",
        },
        {
            "source_id": "DS0028",
            "component_id": "DC0084",
            "description": "Monitor for credential requests.",
        },
    ],
    "persistence": [
        {
            "source_id": "DS0024",
            "component_id": "DC0074",
            "description": "Monitor persistence mechanism modifications.",
        },
        {
            "source_id": "DS0019",
            "component_id": "DC0060",
            "description": "Monitor service creation.",
        },
    ],
    "privilege_escalation": [
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor privilege escalation attempts.",
        },
        {
            "source_id": "DS0028",
            "component_id": "DC0067",
            "description": "Monitor logon session anomalies.",
        },
    ],
    "defense_evasion": [
        {
            "source_id": "DS0022",
            "component_id": "DC0047",
            "description": "Monitor indicator removal activity.",
        },
        {
            "source_id": "DS0015",
            "component_id": "DC0062",
            "description": "Monitor event log manipulation.",
        },
    ],
    "discovery": [
        {
            "source_id": "DS0009",
            "component_id": "DC0019",
            "description": "Monitor discovery command execution.",
        },
        {
            "source_id": "DS0017",
            "component_id": "DC0064",
            "description": "Monitor command line arguments.",
        },
    ],
    "lateral_movement": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor lateral movement traffic.",
        },
        {
            "source_id": "DS0028",
            "component_id": "DC0067",
            "description": "Monitor remote authentication.",
        },
    ],
    "collection": [
        {
            "source_id": "DS0022",
            "component_id": "DC0055",
            "description": "Monitor file access patterns.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0035",
            "description": "Monitor clipboard access.",
        },
    ],
    "command_and_control": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor network traffic patterns.",
        },
        {
            "source_id": "DS0029",
            "component_id": "DC0094",
            "description": "Monitor DNS queries.",
        },
    ],
    "exfiltration": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor network traffic for exfiltration.",
        },
        {
            "source_id": "DS0022",
            "component_id": "DC0055",
            "description": "Monitor large file transfers.",
        },
    ],
    "impact": [
        {
            "source_id": "DS0022",
            "component_id": "DC0061",
            "description": "Monitor file modifications.",
        },
        {
            "source_id": "DS0009",
            "component_id": "DC0020",
            "description": "Monitor destructive process behavior.",
        },
    ],
    "initial_access": [
        {
            "source_id": "DS0029",
            "component_id": "DC0082",
            "description": "Monitor inbound network connections.",
        },
        {
            "source_id": "DS0015",
            "component_id": "DC0062",
            "description": "Monitor application logs for exploitation.",
        },
    ],
    "unknown": [
        {
            "source_id": "DS0009",
            "component_id": "DC0019",
            "description": "Monitor process execution.",
        },
    ],
}
