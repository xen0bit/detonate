# detonate ATT&CK & STIX Enhancement Plan

**Document Version:** 1.0  
**Created:** 2025-04-23  
**Status:** Approved for Implementation  
**Priority:** Depth-First, Then Breadth

---

## Executive Summary

This document outlines a comprehensive plan to enhance detonate's MITRE ATT&CK mapping and STIX 2.1 output capabilities. Based on deep research into the ATT&CK v18.1 knowledge base (24,769 STIX objects across 16 object types) and OASIS CTI specifications, this plan will significantly expand detonate's threat intelligence output while maintaining accuracy.

**Current State:**
- Maps 42 Windows APIs + 26 Linux syscalls to ATT&CK techniques
- Generates STIX bundles with Malware, AttackPattern, Relationship, ObservedData objects
- Confidence scoring with evidence accumulation
- Pattern detection for injection/persistence chains

**Target State:**
- 80+ Windows APIs + 60+ Linux syscalls mapped
- Full sub-technique granularity (T1059.001 vs T1059)
- Mitigation recommendations (268 course-of-action objects)
- Data source/detection opportunities (38 sources + 109 components)
- STIX Indicator generation with pattern matching
- Infrastructure tracking for C2 servers
- Live CVE lookups via NVD API
- Threat actor attribution (187 intrusion-sets)
- Campaign linkage (52 campaigns)

---

## Design Principles

1. **Depth Before Breadth:** Perfect core technique mapping before expanding to new object types
2. **Accuracy Over Coverage:** Prefer fewer high-confidence detections over many low-confidence ones
3. **ENV-Controlled Features:** All optional features toggled via environment variables
4. **STIX 2.1 Compliance:** All output conforms to OASIS STIX 2.1 specification
5. **Backward Compatible:** Existing functionality unchanged; new features additive only

---

## Implementation Phases

### Phase 1: Deepen Core Technique Mapping (CRITICAL)

**Timeline:** 2-3 weeks  
**Dependencies:** None  
**Owner:** Core Team

#### 1.1 Expand Windows API Coverage

**Current:** 42 APIs mapped  
**Target:** 80 APIs covering top 200 techniques by prevalence

**New APIs to Map:**

| Category | APIs | Techniques | Priority |
|----------|------|------------|----------|
| Credential Access | `CredEnumerateA/W`, `CredReadW`, `SamIConnect`, `LsaOpenPolicy`, `LsaQueryInformationPolicy` | T1003.001 (LSASS), T1003.002 (SAM), T1003.004 (LSA Secrets) | P0 |
| Discovery | `GetSystemInfo`, `GetVersionExA/W`, `NetShareEnum`, `NetGetJoinInformation`, `DsGetDcNameW` | T1082, T1135, T1083 | P0 |
| Lateral Movement | `WNetAddConnection2W`, `CreateProcessWithLogonW`, `ImpersonateLoggedOnUser` | T1021.002, T1021.003 | P0 |
| Persistence | `SchTasksCreate`, `RegCreateKeyExW`, `CreateServiceW` | T1053.005, T1547.001, T1543.003 | P0 |
| Defense Evasion | `SetFileTime`, `RemoveDirectoryA/W`, `ClearEventLogA`, `BackupEventLogA` | T1070.003, T1070.004 | P1 |
| Execution | `CreateProcessWithTokenW`, `ShellExecuteExW`, `WinExec` | T1059.003, T1059.001 | P1 |
| Collection | `FindFirstFileA/W`, `FindNextFileA`, `GetClipboardData` | T1005, T1115 | P1 |
| Exfiltration | `InternetOpenUrlA`, `HttpSendRequestA`, `FtpPutFileA` | T1041, T1048 | P2 |
| Impact | `CryptEncrypt`, `CryptDecrypt`, `DeleteFileW` | T1486, T1070.004 | P2 |

**File Changes:**
- `src/detonate/mapping/windows_map.py` - Add ~40 new API mappings
- `src/detonate/core/hooks/windows.py` - Add hook implementations for new APIs
- `src/detonate/mapping/engine.py` - Support sub-technique inheritance

**Sub-technique Granularity:**

Current issue: Many mappings use parent technique IDs only.

```python
# BEFORE (windows_map.py line 8)
"CreateProcessA": {
    "technique_id": "T1106",  # Native API - parent only
    "technique_name": "Native API",
    ...
}

# AFTER
"CreateProcessA": {
    "technique_id": "T1059.003",  # Windows Command Shell - sub-technique
    "technique_name": "Windows Command Shell",
    "param_checks": {
        "lpCommandLine": {
            "powershell": {
                "id": "T1059.001",  # PowerShell - more specific
                "name": "PowerShell",
                ...
            }
        }
    }
}
```

**Acceptance Criteria:**
- [ ] All 40 new APIs have mappings in `windows_map.py`
- [ ] Hook implementations exist in `hooks/windows.py`
- [ ] Unit tests pass for all new hooks (synthesized call tests)
- [ ] Sub-technique IDs used where applicable (not parent-only)
- [ ] Parameter-based refinement for high-confidence matches

#### 1.2 Expand Linux Syscall Coverage

**Current:** 26 syscalls mapped  
**Target:** 60 syscalls

**New Syscalls to Map:**

| Category | Syscalls | Techniques | Priority |
|----------|----------|------------|----------|
| Credential Access | `openat` (/etc/shadow), `getuid`, `geteuid`, `setresuid` | T1003.008, T1548.001 | P0 |
| Discovery | `uname`, `getcwd`, `readlink`, `gethostname`, `sysinfo` | T1082, T1083, T1016 | P0 |
| Container Escape | `mount`, `umount`, `pivot_root`, `unshare` | T1611 | P0 |
| Cloud Metadata | `socket` (169.254.169.254), `connect` (metadata API) | T1592.004 | P0 |
| Persistence | `openat` (cron), `openat` (systemd unit) | T1053.003, T1543.002 | P1 |
| Defense Evasion | `unlinkat`, `renameat2`, `fadvise64` (clear cache) | T1070.004, T1070.003 | P1 |
| Lateral Movement | `ssh` via `execve`, `scp` file access | T1021.004 | P1 |
| Collection | `read`, `pread64`, `splice` | T1005 | P2 |
| Exfiltration | `sendto`, `sendmsg`, `write` (network socket) | T1041 | P2 |

**File Changes:**
- `src/detonate/mapping/linux_map.py` - Add ~35 new syscall mappings
- `src/detonate/core/hooks/linux.py` - Add hook implementations
- `src/detonate/mapping/engine.py` - Support platform-specific confidence adjustments

**Special Considerations for Linux:**

1. **Container Detection:** Flag syscalls that suggest container escape attempts
2. **Cloud Metadata:** Detect access to cloud provider metadata endpoints
3. **File Path Analysis:** Enhance parameter checks for sensitive file paths

```python
# linux_map.py - Enhanced parameter checks
"openat": {
    "technique_id": "T1005",
    "param_checks": {
        "pathname": {
            "/etc/shadow": {
                "id": "T1003.008",
                "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                "tactic": "credential-access",
                "confidence": 0.95  # Higher confidence for shadow file
            },
            "/proc/self/environ": {
                "id": "T1057",
                "name": "Process Discovery",
                "tactic": "discovery",
                "confidence": 0.8
            },
            "/var/run/docker.sock": {
                "id": "T1611",
                "name": "Escape to Host",
                "tactic": "privilege-escalation",
                "confidence": 0.9
            }
        }
    }
}
```

**Acceptance Criteria:**
- [ ] All 35 new syscalls have mappings in `linux_map.py`
- [ ] Hook implementations exist in `hooks/linux.py`
- [ ] Unit tests pass for all new hooks
- [ ] Container escape patterns detected
- [ ] Cloud metadata access detected (AWS, GCP, Azure endpoints)

#### 1.3 Confidence Calibration

**Goal:** Ensure confidence scores accurately reflect detection reliability

**Calibration Rules:**

| Detection Type | Base Score | Evidence Boost | Max Score |
|----------------|------------|----------------|-----------|
| Direct API match (no params) | 0.5 | +0.1 per evidence | 0.7 |
| Parameter keyword match | 0.8 | +0.05 per evidence | 0.95 |
| Pattern-based (multi-call) | 0.85 | Fixed | 0.95 |
| RWX memory allocation | 0.6 | +0.2 if remote process | 0.95 |
| Sub-technique specificity | +0.1 | N/A | 1.0 |

**Implementation:**
```python
# src/detonate/mapping/engine.py
class TechniqueMatch:
    def add_evidence(self) -> None:
        """Increment evidence count and recalculate confidence."""
        self.evidence_count += 1
        # Diminishing returns formula
        import math
        boost = math.log(self.evidence_count + 1) / math.log(10)
        self.confidence_score = min(
            self.max_confidence,  # Cap at technique-specific maximum
            self.confidence_score + boost * 0.1
        )
        self.confidence = self._score_to_label(self.confidence_score)
```

**Acceptance Criteria:**
- [ ] Confidence scores calibrated against test cases
- [ ] Evidence accumulation uses diminishing returns
- [ ] Sub-technique matches receive +0.1 bonus
- [ ] Pattern-based detections capped at 0.95

---

### Phase 2: Mitigation & Data Source Mapping (HIGH)

**Timeline:** 2 weeks  
**Dependencies:** Phase 1 complete, STIX data loaded  
**Owner:** Intelligence Team

#### 2.1 Mitigation Recommendations

**Data Source:** 268 course-of-action objects from `enterprise-attack.json`

**Implementation:**

```python
# New file: src/detonate/mapping/mitigations.py
"""MITRE ATT&CK mitigation mappings."""

TECHNIQUE_TO_MITIGATION = {
    "T1055.001": [
        {
            "mitigation_id": "M1042",
            "name": "Disable or Remove Feature or Program",
            "description": "Remove or disable software that can be used to inject malicious code into processes.",
            "stix_id": "course-of-action--ae18c07a-...",
            "url": "https://attack.mitre.org/mitigations/M1042"
        },
        {
            "mitigation_id": "M1040",
            "name": "Behavior Prevention on Endpoint",
            "description": "Behavioral detection systems can monitor process injection activity...",
            "stix_id": "course-of-action--...",
            "url": "https://attack.mitre.org/mitigations/M1040"
        }
    ],
    "T1059.001": [
        {
            "mitigation_id": "M1049",
            "name": "Antivirus/Antimalware",
            "description": "Use antivirus or antimalware tools to detect and block PowerShell-based attacks.",
            "stix_id": "course-of-action--...",
            "url": "https://attack.mitre.org/mitigations/M1049"
        },
        {
            "mitigation_id": "M1054",
            "name": "Script Blocking",
            "description": "Scripts are a common method of execution for adversaries...",
            "stix_id": "course-of-action--...",
            "url": "https://attack.mitre.org/mitigations/M1054"
        }
    ],
    # ... mappings for all detected techniques
}

def get_mitigations_for_technique(technique_id: str) -> list[dict]:
    """Return list of mitigations for a given technique."""
    return TECHNIQUE_TO_MITIGATION.get(technique_id, [])

def get_all_mitigations() -> list[dict]:
    """Return all unique mitigations."""
    all_mitigations = []
    seen_ids = set()
    for mitigation_list in TECHNIQUE_TO_MITIGATION.values():
        for mitigation in mitigation_list:
            if mitigation["mitigation_id"] not in seen_ids:
                all_mitigations.append(mitigation)
                seen_ids.add(mitigation["mitigation_id"])
    return all_mitigations
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from stix2 import CourseOfAction, Relationship

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Add CourseOfAction objects
    created_mitigations = {}
    for finding in findings:
        mitigations = get_mitigations_for_technique(finding.technique_id)
        for mitigation_data in mitigations:
            if mitigation_data["mitigation_id"] not in created_mitigations:
                coa = CourseOfAction(
                    id=mitigation_data["stix_id"],
                    name=mitigation_data["name"],
                    description=mitigation_data["description"],
                    external_references=[{
                        "source_name": "mitre-attack",
                        "external_id": mitigation_data["mitigation_id"],
                        "url": mitigation_data["url"]
                    }]
                )
                created_mitigations[mitigation_data["mitigation_id"]] = coa
                objects.append(coa)
            
            # Create mitigates relationship
            relationship = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="mitigates",
                source_ref=created_mitigations[mitigation_data["mitigation_id"]].id,
                target_ref=created_patterns[finding.technique_id].id
            )
            objects.append(relationship)
```

**Markdown Report Enhancement:**

```python
# src/detonate/output/report.py
def generate_markdown_report(...):
    # ... existing sections ...
    
    # NEW: Recommended Defenses section
    f.write("## Recommended Defenses\n\n")
    f.write("The following mitigations are recommended based on detected techniques:\n\n")
    
    mitigations_seen = {}
    for finding in findings:
        for mitigation in get_mitigations_for_technique(finding.technique_id):
            if mitigation["mitigation_id"] not in mitigations_seen:
                mitigations_seen[mitigation["mitigation_id"]] = mitigation
                f.write(f"### {mitigation['name']} ({mitigation['mitigation_id']})\n")
                f.write(f"{mitigation['description']}\n\n")
                f.write(f"[Learn more]({mitigation['url']})\n\n")
```

**Acceptance Criteria:**
- [ ] `mitigations.py` created with mappings for all 268 course-of-action objects
- [ ] STIX bundles include `CourseOfAction` objects
- [ ] `mitigates` relationships created (mitigation → technique)
- [ ] Markdown reports include "Recommended Defenses" section
- [ ] Unit tests verify mitigation lookup functionality

#### 2.2 Data Source Mapping

**Data Source:** 38 data sources + 109 data components from STIX data

**Implementation:**

```python
# New file: src/detonate/mapping/data_sources.py
"""MITRE ATT&CK data source mappings for detection opportunities."""

TECHNIQUE_TO_DATA_SOURCE = {
    "T1055.001": [
        {
            "source_id": "DS0009",
            "source_name": "Process Monitoring",
            "component_id": "DC0001",
            "component_name": "Process Injection Detection",
            "description": "Monitor process creation and memory allocation patterns for injection indicators.",
            "stix_refs": {
                "data_source": "x-mitre-data-source--969e530f-...",
                "data_component": "x-mitre-data-component--..."
            }
        },
        {
            "source_id": "DS0011",
            "source_name": "Windows Registry",
            "component_id": "DC0002",
            "component_name": "Registry Key Creation",
            "description": "Monitor registry keys commonly used for persistence via injection.",
            "stix_refs": {...}
        }
    ],
    "T1059.001": [
        {
            "source_id": "DS0012",
            "source_name": "Script Logs",
            "component_id": "DC0003",
            "component_name": "PowerShell Script Block Logging",
            "description": "Enable PowerShell script block logging to capture malicious commands.",
            "stix_refs": {...}
        },
        {
            "source_id": "DS0013",
            "source_name": "Command Logs",
            "component_id": "DC0004",
            "component_name": "Command Line Interface",
            "description": "Log command line arguments for PowerShell execution.",
            "stix_refs": {...}
        }
    ]
}

def get_data_sources_for_technique(technique_id: str) -> list[dict]:
    """Return list of data sources for a given technique."""
    return TECHNIQUE_TO_DATA_SOURCE.get(technique_id, [])
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from stix2 import Bundle

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Add data source and data component objects
    created_sources = {}
    created_components = {}
    
    for finding in findings:
        data_sources = get_data_sources_for_technique(finding.technique_id)
        for ds_data in data_sources:
            # Create data source if not exists
            if ds_data["source_id"] not in created_sources:
                source = {
                    "type": "x-mitre-data-source",
                    "id": ds_data["stix_refs"]["data_source"],
                    "spec_version": "2.1",
                    "name": ds_data["source_name"],
                    "description": f"Data source for detecting {finding.technique_name}",
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": ds_data["source_id"]
                    }]
                }
                created_sources[ds_data["source_id"]] = source
                objects.append(source)
            
            # Create data component if not exists
            if ds_data["component_id"] not in created_components:
                component = {
                    "type": "x-mitre-data-component",
                    "id": ds_data["stix_refs"]["data_component"],
                    "spec_version": "2.1",
                    "name": ds_data["component_name"],
                    "description": ds_data["description"],
                    "data_source_ref": ds_data["stix_refs"]["data_source"]
                }
                created_components[ds_data["component_id"]] = component
                objects.append(component)
```

**Markdown Report Enhancement:**

```python
# src/detonate/output/report.py
def generate_markdown_report(...):
    # ... existing sections ...
    
    # NEW: Detection Opportunities section
    f.write("## Detection Opportunities\n\n")
    f.write("The following data sources can be used to detect the observed behavior:\n\n")
    
    data_sources_seen = {}
    for finding in findings:
        for ds in get_data_sources_for_technique(finding.technique_id):
            key = f"{ds['source_id']}:{ds['component_id']}"
            if key not in data_sources_seen:
                data_sources_seen[key] = ds
                f.write(f"### {ds['source_name']} - {ds['component_name']}\n")
                f.write(f"{ds['description']}\n\n")
                f.write(f"**Data Source ID:** `{ds['source_id']}`  \n")
                f.write(f"**Data Component ID:** `{ds['component_id']}`\n\n")
```

**Acceptance Criteria:**
- [ ] `data_sources.py` created with mappings for all techniques
- [ ] STIX bundles include `x-mitre-data-source` and `x-mitre-data-component` objects
- [ ] Markdown reports include "Detection Opportunities" section
- [ ] Unit tests verify data source lookup functionality

---

### Phase 3: Enhanced STIX 2.1 Features (MEDIUM)

**Timeline:** 3 weeks  
**Dependencies:** Phase 1 & 2 complete  
**Owner:** Engineering Team

#### 3.1 STIX Indicator Generation

**Environment Variable:** `DETONATE_GENERATE_INDICATORS` (default: `false`)

**Implementation:**

```python
# New file: src/detonate/output/indicators.py
"""STIX 2.1 Indicator generation from observed API calls."""

import os
from stix2 import Indicator
from datetime import datetime, timezone

def should_generate_indicators() -> bool:
    """Check if indicator generation is enabled."""
    return os.getenv("DETONATE_GENERATE_INDICATORS", "false").lower() == "true"

def generate_indicator_from_api_call(api_call: APICallRecord) -> Indicator | None:
    """
    Generate STIX Indicator from a single API call.
    
    Returns None if no indicator can be generated.
    """
    if not should_generate_indicators():
        return None
    
    api_name = api_call.api_name or api_call.syscall_name
    params = api_call.params or {}
    
    # Process execution indicators
    if api_name in ("CreateProcessA", "CreateProcessW"):
        cmd_line = params.get("lpCommandLine", "")
        if cmd_line:
            # PowerShell detection
            if "powershell" in cmd_line.lower():
                pattern = f"[process:command_line MATCH '(?i).*powershell.*']"
                return _create_indicator(
                    pattern=pattern,
                    name="PowerShell Execution Detected",
                    description=f"Detected PowerShell execution via {api_name}",
                    confidence=_calculate_confidence(api_call)
                )
            # Command shell detection
            elif "cmd.exe" in cmd_line.lower() or "cmd /c" in cmd_line.lower():
                pattern = f"[process:command_line MATCH '(?i).*cmd\\\\.exe.*']"
                return _create_indicator(
                    pattern=pattern,
                    name="Command Shell Execution Detected",
                    description=f"Detected cmd.exe execution via {api_name}",
                    confidence=_calculate_confidence(api_call)
                )
    
    # Registry persistence indicators
    if api_name in ("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"):
        sub_key = params.get("lpSubKey", "") or params.get("lpValueName", "")
        if sub_key and "run" in sub_key.lower():
            pattern = f"[windows-registry-key:key MATCH '(?i).*\\\\CurrentVersion\\\\Run.*']"
            return _create_indicator(
                pattern=pattern,
                name="Registry Run Key Persistence",
                description=f"Detected registry persistence via {api_name}",
                confidence=_calculate_confidence(api_call)
            )
    
    # Network C2 indicators
    if api_name in ("InternetConnectA", "HttpOpenRequestA", "socket", "connect"):
        server = params.get("lpszServerName", "") or params.get("server", "")
        if server and not server.startswith("127."):
            # Domain or IP indicator
            if "." in server:
                pattern = f"[network-traffic:dst_ref.value = '{server}']"
                return _create_indicator(
                    pattern=pattern,
                    name=f"C2 Communication: {server}",
                    description=f"Detected network connection to {server}",
                    confidence=_calculate_confidence(api_call)
                )
    
    # File creation indicators (suspicious paths)
    if api_name in ("CreateFileA", "CreateFileW", "open", "openat"):
        file_path = params.get("lpFileName", "") or params.get("filename", "") or params.get("pathname", "")
        if file_path:
            # Check for suspicious paths
            suspicious_paths = ["/etc/shadow", "/etc/passwd", ".ssh/id_rsa", "AppData/Roaming"]
            if any(s in file_path for s in suspicious_paths):
                pattern = f"[file:name = '{file_path}']"
                return _create_indicator(
                    pattern=pattern,
                    name=f"Suspicious File Access: {file_path}",
                    description=f"Detected access to sensitive file {file_path}",
                    confidence=_calculate_confidence(api_call)
                )
    
    return None

def _create_indicator(pattern: str, name: str, description: str, confidence: float) -> Indicator:
    """Create a STIX Indicator object."""
    return Indicator(
        id=f"indicator--{uuid.uuid4()}",
        spec_version="2.1",
        created=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        name=name,
        description=description,
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.now(timezone.utc),
        indicator_types=["malicious-activity"],
        confidence=confidence,
        object_marking_refs=["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"]
    )

def _calculate_confidence(api_call: APICallRecord) -> int:
    """Calculate confidence score (0-100) for indicator."""
    base_confidence = 50
    
    # Boost for high-confidence technique matches
    if api_call.confidence == "high":
        base_confidence = 80
    elif api_call.confidence == "medium":
        base_confidence = 65
    
    # Boost for multiple evidence items
    # (Would need to track evidence count in session)
    
    return min(100, base_confidence)

def generate_indicators_for_session(session: AnalysisSession) -> list[Indicator]:
    """Generate all indicators for an analysis session."""
    indicators = []
    
    for api_call in session.api_calls:
        indicator = generate_indicator_from_api_call(api_call)
        if indicator:
            indicators.append(indicator)
    
    return indicators
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from .indicators import should_generate_indicators, generate_indicators_for_session

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Add indicators if enabled
    if should_generate_indicators():
        indicators = generate_indicators_for_session(session)
        objects.extend(indicators)
        
        # Create 'indicates' relationships (indicator → malware)
        for indicator in indicators:
            relationship = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware_id,
                description="This indicator was observed during analysis of the malware sample"
            )
            objects.append(relationship)
```

**Acceptance Criteria:**
- [ ] `indicators.py` created with pattern generation logic
- [ ] ENV var `DETONATE_GENERATE_INDICATORS` controls feature
- [ ] STIX bundles include `Indicator` objects when enabled
- [ ] `indicates` relationships created (indicator → malware)
- [ ] Unit tests for pattern generation from various API calls

#### 3.2 Infrastructure Objects

**Implementation:**

```python
# src/detonate/core/session.py
from dataclasses import dataclass, field
from typing import Any

@dataclass
class InfrastructureRecord:
    """Record of infrastructure observed during analysis."""
    name: str
    infrastructure_types: list[str]
    first_seen: datetime
    last_seen: datetime
    related_api_calls: list[APICallRecord] = field(default_factory=list)
    confidence: str = "medium"

class AnalysisSession:
    # ... existing fields ...
    infrastructure: list[InfrastructureRecord] = field(default_factory=list)
    
    def add_infrastructure(
        self,
        name: str,
        infrastructure_types: list[str],
        related_api_call: APICallRecord
    ) -> None:
        """Add or update infrastructure record."""
        # Check if infrastructure already exists
        for infra in self.infrastructure:
            if infra.name == name:
                infra.related_api_calls.append(related_api_call)
                infra.last_seen = related_api_call.timestamp
                return
        
        # Create new record
        self.infrastructure.append(InfrastructureRecord(
            name=name,
            infrastructure_types=infrastructure_types,
            first_seen=related_api_call.timestamp,
            last_seen=related_api_call.timestamp,
            related_api_calls=[related_api_call],
            confidence=related_api_call.confidence or "medium"
        ))
```

**Hook Integration:**

```python
# src/detonate/core/hooks/windows.py
def hook_InternetConnectA(self, ql: Any) -> None:
    """Hook InternetConnectA for C2 infrastructure detection."""
    lpszServerName = ql.os.f_param_read(1)
    server_name = ql.mem.string(lpszServerName) if lpszServerName else ""
    
    params = {"lpszServerName": server_name}
    record = self._record_api_call("InternetConnectA", params)
    
    # NEW: Track infrastructure
    if server_name and not server_name.startswith("127."):
        self.session.add_infrastructure(
            name=f"C2 Server: {server_name}",
            infrastructure_types=["command-and-control"],
            related_api_call=record
        )
    
    # ... existing technique detection code ...
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from stix2 import Infrastructure

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Add infrastructure objects
    for infra_record in session.infrastructure:
        infrastructure = Infrastructure(
            id=f"infrastructure--{uuid.uuid4()}",
            spec_version="2.1",
            name=infra_record.name,
            description=f"Infrastructure observed during malware analysis",
            infrastructure_types=infra_record.infrastructure_types,
            first_seen=infra_record.first_seen,
            last_seen=infra_record.last_seen,
            confidence=infra_record.confidence
        )
        objects.append(infrastructure)
        
        # Create 'consists-of' relationship (infrastructure → observable)
        # And 'related-to' relationship (malware → infrastructure)
        relationship = Relationship(
            id=f"relationship--{uuid.uuid4()}",
            relationship_type="controls",
            source_ref=malware_id,
            target_ref=infrastructure.id,
            description="Malware communicated with this infrastructure"
        )
        objects.append(relationship)
```

**Acceptance Criteria:**
- [ ] `InfrastructureRecord` dataclass added to session
- [ ] Network hooks track infrastructure
- [ ] STIX bundles include `Infrastructure` objects
- [ ] `controls` relationships created (malware → infrastructure)
- [ ] Unit tests for infrastructure tracking

#### 3.3 Live CVE Lookup

**Environment Variables:**
- `DETONATE_CVE_LOOKUP` (default: `false`)
- `DETONATE_NVD_API_KEY` (optional, for higher rate limits)

**Implementation:**

```python
# New file: src/detonate/utils/cve_lookup.py
"""Live CVE lookup via NVD API."""

import os
import time
import requests
from typing import Optional
from functools import lru_cache

class CVELookup:
    """NVD API client with rate limiting and caching."""
    
    def __init__(self):
        self.enabled = os.getenv("DETONATE_CVE_LOOKUP", "false").lower() == "true"
        self.api_key = os.getenv("DETONATE_NVD_API_KEY")
        self.cache = {}
        self.last_request_time = 0
        self.min_request_interval = 0.6  # 5 requests per 30 seconds without API key
        
        if self.api_key:
            self.min_request_interval = 0.06  # 50 requests per 30 seconds with API key
    
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
        
        Returns None if:
        - CVE lookup is disabled
        - CVE not found
        - API error occurs
        """
        if not self.enabled:
            return None
        
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
                timeout=10
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
                    "references": cve_data.get("references", [])
                }
                self.cache[cve_id] = result
                return result
        except Exception as e:
            # Log error but don't fail
            import structlog
            log = structlog.get_logger()
            log.warning("cve_lookup_failed", cve_id=cve_id, error=str(e))
        
        return None
    
    def _extract_description(self, cve_data: dict) -> str:
        """Extract primary description from CVE."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return ""
    
    def _extract_cvss(self, cve_data: dict) -> Optional[float]:
        """Extract CVSS v3.1 base score."""
        metrics = cve_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0]
        return cvss_data.get("cvssData", {}).get("baseScore")
    
    def _extract_severity(self, cve_data: dict) -> str:
        """Extract severity rating."""
        metrics = cve_data.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31", [{}])[0]
        return cvss_data.get("cvssData", {}).get("baseSeverity", "UNKNOWN")


# Global instance
cve_lookup = CVELookup()

def lookup_cve(cve_id: str) -> Optional[dict]:
    """Convenience function for CVE lookup."""
    return cve_lookup.lookup(cve_id)
```

**Integration with Analysis:**

```python
# src/detonate/core/hooks/windows.py
from ...utils.cve_lookup import lookup_cve

def hook_CreateFileA(self, ql: Any) -> None:
    """Hook CreateFileA with CVE detection."""
    lpFileName = ql.os.f_param_read(0)
    file_name = ql.mem.string(lpFileName) if lpFileName else ""
    
    params = {"lpFileName": file_name}
    record = self._record_api_call("CreateFileA", params)
    
    # Check for CVE indicators in file path
    cve_matches = self._detect_cve_indicators(file_name)
    for cve_id in cve_matches:
        cve_data = lookup_cve(cve_id)
        if cve_data:
            self.session.add_vulnerability(
                cve_id=cve_id,
                cve_data=cve_data,
                related_api_call=record
            )
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from stix2 import Vulnerability

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Add vulnerability objects
    for vuln_record in session.vulnerabilities:
        vulnerability = Vulnerability(
            id=f"vulnerability--{uuid.uuid4()}",
            spec_version="2.1",
            name=vuln_record.cve_id,
            description=vuln_record.cve_data.get("description", ""),
            external_references=[{
                "source_name": "CVE",
                "external_id": vuln_record.cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{vuln_record.cve_id}"
            }]
        )
        objects.append(vulnerability)
        
        # Create 'targets' relationship (attack-pattern → vulnerability)
        if vuln_record.technique_id:
            relationship = Relationship(
                id=f"relationship--{uuid.uuid4()}",
                relationship_type="targets",
                source_ref=created_patterns[vuln_record.technique_id].id,
                target_ref=vulnerability.id,
                description=f"Technique exploits {vuln_record.cve_id}"
            )
            objects.append(relationship)
```

**Acceptance Criteria:**
- [ ] `cve_lookup.py` created with NVD API client
- [ ] ENV vars `DETONATE_CVE_LOOKUP` and `DETONATE_NVD_API_KEY` implemented
- [ ] Rate limiting enforced (5 req/30s without key, 50 req/30s with key)
- [ ] LRU caching implemented (1000 entry cache)
- [ ] STIX bundles include `Vulnerability` objects when CVEs detected
- [ ] Unit tests for CVE lookup (mocked API responses)

---

### Phase 4: Threat Actor Attribution (MEDIUM)

**Timeline:** 2-3 weeks  
**Dependencies:** Phase 1-3 complete  
**Owner:** Intelligence Team

#### 4.1 TTP-Based Attribution

**Environment Variable:** `DETONATE_ATTRIBUTION_THRESHOLD` (default: `0.5`)

**Implementation:**

```python
# New file: src/detonate/mapping/attribution.py
"""Threat actor attribution based on TTP overlap."""

import os
from typing import List, Tuple
from .stix_data import STIXDataStore

def get_attribution_threshold() -> float:
    """Get attribution threshold from environment."""
    try:
        return float(os.getenv("DETONATE_ATTRIBUTION_THRESHOLD", "0.5"))
    except ValueError:
        return 0.5

def attribute_to_threat_actors(
    detected_techniques: set[str],
    stix_store: STIXDataStore
) -> List[Tuple[dict, float]]:
    """
    Attribute detected TTPs to known threat actors.
    
    Args:
        detected_techniques: Set of technique IDs detected during analysis
        stix_store: STIX data store with intrusion-set objects
    
    Returns:
        List of (intrusion_set_data, confidence_score) tuples, sorted by confidence
    """
    threshold = get_attribution_threshold()
    results = []
    
    # Get all intrusion sets from STIX data
    intrusion_sets = stix_store.get_all_intrusion_sets()
    
    for intrusion_set in intrusion_sets:
        # Get known TTPs for this intrusion set
        known_ttps = set(intrusion_set.get("ttps", []))
        
        if not known_ttps:
            continue
        
        # Calculate overlap
        overlap = detected_techniques & known_ttps
        overlap_count = len(overlap)
        
        if overlap_count == 0:
            continue
        
        # Calculate confidence as overlap ratio
        confidence = overlap_count / len(known_ttps)
        
        if confidence >= threshold:
            results.append((intrusion_set, confidence, overlap))
    
    # Sort by confidence descending
    results.sort(key=lambda x: x[1], reverse=True)
    
    return [(is_data, confidence) for is_data, confidence, _ in results]

def get_intrusion_set_ttps(intrusion_set_id: str, stix_store: STIXDataStore) -> set[str]:
    """Get all TTPs associated with an intrusion set."""
    intrusion_set = stix_store.get_intrusion_set(intrusion_set_id)
    if not intrusion_set:
        return set()
    
    return set(intrusion_set.get("ttps", []))
```

**STIX Data Store Enhancement:**

```python
# src/detonate/mapping/stix_data.py
class STIXDataStore:
    # ... existing code ...
    
    def __init__(self, stix_path: str | Path | None = None):
        # ... existing fields ...
        self.intrusion_sets: dict[str, dict[str, Any]] = {}
        self.relationships_by_type: dict[str, list[dict]] = {}
        # ... rest of init ...
    
    def _index_objects(self) -> None:
        """Index STIX objects for fast lookup."""
        objects = self.bundle.get("objects", [])
        
        # Index intrusion sets
        for obj in objects:
            if obj.get("type") == "intrusion-set":
                external_refs = obj.get("external_references", [])
                attack_id = None
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        attack_id = ref.get("external_id")
                        break
                
                if attack_id:
                    self.intrusion_sets[attack_id] = {
                        "id": obj.get("id"),
                        "intrusion_set_id": attack_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "aliases": obj.get("aliases", []),
                        "ttps": [],  # Will be populated from relationships
                        "url": f"https://attack.mitre.org/groups/{attack_id}/"
                    }
        
        # Index relationships
        for obj in objects:
            if obj.get("type") == "relationship":
                rel_type = obj.get("relationship_type")
                if rel_type not in self.relationships_by_type:
                    self.relationships_by_type[rel_type] = []
                self.relationships_by_type[rel_type].append(obj)
        
        # Populate TTPs for each intrusion set from 'uses' relationships
        for rel in self.relationships_by_type.get("uses", []):
            source_ref = rel.get("source_ref", "")
            target_ref = rel.get("target_ref", "")
            
            # Find intrusion set by source_ref
            for is_data in self.intrusion_sets.values():
                if is_data["id"] == source_ref:
                    # Extract technique ID from target_ref (attack-pattern--xxx)
                    if target_ref.startswith("attack-pattern--"):
                        # Look up technique to get external ID
                        for tech in self.techniques.values():
                            if tech["id"] == target_ref:
                                is_data["ttps"].append(tech["technique_id"])
                                break
    
    def get_all_intrusion_sets(self) -> list[dict]:
        """Get all intrusion sets."""
        return list(self.intrusion_sets.values())
    
    def get_intrusion_set(self, intrusion_set_id: str) -> dict | None:
        """Get intrusion set by ID."""
        return self.intrusion_sets.get(intrusion_set_id)
```

**STIX Bundle Integration:**

```python
# src/detonate/output/stix.py
from stix2 import IntrusionSet, Relationship
from ..mapping.attribution import attribute_to_threat_actors

def generate_stix_bundle(...):
    # ... existing code ...
    
    # Perform attribution
    detected_technique_ids = {f.technique_id for f in findings}
    attributed_actors = attribute_to_threat_actors(detected_technique_ids, stix_store)
    
    # Add intrusion set objects and relationships
    created_intrusion_sets = {}
    for intrusion_set_data, confidence in attributed_actors:
        if intrusion_set_data["intrusion_set_id"] not in created_intrusion_sets:
            intrusion_set = IntrusionSet(
                id=intrusion_set_data["id"],
                spec_version="2.1",
                name=intrusion_set_data["name"],
                description=intrusion_set_data["description"],
                aliases=intrusion_set_data["aliases"],
                external_references=[{
                    "source_name": "mitre-attack",
                    "external_id": intrusion_set_data["intrusion_set_id"],
                    "url": intrusion_set_data["url"]
                }]
            )
            created_intrusion_sets[intrusion_set_data["intrusion_set_id"]] = intrusion_set
            objects.append(intrusion_set)
        
        # Create 'attributed-to' relationship (malware → intrusion-set)
        relationship = Relationship(
            id=f"relationship--{uuid.uuid4()}",
            relationship_type="attributed-to",
            source_ref=malware_id,
            target_ref=intrusion_set.id,
            description=f"Malware behavior attributed to {intrusion_set_data['name']} (confidence: {confidence:.0%})",
            confidence=confidence
        )
        objects.append(relationship)
```

**Markdown Report Enhancement:**

```python
# src/detonate/output/report.py
from ..mapping.attribution import attribute_to_threat_actors, get_attribution_threshold

def generate_markdown_report(...):
    # ... existing sections ...
    
    # NEW: Possible Attribution section
    detected_technique_ids = {f.technique_id for f in findings}
    attributed_actors = attribute_to_threat_actors(detected_technique_ids, stix_store)
    
    if attributed_actors:
        f.write("## Possible Attribution\n\n")
        f.write(f"The following threat actors have been identified based on TTP overlap (threshold: {get_attribution_threshold():.0%}):\n\n")
        
        for intrusion_set_data, confidence in attributed_actors[:5]:  # Top 5 matches
            f.write(f"### {intrusion_set_data['name']} ({intrusion_set_data['intrusion_set_id']})\n")
            f.write(f"**Confidence:** {confidence:.0%}\n\n")
            f.write(f"{intrusion_set_data['description']}\n\n")
            
            if intrusion_set_data.get("aliases"):
                f.write(f"**Also known as:** {', '.join(intrusion_set_data['aliases'])}\n\n")
            
            f.write(f"[Learn more]({intrusion_set_data['url']})\n\n")
```

**Acceptance Criteria:**
- [ ] `attribution.py` created with TTP overlap algorithm
- [ ] ENV var `DETONATE_ATTRIBUTION_THRESHOLD` controls minimum confidence
- [ ] STIX data store indexes intrusion sets and relationships
- [ ] STIX bundles include `IntrusionSet` objects when attribution found
- [ ] `attributed-to` relationships created (malware → intrusion-set)
- [ ] Markdown reports include "Possible Attribution" section
- [ ] Unit tests for attribution algorithm

---

## Environment Variables Reference

| Variable | Default | Description | Phase |
|----------|---------|-------------|-------|
| `DETONATE_GENERATE_INDICATORS` | `false` | Enable STIX Indicator generation | 3.1 |
| `DETONATE_CVE_LOOKUP` | `false` | Enable live NVD API lookups | 3.3 |
| `DETONATE_NVD_API_KEY` | `None` | API key for NVD (higher rate limits) | 3.3 |
| `DETONATE_ATTRIBUTION_THRESHOLD` | `0.5` | Minimum confidence for threat actor attribution | 4.1 |

---

## Database Schema Changes

```sql
-- Mitigations table
CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    stix_id TEXT UNIQUE,
    url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Data sources table
CREATE TABLE IF NOT EXISTS data_sources (
    source_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    stix_id TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Data components table
CREATE TABLE IF NOT EXISTS data_components (
    component_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    data_source_id TEXT,
    stix_id TEXT UNIQUE,
    description TEXT,
    FOREIGN KEY (data_source_id) REFERENCES data_sources(source_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Technique-mitigation mapping
CREATE TABLE IF NOT EXISTS technique_mitigations (
    technique_id TEXT NOT NULL,
    mitigation_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, mitigation_id),
    FOREIGN KEY (mitigation_id) REFERENCES mitigations(mitigation_id)
);

-- Technique-data source mapping
CREATE TABLE IF NOT EXISTS technique_data_sources (
    technique_id TEXT NOT NULL,
    data_source_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    PRIMARY KEY (technique_id, data_source_id, component_id),
    FOREIGN KEY (data_source_id) REFERENCES data_sources(source_id),
    FOREIGN KEY (component_id) REFERENCES data_components(component_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_technique_mitigations ON technique_mitigations(technique_id);
CREATE INDEX IF NOT EXISTS idx_technique_data_sources ON technique_data_sources(technique_id);
```

**Migration Strategy:**
- Auto-migrate on first run using Alembic
- Pre-populate tables from STIX data at application startup
- Cache in-memory for fast lookups

---

## Testing Strategy

### Unit Tests (Synthesized Hooks)

```python
# tests/test_enhanced_mapping.py
import pytest
from unittest.mock import Mock, MagicMock
from src.detonate.core.session import AnalysisSession
from src.detonate.core.hooks.windows import WindowsHooks
from src.detonate.mapping.mitigations import get_mitigations_for_technique
from src.detonate.mapping.data_sources import get_data_sources_for_technique

def create_mock_ql():
    """Create mock Qiling instance."""
    ql = Mock()
    ql.mem = Mock()
    ql.mem.string = Mock(return_value="test")
    ql.mem.wstring = Mock(return_value="test")
    ql.os = Mock()
    ql.os.f_param_read = Mock(return_value=0x1000)
    ql.arch = Mock()
    ql.arch.pc = 0x401000
    return ql

class TestCredentialAccessMapping:
    """Test credential access technique detection."""
    
    def test_lsass_access_detection(self):
        """Test LSASS access via CredEnumerateA."""
        session = AnalysisSession("test", "windows", "x86")
        ql = create_mock_ql()
        ql.mem.string.return_value = "Vault"  # CredEnumerateA parameter
        
        hooks = WindowsHooks(session, ql)
        hooks.hook_CredEnumerateA(ql)
        
        findings = session.get_findings()
        assert any(f.technique_id == "T1003.001" for f in findings)
    
    def test_sam_access_detection(self):
        """Test SAM database access detection."""
        session = AnalysisSession("test", "windows", "x86")
        ql = create_mock_ql()
        ql.mem.string.return_value = "SAM"
        
        hooks = WindowsHooks(session, ql)
        hooks.hook_CreateFileA(ql)
        
        findings = session.get_findings()
        assert any(f.technique_id == "T1003.002" for f in findings)

class TestMitigationMapping:
    """Test mitigation recommendation functionality."""
    
    def test_mitigation_lookup(self):
        """Test mitigation lookup for technique."""
        mitigations = get_mitigations_for_technique("T1055.001")
        assert len(mitigations) > 0
        assert all("mitigation_id" in m for m in mitigations)
    
    def test_all_techniques_have_mitigations(self):
        """Test that all detected techniques have mitigation mappings."""
        # Get all technique IDs from windows_map and linux_map
        from src.detonate.mapping.windows_map import API_TO_TECHNIQUE
        from src.detonate.mapping.linux_map import SYSCALL_TO_TECHNIQUE
        
        technique_ids = set()
        for api_data in API_TO_TECHNIQUE.values():
            technique_ids.add(api_data["technique_id"])
            # Check param_checks for sub-techniques
            if "param_checks" in api_data:
                for checks in api_data["param_checks"].values():
                    for technique in checks.values():
                        technique_ids.add(technique["id"])
        
        # Verify all have mitigations
        missing = []
        for tech_id in technique_ids:
            if not get_mitigations_for_technique(tech_id):
                missing.append(tech_id)
        
        # Allow some techniques without mitigations
        assert len(missing) < len(technique_ids) * 0.1  # < 10% missing

class TestDataSourceMapping:
    """Test data source mapping functionality."""
    
    def test_data_source_lookup(self):
        """Test data source lookup for technique."""
        data_sources = get_data_sources_for_technique("T1055.001")
        assert len(data_sources) > 0
        assert all("source_id" in ds for ds in data_sources)
        assert all("component_id" in ds for ds in data_sources)

class TestLinuxContainerEscape:
    """Test container escape detection."""
    
    def test_docker_socket_access(self):
        """Test Docker socket access detection."""
        from src.detonate.core.hooks.linux import LinuxHooks
        
        session = AnalysisSession("test", "linux", "x86_64")
        ql = create_mock_ql()
        ql.mem.string.return_value = "/var/run/docker.sock"
        
        hooks = LinuxHooks(session, ql)
        # Mock the syscall parameters
        ql.arch.regs.rdi = 0x1000  # dirfd
        ql.arch.regs.rsi = 0x2000  # pathname
        
        hooks.hook_sys_openat(ql)
        
        findings = session.get_findings()
        assert any(f.technique_id == "T1611" for f in findings)
    
    def test_cloud_metadata_access(self):
        """Test cloud metadata endpoint access."""
        session = AnalysisSession("test", "linux", "x86_64")
        ql = create_mock_ql()
        ql.mem.string.return_value = "169.254.169.254"
        
        hooks = LinuxHooks(session, ql)
        ql.arch.regs.rdi = 2  # AF_INET
        ql.arch.regs.rsi = 1  # SOCK_STREAM
        
        hooks.hook_sys_socket(ql)
        
        findings = session.get_findings()
        assert any(f.technique_id == "T1592.004" for f in findings)
```

### Integration Tests

```python
# tests/test_stix_bundle_enhanced.py
import pytest
from src.detonate.output.stix import generate_stix_bundle
from src.detonate.output.indicators import should_generate_indicators

class TestEnhancedSTIXBundle:
    """Test enhanced STIX bundle generation."""
    
    def test_bundle_contains_all_object_types(self, monkeypatch):
        """Test that bundle contains all expected object types."""
        # Enable all features
        monkeypatch.setenv("DETONATE_GENERATE_INDICATORS", "true")
        monkeypatch.setenv("DETONATE_CVE_LOOKUP", "false")  # Disable for this test
        
        session = create_test_session_with_findings([
            "T1055.001",  # Process Injection
            "T1059.001",  # PowerShell
            "T1547.001"   # Registry Persistence
        ])
        
        bundle = generate_stix_bundle(
            session_id=session.session_id,
            sample_sha256=session.sample_sha256,
            sample_path="/test/sample",
            findings=session.get_findings(),
            api_calls=session.api_calls
        )
        
        object_types = {o.type for o in bundle.objects}
        
        # Core types (always present)
        assert "malware" in object_types
        assert "attack-pattern" in object_types
        assert "relationship" in object_types
        assert "observed-data" in object_types
        
        # Enhanced types (from Phase 2)
        assert "course-of-action" in object_types
        assert "x-mitre-data-source" in object_types
        assert "x-mitre-data-component" in object_types
        
        # Indicator types (from Phase 3, when enabled)
        assert "indicator" in object_types
    
    def test_mitigation_relationships(self):
        """Test that mitigation relationships are created."""
        session = create_test_session_with_findings(["T1055.001"])
        bundle = generate_stix_bundle(...)
        
        # Find mitigates relationships
        mitigates_rels = [
            r for r in bundle.objects
            if hasattr(r, 'relationship_type') and r.relationship_type == "mitigates"
        ]
        
        assert len(mitigates_rels) > 0
        # Verify relationship structure
        for rel in mitigates_rels:
            assert rel.source_ref.startswith("course-of-action--")
            assert rel.target_ref.startswith("attack-pattern--")
    
    def test_attribution_relationships(self, monkeypatch):
        """Test threat actor attribution."""
        monkeypatch.setenv("DETONATE_ATTRIBUTION_THRESHOLD", "0.3")
        
        # Create session with techniques common to known threat actors
        session = create_test_session_with_findings([
            "T1059.001",  # PowerShell - common APT technique
            "T1055.001",  # Process Injection
            "T1071.001"   # Web Protocols
        ])
        
        bundle = generate_stix_bundle(...)
        
        # Find attributed-to relationships
        attribution_rels = [
            r for r in bundle.objects
            if hasattr(r, 'relationship_type') and r.relationship_type == "attributed-to"
        ]
        
        # May be empty if no matches above threshold
        # Just verify structure if present
        for rel in attribution_rels:
            assert rel.source_ref.startswith("malware--")
            assert rel.target_ref.startswith("intrusion-set--")
            assert hasattr(rel, 'confidence')
```

### Performance Tests

```python
# tests/test_performance.py
import pytest
import time
from src.detonate.utils.cve_lookup import CVELookup

class TestCVELookupPerformance:
    """Test CVE lookup performance and rate limiting."""
    
    def test_rate_limiting_without_api_key(self, monkeypatch):
        """Test rate limiting without API key."""
        monkeypatch.delenv("DETONATE_NVD_API_KEY", raising=False)
        monkeypatch.setenv("DETONATE_CVE_LOOKUP", "true")
        
        lookup = CVELookup()
        
        # Make 6 requests (should take ~3.6 seconds with rate limiting)
        start = time.time()
        for i in range(6):
            lookup.lookup(f"CVE-2021-{i:04d}")
        elapsed = time.time() - start
        
        # Should take at least 3 seconds (5 requests per 30 seconds = 0.6s per request)
        assert elapsed >= 3.0
    
    def test_caching(self, monkeypatch):
        """Test that repeated lookups use cache."""
        monkeypatch.setenv("DETONATE_CVE_LOOKUP", "true")
        
        lookup = CVELookup()
        
        # First lookup (should be slow, hits API)
        start = time.time()
        lookup.lookup("CVE-2021-44228")
        first_elapsed = time.time() - start
        
        # Second lookup (should be fast, from cache)
        start = time.time()
        lookup.lookup("CVE-2021-44228")
        second_elapsed = time.time() - start
        
        # Cache lookup should be much faster
        assert second_elapsed < first_elapsed * 0.1
```

---

## Acceptance Criteria Summary

### Phase 1: Core Technique Mapping
- [ ] 80+ Windows APIs mapped with sub-technique granularity
- [ ] 60+ Linux syscalls mapped with container/cloud detection
- [ ] Confidence calibration implemented with diminishing returns
- [ ] All unit tests pass (synthesized hook tests)

### Phase 2: Mitigation & Data Sources
- [ ] 268 course-of-action objects integrated
- [ ] 38 data sources + 109 components mapped
- [ ] STIX bundles include mitigation and data source objects
- [ ] Markdown reports include "Recommended Defenses" and "Detection Opportunities" sections

### Phase 3: Enhanced STIX 2.1 Features
- [ ] Indicator generation controlled by ENV var
- [ ] Infrastructure tracking for C2 servers
- [ ] Live CVE lookup with rate limiting and caching
- [ ] All new STIX object types in bundles

### Phase 4: Threat Actor Attribution
- [ ] TTP-based attribution algorithm implemented
- [ ] Attribution threshold configurable via ENV var
- [ ] IntrusionSet objects in STIX bundles
- [ ] "Possible Attribution" section in reports

---

## Implementation Timeline

| Phase | Duration | Start Date | End Date | Status |
|-------|----------|------------|----------|--------|
| Phase 1.1 (Windows APIs) | 2 weeks | Week 1 | Week 2 | Pending |
| Phase 1.2 (Linux Syscalls) | 1 week | Week 3 | Week 3 | Pending |
| Phase 1.3 (Confidence) | 1 week | Week 4 | Week 4 | Pending |
| Phase 2.1 (Mitigations) | 1 week | Week 5 | Week 5 | Pending |
| Phase 2.2 (Data Sources) | 1 week | Week 6 | Week 6 | Pending |
| Phase 3.1 (Indicators) | 1 week | Week 7 | Week 7 | Pending |
| Phase 3.2 (Infrastructure) | 1 week | Week 8 | Week 8 | Pending |
| Phase 3.3 (CVE Lookup) | 1 week | Week 9 | Week 9 | Pending |
| Phase 4.1 (Attribution) | 2 weeks | Week 10 | Week 11 | Pending |
| **Total** | **12 weeks** | | | |

---

## Success Metrics

1. **Coverage:** 90%+ of detected techniques have mitigation and data source mappings
2. **Accuracy:** < 5% false positive rate in attribution (confidence >= 0.5)
3. **Performance:** < 100ms overhead for enhanced STIX bundle generation
4. **Completeness:** All 16 STIX object types from ATT&CK represented in output

---

## Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| NVD API rate limiting | High | Medium | Implement caching, require API key for production use |
| Attribution false positives | Medium | Medium | Configurable threshold, clear confidence reporting |
| STIX bundle size growth | Low | High | Optional compression, streaming output |
| Mapping accuracy | High | Medium | Extensive unit testing, community review |

---

## Appendix A: STIX 2.1 Object Reference

### Core Objects (Already Implemented)
- `malware` - Analyzed sample
- `attack-pattern` - Detected techniques
- `relationship` - Connections between objects
- `observed-data` - API call evidence

### Phase 2 Objects
- `course-of-action` - Mitigations (268 objects)
- `x-mitre-data-source` - Data sources (38 objects)
- `x-mitre-data-component` - Data components (109 objects)

### Phase 3 Objects
- `indicator` - Detection patterns
- `infrastructure` - C2 servers
- `vulnerability` - CVEs

### Phase 4 Objects
- `intrusion-set` - Threat actors (187 objects)
- `campaign` - Campaigns (52 objects)

---

## Appendix B: File Changes Summary

### New Files
```
src/detonate/mapping/mitigations.py
src/detonate/mapping/data_sources.py
src/detonate/mapping/attribution.py
src/detonate/output/indicators.py
src/detonate/utils/cve_lookup.py
tests/test_enhanced_mapping.py
tests/test_stix_bundle_enhanced.py
tests/test_performance.py
```

### Modified Files
```
src/detonate/mapping/windows_map.py
src/detonate/mapping/linux_map.py
src/detonate/mapping/engine.py
src/detonate/mapping/stix_data.py
src/detonate/core/session.py
src/detonate/core/hooks/windows.py
src/detonate/core/hooks/linux.py
src/detonate/output/stix.py
src/detonate/output/report.py
src/detonate/db/models.py
src/detonate/db/store.py
```

---

## Appendix C: ENV Variable Configuration

```bash
# .env.example for development
DETONATE_GENERATE_INDICATORS=true
DETONATE_CVE_LOOKUP=false
DETONATE_NVD_API_KEY=  # Optional, get from https://nvd.nist.gov/developers
DETONATE_ATTRIBUTION_THRESHOLD=0.5

# Database
DETONATE_DATABASE=/var/lib/detonate/detonate.db

# Analysis settings
DETONATE_ROOTFS=/app/data/rootfs
DETONATE_DLLS_X86=/opt/rootfs/x86_windows/dlls
DETONATE_DLLS_X64=/opt/rootfs/x8664_windows/dlls
DETONATE_OUTPUT_DIR=/output
```

---

**Document End**
