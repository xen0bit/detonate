# Backward Agent State

## Session Info
- Mode: Bootstrap
- Bootstrap Completed: 2026-04-23T00:00:00Z
- Revision Count: 0

## Persona Chosen
- Name: Tavis Ormandy
- Rationale: Security research / reverse engineering domain match — malware analysis tooling requires deep Windows/Linux internals knowledge and rigorous detection accuracy.

## Revision History
- Phase 1.1: Expand Windows API Coverage | src/detonate/core/hooks/windows.py | hook_ShellExecuteW, hook_ReadFile, hook_WriteFile recorded calls but never added technique evidence - critical gap for ATT&CK mapping | 2026-04-23T00:05:00Z
- Phase 1.2: Expand Linux Syscall Coverage | src/detonate/core/hooks/linux.py | hook_sys_connect missing address parsing (cloud metadata detection broken), hook_sys_getuid/geteuid/access never triggered technique evidence, _parse_sockaddr helper absent | 2026-04-23T00:30:00Z
- Phase 1.3: Confidence Calibration | src/detonate/mapping/engine.py, src/detonate/mapping/patterns.py | is_sub_technique and is_pattern_based flags defined but never set - sub-technique bonus dead code, pattern-based caps never applied | 2026-04-23T04:00:00Z
- Phase 2.1: Mitigation Recommendations | src/detonate/mapping/mitigations.py | Only 14 unique mitigations covering 41 techniques, not 268 course-of-action objects as required - needs STIXDataStore integration for full coverage | 2026-04-23T06:00:00Z
- Phase 2.2: Data Source Mapping | src/detonate/mapping/data_sources.py | _get_technique_category uses fragile prefix matching (T108/T101 too broad), missing 6+ major categories (Collection, Impact, Execution, Initial Access, Privilege Escalation, C2), no tactic-based fallback | 2026-04-23T08:00:00Z
- Phase 3.1: STIX Indicator Generation | src/detonate/output/indicators.py | pattern_type="stix" incorrect (must be "stix-patterning"), no valid_until, incomplete pattern escaping, missing ATT&CK external_references, IPv6 gaps, cloud metadata URL path detection missing, weak script patterns, confidence ignores complexity | 2026-04-23T12:00:00Z
- Phase 3.2: Infrastructure Objects | src/detonate/output/stix.py | Infrastructure objects have generic descriptions, missing technique-infrastructure relationships, Windows connect hook doesn't track infrastructure, no threat intel external_references | 2026-04-23T13:00:00Z
- Phase 3.3: Live CVE Lookup | src/detonate/core/hooks/windows.py | hook_CreateFileA never calls lookup_cve() - CVE utility exists but is never invoked, no vulnerability detection occurs, no CVE indicator patterns defined | 2026-04-23T16:00:00Z
- Phase 4.1: Threat Actor Attribution | src/detonate/mapping/attribution.py | attribute_to_threat_actors uses simple ratio without TTP weighting - rare/distinctive TTPs should contribute more to confidence than common ones, no calculate_ttp_weights function | 2026-04-23T18:30:00Z

All completed units already revised. Exiting.
