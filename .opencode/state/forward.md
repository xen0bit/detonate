# Forward Agent State

## Persona
**Name**: Tavis Ormandy
**Domain**: Security research / vulnerability analysis / reverse engineering
**Style**: 
- Ruthlessly precise about detection accuracy — false positives are unacceptable
- Deep dives into OS internals (Windows APIs, Linux syscalls) before implementing hooks
- Minimal, testable code with explicit edge case handling
- Skeptical of confidence scores without empirical evidence
- Documents assumptions and limitations clearly
**Why chosen**: This is security research tooling requiring meticulous ATT&CK mapping and behavioral analysis — Tavis's expertise in Windows/Linux internals and vulnerability discovery aligns with the task's demand for accurate technique detection.

## Session Info
- Started: 2026-04-23T00:00:00Z
- Current Iteration: 1

## Task Queue
- [x] Phase 1: Foundation
- [x] Phase 1.1: Expand Windows API Coverage (40 new APIs for credential access, discovery, lateral movement, defense evasion, execution, collection, exfiltration, impact)
- [x] Phase 1.2: Expand Linux Syscall Coverage (35 new syscalls for credential access, discovery, container escape, cloud metadata, persistence, defense evasion, lateral movement, collection, exfiltration)
- [x] Phase 1.3: Confidence Calibration (diminishing returns, sub-technique bonus, pattern-based caps)
- [x] Phase 2.1: Mitigation Recommendations (268 course-of-action objects)
- [x] Phase 2.2: Data Source Mapping (38 data sources + 109 data components)
- [x] Phase 3.1: STIX Indicator Generation (ENV-controlled)
- [x] Phase 3.2: Infrastructure Objects (C2 server tracking) - REVISED: richer descriptions, technique relationships, Windows connect hook fix, threat intel refs
- [x] Phase 3.3: Live CVE Lookup (NVD API integration) - REVISED: Implemented CVE indicator pattern matching in hook_CreateFileA with NVD API integration
- [x] Phase 4.1: Threat Actor Attribution (TTP-based overlap algorithm) - REVISED: Add TTP weighting by rarity for improved attribution accuracy

## Implementation Progress
- Completed: ["Phase 1: Foundation", "Phase 1.1: Expand Windows API Coverage", "Phase 1.2: Expand Linux Syscall Coverage", "Phase 1.3: Confidence Calibration", "Phase 2.1: Mitigation Recommendations", "Phase 2.2: Data Source Mapping", "Phase 3.1: STIX Indicator Generation", "Phase 3.2: Infrastructure Objects (C2 server tracking) - REVISED", "Phase 3.3: Live CVE Lookup (NVD API integration) - REVISED", "Phase 4.1: Threat Actor Attribution (TTP-based overlap algorithm) - REVISED"]
- In Progress: []
- Blocked: []

## Last Action
- Completed Phase 4.1 (Threat Actor Attribution): Implemented TTP weighting by rarity with three strategies (rarity, log_rarity, uniform). Added calculate_ttp_weights() function and optional ttp_weights parameter to attribute_to_threat_actors(). Added 8 comprehensive tests validating weighting behavior, rarity scoring, and weighted vs unweighted attribution. All 25 tests pass. (2026-04-23T19:00:00Z)
