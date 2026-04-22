# Detonate Test Samples

# TODO: Prior implementation provided pre-compiled binaries (minimal_x86_64, minimal_x86,
# trigger_x86_64, fake_pe_x86.exe) without source code, reproducible build process, or
# e2e validation script. Re-implement with:
# 1. Source files (.c) for each ELF binary stored alongside compiled output
# 2. build_all.sh script that compiles from source (reproducible, documented)
# 3. test_e2e.sh script that runs detonate analyze on each sample and verifies:
#    - Expected syscalls were captured (openat, socket, setuid, etc.)
#    - Expected ATT&CK techniques were detected (T1548.001, T1071.001, etc.)
#    - All four output formats are generated correctly
# 4. Clear documentation of what each sample tests and expected behavior
# 5. Verify all ELF samples are statically linked (no rootfs dependencies)
# 6. Remove pre-compiled binaries from version control; add build instructions
#
# Source files added: minimal_x86_64.c, minimal_x86.c, trigger_x86_64.c
# Build script added: build_all.sh
# E2E test added: test_e2e.sh
# This README: Updated with full documentation

---

This directory contains safe test binaries for end-to-end validation of the detonate malware analysis platform.

## Overview

These samples are designed to exercise specific syscalls and verify that detonate correctly:
1. Captures syscall parameters and return values
2. Maps syscalls to ATT&CK techniques
3. Generates all four output formats (Navigator, STIX, Markdown, JSON)

## Samples

| Binary | Architecture | Purpose | Expected Behavior |
|--------|-------------|---------|-------------------|
| `minimal_x86_64` | x86_64 | Basic emulation test | Single `exit(0)` syscall |
| `minimal_x86` | x86 | 32-bit emulation test | Single `exit(0)` syscall |
| `trigger_x86_64` | x86_64 | Hook coverage test | Multiple syscalls with ATT&CK mappings |
| `fake_pe_x86.exe` | x86 | PE detection test | Not executable - header only |

## Building from Source

All ELF samples are statically linked to avoid rootfs dependencies.

```bash
# Build all samples
./build_all.sh

# Or compile individually:
gcc -static -o minimal_x86_64 minimal_x86_64.c
gcc -static -m32 -o minimal_x86 minimal_x86.c
gcc -static -o trigger_x86_64 trigger_x86_64.c
```

## Running End-to-End Tests

```bash
# Analyze trigger sample and verify output
./test_e2e.sh

# Or manually:
detonate analyze trigger_x86_64 --platform linux --arch x86_64 --format all --output ./results
```

## Expected ATT&CK Techniques (trigger_x86_64)

| Syscall | Technique | Tactic | Confidence |
|---------|-----------|--------|------------|
| `openat("/etc/passwd")` | T1005 (Data from Local System) | collection | medium |
| `read()` | T1005 | collection | low |
| `socket(AF_INET, SOCK_STREAM)` | T1071.001 (Web Protocols) | command-and-control | medium |
| `setuid(0)` | T1548.001 (Setuid and Setgid) | privilege-escalation | high |

## Safety

These binaries are **completely safe**:
- No malicious code
- No network connections (emulated only)
- No actual privilege changes
- Designed for testing analysis infrastructure
