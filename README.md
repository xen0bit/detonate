# detonate

A Docker-based malware analysis platform using Qiling emulation to map observed behavior to MITRE ATT&CK techniques. Produces four output formats (ATT&CK Navigator layers, STIX 2.1 bundles, Markdown reports, and structured JSON logs) with both CLI and REST API interfaces.

## Overview

`detonate` analyzes suspicious binaries in an emulated environment without executing them on your host system. It intercepts API calls and syscalls, maps them to ATT&CK techniques with confidence scoring, and generates actionable intelligence outputs.

**Key capabilities:**

- **Safe emulation**: Malware runs in Qiling's userspace emulator, not on your hardware
- **ATT&CK mapping**: Every observed behavior mapped to MITRE ATT&CK techniques with confidence scores
- **Multi-platform**: Supports Windows PE and Linux ELF binaries (x86/x86_64)
- **Multiple outputs**: Navigator layers, STIX 2.1 bundles, Markdown reports, JSON logs
- **Flexible deployment**: CLI for one-off analysis, REST API for integration, Docker for isolation

## Installation

### Prerequisites

- Python 3.10+
- Docker (for containerized deployment)
- Windows DLLs (for Windows PE analysis — must be provided by user due to licensing)

### Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/your-org/detonate.git
cd detonate

# Build the Docker image
docker build -t detonate:latest .

# Analyze a Linux binary (no extra dependencies needed)
docker run --rm -v $(pwd)/samples:/samples:ro -v $(pwd)/output:/output \
    detonate analyze /samples/suspicious_elf --output /output

# Analyze a Windows PE (requires Windows DLLs)
docker run --rm -v $(pwd)/samples:/samples:ro -v $(pwd)/output:/output \
    -v $(pwd)/dlls/x86:/opt/rootfs/x86_windows/dlls:ro \
    detonate analyze /samples/malware.exe --output /output
```

### Local Development Install

```bash
# Install dependencies with uv
uv sync

# Run tests
uv run pytest

# Analyze a sample
uv run detonate analyze path/to/sample --output ./results
```

## Usage

### CLI Commands

#### Analyze a Sample

```bash
# Basic analysis with all output formats
detonate analyze malware.exe --rootfs ./rootfs/x86_windows --dlls ./dlls --output ./results

# Linux binary, JSON output only
detonate analyze linux_suspicious --format json --output ./results

# Custom timeout for slow samples
detonate analyze slow_malware.exe --timeout 120 --rootfs ./rootfs/x86_windows
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--platform` | `auto`, `windows`, or `linux` | `auto` |
| `--arch` | `auto`, `x86`, `x86_64`, `arm`, `arm64` | `auto` |
| `--rootfs` | Path to Qiling rootfs (required for Windows) | — |
| `--dlls` | Path to Windows DLLs directory (required for Windows) | — |
| `--timeout` | Execution timeout in seconds | `60` |
| `--format` | Output format: `json`, `navigator`, `stix`, `report`, `all` | `all` |
| `--output` | Output directory | Current directory |
| `--verbose` | Enable verbose logging | — |

#### Start the REST API Server

```bash
# Default (localhost:8000)
detonate serve

# Accessible from network
detonate serve --host 0.0.0.0 --port 8000

# Custom database location
detonate serve --database ./data/detonate.db
```

#### List Past Analyses

```bash
# Recent analyses
detonate list

# Filter by status and platform
detonate list --status failed --platform windows --limit 10

# JSON output for scripting
detonate list --format json
```

#### Export Results

```bash
# Export Navigator layer
detonate export <session_id> --format navigator --output layer.json

# Export STIX bundle
detonate export <session_id> --format stix --output bundle.json

# Export Markdown report
detonate export <session_id> --format report --output report.md
```

### REST API

```bash
# Submit a sample for analysis
curl -X POST http://localhost:8000/api/v1/analyze \
    -F "file=@malware.exe" \
    -F "timeout=120"

# Check analysis status
curl http://localhost:8000/api/v1/analyze/<session_id>

# Download Navigator layer
curl http://localhost:8000/api/v1/reports/<session_id>/navigator \
    -o navigator.json

# Download STIX bundle
curl http://localhost:8000/api/v1/reports/<session_id>/stix \
    -o stix.json

# Download Markdown report
curl http://localhost:8000/api/v1/reports/<session_id>/report \
    -o report.md

# Stream JSON log
curl http://localhost:8000/api/v1/reports/<session_id>/log
```

Full API documentation available at `http://localhost:8000/docs` when the server is running.

## Output Formats

### 1. ATT&CK Navigator Layer

Interactive visualization of detected techniques. Load directly into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

```json
{
  "version": "4.5",
  "name": "detonate: malware.exe (4a8c...)",
  "techniques": [
    {
      "techniqueID": "T1055.001",
      "tactic": "defense-evasion",
      "score": 8,
      "comment": "CreateRemoteThread after WriteProcessMemory (confidence: high)"
    }
  ]
}
```

### 2. STIX 2.1 Bundle

Machine-readable threat intelligence format. Includes:

- `malware` object representing the analyzed sample
- `attack-pattern` objects for each detected technique
- `relationship` objects linking malware to techniques
- `observed-data` objects with API call evidence

Compatible with STIX/TAXII servers and threat intelligence platforms.

### 3. Markdown Report

Human-readable analysis report with:

- Sample information (hashes, file type, platform)
- Executive summary
- ATT&CK techniques table with confidence scores
- Detailed timeline of API calls per technique
- File system and network activity
- Strings of interest

### 4. Structured JSON Log

Real-time structured logs (JSON Lines format) for pipeline integration:

```json
{"event": "api_call", "api": "CreateProcessA", "technique_id": "T1059.001", "confidence": "high"}
{"event": "api_call", "api": "RegSetValueExA", "technique_id": "T1547.001", "confidence": "high"}
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Docker Container (isolated, no network, non-root)      │
│                                                         │
│  ┌──────────────┐    ┌──────────────────┐              │
│  │   FastAPI    │───▶│   Qiling         │              │
│  │   REST API   │    │   Emulator       │              │
│  └──────────────┘    └──────────────────┘              │
│         │                    │                          │
│         │              ┌──────────────────┐            │
│         │              │   ATT&CK         │            │
│         │              │   Mapping        │            │
│         │              │   Engine         │            │
│         │              └──────────────────┘            │
│         │                        │                     │
│  ┌──────────────┐    ┌───────────▼────────┐           │
│  │   SQLite     │    │   Output Pipeline  │           │
│  │   Database   │    │   (4 formats)      │           │
│  └──────────────┘    └────────────────────┘           │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Submission**: Binary submitted via CLI or REST API
2. **Emulation**: Qiling runs the binary with hooked APIs/syscalls
3. **Interception**: Hooks capture API parameters and return values
4. **Mapping**: Each call mapped to ATT&CK technique(s) with confidence scoring
5. **Pattern Detection**: Multi-call patterns (e.g., process injection chains) identified
6. **Output Generation**: Navigator, STIX, report, and log files produced
7. **Persistence**: All data stored in SQLite for later retrieval

## Security Model

This tool is designed for analyzing **untrusted code**. Key security properties:

| Property | Implementation |
|----------|----------------|
| **No native execution** | Binaries run in Qiling userspace emulator only |
| **Network isolation** | Docker network mode `none` or internal-only |
| **Read-only rootfs** | Container filesystem is read-only except tmpfs |
| **Non-root user** | Container runs as UID 1000 (`detonate` user) |
| **Dropped capabilities** | `cap_drop: ALL` in Docker configuration |
| **Resource limits** | CPU, memory, and PID limits enforced |
| **Timeout enforcement** | Analysis terminated after configurable timeout |
| **Sample handling** | Samples mounted read-only, never stored in image |

**Important**: Windows DLLs must be provided by the user. Do not use DLLs from production systems — use isolated test environments or clean Windows installations.

## ATT&CK Mapping

### Confidence Scoring

| Level | Score Range | Criteria |
|-------|-------------|----------|
| **High** | 0.8–1.0 | Direct API-to-technique match with confirming parameters |
| **Medium** | 0.5–0.79 | API match without parameter confirmation, or pattern match |
| **Low** | 0.2–0.49 | Heuristic match, suspicious but not definitive |

### Detected Patterns

The mapping engine recognizes multi-call behavior patterns:

| Pattern | Sequence | Technique |
|---------|----------|-----------|
| **Process Injection (Classic)** | `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` | T1055.001 |
| **Process Hollowing** | `CreateProcess` (suspended) → `NtUnmapViewOfSection` → `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread` | T1055.012 |
| **Registry Persistence** | `RegOpenKey` (Run key) → `RegSetValueEx` | T1547.001 |
| **DLL Side-Loading** | `CreateProcess` → `LoadLibrary` (unexpected path) | T1574.002 |

### Hooked APIs (Windows)

- **Process Execution**: `CreateProcessA/W`, `ShellExecuteA/W`, `WinExec`
- **Process Injection**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `SetThreadContext`
- **Registry**: `RegOpenKeyExA/W`, `RegQueryValueExA/W`, `RegSetValueExA/W`, `RegCreateKeyExA/W`
- **File Operations**: `CreateFileA/W`, `ReadFile`, `WriteFile`, `DeleteFileA/W`
- **Network**: `InternetOpenA/W`, `InternetConnectA/W`, `HttpOpenRequestA/W`, `socket`, `connect`
- **Privilege**: `AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValueA/W`
- **DLL Loading**: `LoadLibraryA/W`, `GetProcAddress`
- **Native APIs**: `NtCreateFile`, `NtOpenKey`, `NtSetValueKey`

### Hooked Syscalls (Linux)

- **Process Execution**: `execve`, `execveat`
- **Process Injection**: `ptrace`, `process_vm_writev`
- **File Operations**: `open`, `openat`, `read`, `write`, `unlink`
- **Network**: `socket`, `connect`, `sendto`, `recvfrom`
- **Privilege**: `setuid`, `setgid`, `setreuid`, `setregid`
- **Memory**: `mmap`, `mprotect`, `mremap`

## Testing

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/test_emulator.py
pytest tests/test_mapping.py
pytest tests/test_cli.py

# With coverage
pytest --cov=src/detonate --cov-report=html
```

Test binaries are provided in `examples/samples/` (benign test executables from Qiling).

## Project Structure

```
detonate/
├── src/detonate/
│   ├── cli.py                 # CLI entry point (typer)
│   ├── config.py              # Settings (pydantic-settings)
│   ├── api/                   # FastAPI REST API
│   │   ├── app.py
│   │   ├── routes.py
│   │   └── models.py
│   ├── core/                  # Emulation engine
│   │   ├── emulator.py
│   │   ├── session.py
│   │   └── hooks/
│   │       ├── windows.py
│   │       └── linux.py
│   ├── mapping/               # ATT&CK mapping
│   │   ├── engine.py
│   │   ├── patterns.py
│   │   └── stix_data.py
│   ├── output/                # Output generators
│   │   ├── navigator.py
│   │   ├── stix.py
│   │   ├── report.py
│   │   └── json_log.py
│   └── db/                    # Database layer
│       ├── models.py
│       └── store.py
├── data/
│   ├── attack_stix/           # MITRE ATT&CK STIX data
│   └── rootfs/                # Qiling rootfs (Linux)
├── tests/
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## Requirements

- Python 3.10+
- Qiling 1.4+
- FastAPI 0.115+
- SQLAlchemy 2.0+
- structlog 24+
- stix2 3.0+
- typer 0.12+

## License

MIT License — see LICENSE file.

## References

- [Qiling Framework](https://github.com/qilingframework/qiling)
- [MITRE ATT&CK](https://attack.mitre.org)
- [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1-part1-stix-core.html)

---

## Web UI

TODO: Prior implementation completed all Web UI pages (Dashboard, Submit, Analyses List, Analysis Detail, ATT&CK Navigator) but omitted documentation in README. Add a new "Web UI" section covering:
- Access instructions (http://localhost:8000/ after docker-compose up)
- Page descriptions (Dashboard stats, Submit form with drag-drop, Analyses list with filters/pagination, Detail view with 4 tabs, Navigator full matrix)
- Technical stack (PicoCSS v2, Chart.js, marked.js, vanilla JS only - no frameworks)
- Theme toggle (light/dark mode with localStorage persistence)
- Polling behavior (5-second intervals for running analyses, 10-minute max)
- Browser compatibility (Chrome, Firefox, Safari, Edge)
- Vendored dependencies location (web/js/, web/css/)
