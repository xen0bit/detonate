# Detonate — Implementation Plan

A Docker-based malware analysis platform using Qiling emulation, mapping observed behavior to MITRE ATT&CK techniques, with four output formats and both CLI + REST API interfaces.

---

## Table of Contents

1. [High-Level Architecture](#high-level-architecture)
2. [Project Structure](#project-structure)
3. [Component Specifications](#component-specifications)
4. [ATT&CK Mapping Reference](#attck-mapping-reference)
5. [Output Format Specifications](#output-format-specifications)
6. [REST API Specification](#rest-api-specification)
7. [CLI Specification](#cli-specification)
8. [Database Schema](#database-schema)
9. [Docker Configuration](#docker-configuration)
10. [Implementation Sequence](#implementation-sequence)
11. [Testing Strategy](#testing-strategy)
12. [Security Considerations](#security-considerations)

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Docker Container (multi-stage, hardened, no network)        │
│                                                              │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────┐ │
│  │   FastAPI    │───▶│   Qiling         │───▶│   Output   │ │
│  │   REST API   │    │   Emulator       │    │   Pipeline │ │
│  │   (port 8000)│    │   + Hooks        │    │            │ │
│  └──────────────┘    └──────────────────┘    └────────────┘ │
│         │                    │                    │          │
│         │              ┌──────────────────┐      │          │
│         │              │   ATT&CK         │      │          │
│         │              │   Mapping        │      │          │
│         │              │   Engine         │      │          │
│         │              └──────────────────┘      │          │
│         │                                        │          │
│  ┌──────────────┐    ┌──────────────────┐    ┌────────────┐ │
│  │   SQLite     │    │   structlog      │    │   STIX/    │ │
│  │   Database   │    │   JSON Logs      │    │   Navigator│ │
│  └──────────────┘    └──────────────────┘    └────────────┘ │
└──────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    ┌────▼────┐          ┌────▼────┐         ┌────▼────┐
    │ Samples │          │  DLLs   │         │ Output  │
    │  (ro)   │          │  (ro)   │         │  (rw)   │
    └─────────┘          └─────────┘         └─────────┘
```

### Data Flow

1. **Sample Submission**: User submits binary via CLI or REST API
2. **Emulation Setup**: Qiling instance configured with appropriate rootfs, hooks
3. **Execution**: Binary runs in emulated environment (timeout: 60s default)
4. **Hook Capture**: API calls/syscalls intercepted, mapped to ATT&CK techniques
5. **Log Streaming**: structlog emits JSON events in real-time
6. **Result Generation**: Navigator layer, STIX bundle, and report generated
7. **Persistence**: All data stored in SQLite database
8. **Output Delivery**: Results returned to user or stored for retrieval

---

## Project Structure

```
detonate/
├── Dockerfile                    # Multi-stage build (builder + runtime)
├── docker-compose.yml            # Compose config for API mode
├── docker-compose.cli.yml        # Compose config for CLI mode
├── pyproject.toml                # Project metadata, dependencies, scripts
├── poetry.lock                   # Poetry lock file
├── README.md                     # Project documentation
├── task.md                       # This implementation plan
├── .gitignore
├── .dockerignore
├── src/
│   └── detonate/
│       ├── __init__.py           # Package init, version info
│       ├── cli.py                # CLI entry point (typer-based)
│       ├── config.py             # Settings management (pydantic-settings)
│       │
│       ├── api/                  # FastAPI REST API
│       │   ├── __init__.py
│       │   ├── app.py            # FastAPI app factory
│       │   ├── routes.py         # API route handlers
│       │   ├── models.py         # Pydantic request/response models
│       │   └── middleware.py     # Request logging, error handling
│       │
│       ├── core/                 # Core emulation logic
│       │   ├── __init__.py
│       │   ├── emulator.py       # Qiling wrapper (setup, run, hooks)
│       │   ├── session.py        # Analysis session management
│       │   ├── timeout.py        # Execution timeout enforcement
│       │   └── hooks/            # API/syscall hook definitions
│       │       ├── __init__.py
│       │       ├── windows.py    # Windows API hooks → ATT&CK
│       │       └── linux.py      # Linux syscall hooks → ATT&CK
│       │
│       ├── mapping/              # ATT&CK mapping engine
│       │   ├── __init__.py
│       │   ├── engine.py         # Mapping logic, confidence scoring
│       │   ├── patterns.py       # Multi-call pattern detection
│       │   ├── windows_map.py    # Windows API → ATT&CK technique dict
│       │   ├── linux_map.py      # Linux syscall → ATT&CK technique dict
│       │   └── stix_data.py      # Load & query ATT&CK STIX data
│       │
│       ├── output/               # Output format generators
│       │   ├── __init__.py
│       │   ├── json_log.py       # structlog configuration
│       │   ├── navigator.py      # ATT&CK Navigator layer generator
│       │   ├── stix.py           # STIX 2.1 bundle generator
│       │   └── report.py         # Human-readable report (markdown)
│       │
│       ├── db/                   # Database layer
│       │   ├── __init__.py
│       │   ├── models.py         # SQLAlchemy ORM models
│       │   ├── store.py          # CRUD operations
│       │   └── init_db.py        # Database initialization
│       │
│       └── utils/                # Utility functions
│           ├── __init__.py
│           ├── hashing.py        # SHA256, file type detection
│           └── binary.py         # PE/ELF detection, architecture detection
│
├── data/
│   ├── attack_stix/              # MITRE ATT&CK STIX 2.1 JSON
│   │   └── enterprise-attack.json
│   └── rootfs/                   # Qiling rootfs (Linux bundled)
│       ├── x86_linux/
│       └── x8664_linux/
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures
│   ├── test_emulator.py          # Emulator wrapper tests
│   ├── test_mapping.py           # ATT&CK mapping tests
│   ├── test_output.py            # Output generator tests
│   ├── test_api.py               # REST API tests
│   └── test_cli.py               # CLI tests
│
└── examples/
    ├── samples/                  # Test malware samples (benign test binaries)
    └── outputs/                  # Example output files
```

---

## Component Specifications

### 1. Core Emulator (`core/emulator.py`)

**Class: `DetonateEmulator`**

```python
class DetonateEmulator:
    def __init__(
        self,
        sample_path: str,
        rootfs_path: str,
        platform: str = "auto",
        arch: str = "auto",
        timeout: int = 60,
    )
    
    async def run(self) -> AnalysisResult:
        """Run emulation and return results."""
    
    def _setup_hooks(self) -> None:
        """Configure Qiling hooks based on platform."""
    
    def _detect_platform(self) -> tuple[str, str]:
        """Auto-detect platform and architecture from binary."""
```

**Responsibilities:**
- Auto-detect binary type (PE/ELF) and architecture (x86/x86_64/ARM/ARM64)
- Initialize Qiling instance with appropriate rootfs
- Set up platform-specific hooks (Windows API or Linux syscall)
- Enforce execution timeout
- Capture exceptions and preserve partial results
- Return `AnalysisResult` dataclass with all captured data

**Key Qiling Integration Points:**
- `ql.os.set_api(api_name, callback)` for Windows API hooking
- `ql.hook_intno(callback, intno)` for Linux syscall interception
- `ql.os.stats.strings` for string extraction
- `ql.os.syscalls` for API call history
- `ql.mem.string(addr)` for reading strings from emulated memory

---

### 2. Hook Definitions (`core/hooks/`)

#### Windows Hooks (`windows.py`)

```python
# Hook callback signature
def hook_CreateProcessA(ql: Qiling) -> None:
    """Hook CreateProcessA to detect process execution."""
    # Read lpCommandLine parameter
    cmd_line = ql.mem.string(ql.os.f_param_read(1))
    
    # Map to ATT&CK based on command
    technique = detect_technique_from_command(cmd_line)
    
    # Emit structured log event
    log_event(
        event="api_call",
        api="CreateProcessA",
        params={"lpCommandLine": cmd_line},
        technique_id=technique.id,
        tactic=technique.tactic,
        confidence=technique.confidence,
    )
```

**Hooked Windows APIs (non-exhaustive):**

| Category | APIs |
|---|---|
| **Process Execution** | `CreateProcessA/W`, `ShellExecuteA/W`, `WinExec` |
| **Process Injection** | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `SetThreadContext` |
| **Registry Access** | `RegOpenKeyExA/W`, `RegQueryValueExA/W`, `RegSetValueExA/W`, `RegCreateKeyExA/W` |
| **File Operations** | `CreateFileA/W`, `ReadFile`, `WriteFile`, `DeleteFileA/W` |
| **Service Operations** | `CreateServiceA/W`, `StartServiceA/W`, `OpenServiceA/W` |
| **Network** | `InternetOpenA/W`, `InternetConnectA/W`, `HttpOpenRequestA/W`, `socket`, `connect`, `send`, `recv` |
| **Crypto** | `CryptEncrypt`, `CryptDecrypt`, `CryptGenKey` |
| **Privilege** | `AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValueA/W` |
| **DLL Loading** | `LoadLibraryA/W`, `GetProcAddress`, `LdrLoadDll` |
| **Synchronization** | `CreateMutexA/W`, `OpenMutexA/W` |
| **Native APIs** | `NtCreateFile`, `NtOpenKey`, `NtSetValueKey`, `NtCreateSection` |

#### Linux Hooks (`linux.py`)

```python
# Hook callback signature
def hook_syscall_execve(ql: Qiling) -> None:
    """Hook execve syscall to detect command execution."""
    filename = ql.mem.string(ql.arch.regs.rdi)  # x86_64
    argv = read_argv(ql.arch.regs.rsi)
    
    technique = detect_technique_from_command(filename, argv)
    
    log_event(
        event="syscall",
        syscall="execve",
        params={"filename": filename, "argv": argv},
        technique_id=technique.id,
        tactic=technique.tactic,
        confidence=technique.confidence,
    )
```

**Hooked Linux Syscalls (non-exhaustive):**

| Category | Syscalls |
|---|---|
| **Process Execution** | `execve`, `execveat` |
| **Process Injection** | `ptrace`, `process_vm_writev` |
| **File Operations** | `open`, `openat`, `read`, `write`, `unlink`, `unlinkat` |
| **Network** | `socket`, `connect`, `sendto`, `recvfrom`, `bind`, `listen` |
| **Process Management** | `clone`, `fork`, `vfork`, `kill` |
| **Privilege** | `setuid`, `setgid`, `setreuid`, `setregid` |
| **Memory** | `mmap`, `mprotect`, `mremap` |

---

### 3. ATT&CK Mapping Engine (`mapping/engine.py`)

**Class: `ATTCKMapper`**

```python
class ATTCKMapper:
    def __init__(self, stix_store: MemoryStore)
    
    def map_api_call(
        self,
        api_name: str,
        params: dict,
        platform: str,
    ) -> TechniqueMatch:
        """Map a single API call to ATT&CK technique(s)."""
    
    def detect_patterns(
        self,
        api_calls: list[APICall],
    ) -> list[PatternMatch]:
        """Detect multi-call patterns (e.g., process injection chain)."""
    
    def get_technique_metadata(
        self,
        technique_id: str,
    ) -> TechniqueMetadata:
        """Retrieve technique metadata from STIX data."""
```

**Confidence Scoring:**

| Confidence Level | Score | Criteria |
|---|---|---|
| **High** | 0.8–1.0 | Direct API-to-technique match with confirming parameters |
| **Medium** | 0.5–0.79 | API match without parameter confirmation, or pattern match |
| **Low** | 0.2–0.49 | Heuristic match, suspicious but not definitive |

**Pattern Detection Examples:**

| Pattern | Sequence | ATT&CK Technique |
|---|---|---|
| **Process Injection (Classic)** | `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` | T1055.001 |
| **Process Hollowing** | `CreateProcess` (suspended) → `NtUnmapViewOfSection` → `VirtualAllocEx` → `WriteProcessMemory` → `SetThreadContext` → `ResumeThread` | T1055.012 |
| **DLL Side-Loading** | `CreateProcess` → `LoadLibrary` (unexpected path) | T1574.002 |
| **Registry Persistence** | `RegOpenKey` (Run key) → `RegSetValueEx` | T1547.001 |

---

### 4. Output Generators (`output/`)

#### Structured JSON Logs (`json_log.py`)

```python
# structlog configuration
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.PrintLoggerFactory(sys.stdout),
)

# Usage in hooks
log = structlog.get_logger()
log.bind(
    session_id=session_id,
    sample_sha256=sample_hash,
    platform=platform,
)
log.info(
    "api_call",
    technique_id="T1059.001",
    technique_name="PowerShell",
    tactic="execution",
    confidence="high",
    api="CreateProcessA",
    params={"lpCommandLine": "powershell -enc ..."},
    return_value=True,
)
```

**Log Event Schema:**
```json
{
  "event": "api_call|syscall|pattern_detected|analysis_complete",
  "timestamp": "2026-04-20T18:45:00Z",
  "session_id": "uuid4",
  "sample_sha256": "hex string",
  "platform": "windows|linux",
  "architecture": "x86|x86_64|arm|arm64",
  "technique_id": "TXXXX.XXX",
  "technique_name": "Technique Name",
  "tactic": "tactic-name",
  "confidence": "high|medium|low",
  "api": "API name",
  "syscall": "Syscall name",
  "params": {...},
  "return_value": ...,
  "address": "0x00000000"
}
```

#### Navigator Layer Generator (`navigator.py`)

```python
def generate_navigator_layer(
    session_id: str,
    sample_hash: str,
    findings: list[TechniqueMatch],
) -> dict:
    """Generate ATT&CK Navigator layer JSON."""
```

**Output Format:**
```json
{
  "version": "4.5",
  "name": "detonate: malware.exe (4a8c...)",
  "domain": "enterprise-attack",
  "description": "Analysis of sample 4a8c... on 2026-04-20",
  "techniques": [
    {
      "techniqueID": "T1059.001",
      "tactic": "execution",
      "score": 8,
      "color": "#ff6666",
      "comment": "CreateProcessA → powershell -enc (confidence: high)",
      "enabled": true,
      "showSubtechniques": true,
      "metadata": [
        {"name": "api", "value": "CreateProcessA"},
        {"name": "confidence", "value": "high"},
        {"name": "evidence_count", "value": "3"}
      ]
    }
  ],
  "gradient": {
    "colors": ["#ffffff", "#ff6666", "#ff0000"],
    "minValue": 0,
    "maxValue": 10
  },
  "legendItems": [
    {"color": "#ff6666", "label": "Low confidence"},
    {"color": "#ff0000", "label": "High confidence"}
  ],
  "filters": {
    "platforms": ["Windows"]
  }
}
```

**Score Calculation:**
```
score = confidence_score × 10 × log(evidence_count + 1)
```

#### STIX 2.1 Bundle Generator (`stix.py`)

```python
def generate_stix_bundle(
    session_id: str,
    sample_hash: str,
    sample_path: str,
    findings: list[TechniqueMatch],
    api_calls: list[APICall],
) -> Bundle:
    """Generate STIX 2.1 bundle with ATT&CK mappings."""
```

**Bundle Contents:**

1. **`malware` object** (the sample):
```json
{
  "type": "malware",
  "id": "malware--<uuid>",
  "name": "sample_4a8c...",
  "is_family": false,
  "external_references": [
    {
      "source_name": "detonate",
      "external_id": "4a8c...",
      "description": "SHA256 hash of analyzed sample"
    }
  ]
}
```

2. **`attack-pattern` objects** (techniques):
```json
{
  "type": "attack-pattern",
  "id": "attack-pattern--<uuid>",
  "name": "PowerShell",
  "external_references": [
    {
      "source_name": "mitre-attack",
      "external_id": "T1059.001",
      "url": "https://attack.mitre.org/techniques/T1059/001/"
    }
  ],
  "kill_chain_phases": [
    {
      "kill_chain_name": "mitre-attack",
      "phase_name": "execution"
    }
  ]
}
```

3. **`relationship` objects** (malware uses technique):
```json
{
  "type": "relationship",
  "id": "relationship--<uuid>",
  "relationship_type": "uses",
  "source_ref": "malware--<uuid>",
  "target_ref": "attack-pattern--<uuid>",
  "description": "CreateProcessA called with powershell.exe"
}
```

4. **`observed-data` objects** (API call evidence):
```json
{
  "type": "observed-data",
  "id": "observed-data--<uuid>",
  "objects": {
    "0": {
      "type": "windows-registry-ext",
      "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    }
  },
  "first_observed": "2026-04-20T18:45:00Z",
  "last_observed": "2026-04-20T18:45:01Z",
  "number_observed": 1
}
```

#### Human-Readable Report Generator (`report.py`)

```python
def generate_report(
    session_id: str,
    sample_info: SampleInfo,
    findings: list[TechniqueMatch],
    api_calls: list[APICall],
) -> str:
    """Generate Markdown report."""
```

**Report Structure:**

```markdown
# Detonate Analysis Report

## Sample Information

| Field | Value |
|-------|-------|
| SHA256 | 4a8c... |
| MD5 | ... |
| File Type | PE32 executable |
| Platform | Windows x86 |
| Analysis Date | 2026-04-20 18:45:00 UTC |
| Duration | 45.2 seconds |

## Executive Summary

This sample exhibited behavior consistent with **8 ATT&CK techniques** across **5 tactics**.
Notable findings include process injection patterns and registry persistence mechanisms.

## ATT&CK Techniques Detected

| Technique ID | Technique Name | Tactic | Confidence | Evidence Count |
|--------------|----------------|--------|------------|----------------|
| T1055.001 | Dynamic-link Library Injection | Defense Evasion | High | 5 |
| T1547.001 | Registry Run Keys | Persistence | High | 3 |
| T1059.001 | PowerShell | Execution | Medium | 2 |

## Detailed Findings

### T1055.001 - Dynamic-link Library Injection

**Confidence:** High  
**Tactic:** Defense Evasion  
**Evidence:** 5 API calls

**Timeline:**
```
18:45:00.123 - OpenProcess(PROCESS_ALL_ACCESS, pid=1234)
18:45:00.156 - VirtualAllocEx(hProcess, 0x1000, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
18:45:00.189 - WriteProcessMemory(hProcess, 0x1000, ..., 0x500)
18:45:00.222 - CreateRemoteThread(hProcess, 0x1000, ...)
```

### T1547.001 - Registry Run Keys

**Confidence:** High  
**Tactic:** Persistence  
**Evidence:** 3 API calls

**Timeline:**
```
18:45:01.001 - RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
18:45:01.034 - RegSetValueExA("malware", "C:\\Windows\\malware.exe")
```

## Network Activity

No network activity observed.

## File System Activity

| Path | Operation | Result |
|------|-----------|--------|
| C:\Windows\malware.exe | CreateFile | SUCCESS |
| C:\Users\Public\config.ini | WriteFile | SUCCESS |

## Strings of Interest

- `powershell -enc`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `http://malicious-domain.com/beacon`

## Output Files

- Navigator Layer: `navigator_4a8c.json`
- STIX Bundle: `stix_4a8c.json`
- JSON Log: `log_4a8c.jsonl`
```

---

## REST API Specification

### Base URL

```
http://localhost:8000/api/v1
```

### Endpoints

#### `POST /analyze`

Submit a sample for analysis.

**Request:**
```
Content-Type: multipart/form-data

file: <binary file>
platform: "auto" | "windows" | "linux"  (optional, default: "auto")
arch: "auto" | "x86" | "x86_64" | "arm" | "arm64"  (optional, default: "auto")
timeout: <int seconds>  (optional, default: 60)
```

**Response (202 Accepted):**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "created_at": "2026-04-20T18:45:00Z"
}
```

**Errors:**
- `400 Bad Request`: Invalid file type, missing file
- `422 Unprocessable Entity`: Invalid parameters
- `500 Internal Server Error`: Emulation failure

---

#### `GET /analyze/{session_id}`

Get analysis status and results.

**Response (200 OK):**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "sample": {
    "sha256": "4a8c...",
    "md5": "...",
    "size": 12345,
    "file_type": "PE32 executable",
    "platform": "windows",
    "architecture": "x86"
  },
  "analysis": {
    "started_at": "2026-04-20T18:45:00Z",
    "completed_at": "2026-04-20T18:45:45Z",
    "duration_seconds": 45.2,
    "techniques_detected": 8,
    "tactics_observed": ["execution", "defense-evasion", "persistence"]
  },
  "findings": [
    {
      "technique_id": "T1055.001",
      "technique_name": "Dynamic-link Library Injection",
      "tactic": "defense-evasion",
      "confidence": "high",
      "evidence_count": 5
    }
  ],
  "outputs": {
    "navigator": "/api/v1/reports/550e8400/navigator",
    "stix": "/api/v1/reports/550e8400/stix",
    "report": "/api/v1/reports/550e8400/report",
    "log": "/api/v1/reports/550e8400/log"
  }
}
```

**Status Values:**
- `pending`: Queued for analysis
- `running`: Currently emulating
- `completed`: Analysis finished successfully
- `failed`: Analysis failed (timeout, crash, error)

---

#### `GET /reports/{session_id}/navigator`

Download ATT&CK Navigator layer JSON.

**Response (200 OK):**
```
Content-Type: application/json
Content-Disposition: attachment; filename="navigator_4a8c.json"

{... Navigator layer JSON ...}
```

---

#### `GET /reports/{session_id}/stix`

Download STIX 2.1 bundle.

**Response (200 OK):**
```
Content-Type: application/json
Content-Disposition: attachment; filename="stix_4a8c.json"

{... STIX bundle JSON ...}
```

---

#### `GET /reports/{session_id}/report`

Download human-readable Markdown report.

**Response (200 OK):**
```
Content-Type: text/markdown
Content-Disposition: attachment; filename="report_4a8c.md"

# Detonate Analysis Report
...
```

---

#### `GET /reports/{session_id}/log`

Stream structured JSON log.

**Response (200 OK):**
```
Content-Type: application/x-jsonlines

{"event": "analysis_started", ...}
{"event": "api_call", ...}
{"event": "api_call", ...}
{"event": "analysis_complete", ...}
```

---

#### `GET /reports`

List all past analyses (paginated).

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `status`: Filter by status (`completed`, `failed`, `running`)
- `platform`: Filter by platform (`windows`, `linux`)

**Response (200 OK):**
```json
{
  "items": [
    {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "sample_sha256": "4a8c...",
      "platform": "windows",
      "status": "completed",
      "created_at": "2026-04-20T18:45:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "pages": 8
}
```

---

#### `DELETE /reports/{session_id}`

Delete an analysis and its data.

**Response (204 No Content)**

---

#### `GET /health`

Health check endpoint.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

---

## CLI Specification

### Entry Point

```bash
detonate <command> [options]
```

### Commands

#### `detonate analyze`

Analyze a sample file.

```bash
detonate analyze <sample_path> [options]
```

**Options:**
- `--platform`: `auto` | `windows` | `linux` (default: `auto`)
- `--arch`: `auto` | `x86` | `x86_64` | `arm` | `arm64` (default: `auto`)
- `--rootfs`: Path to rootfs directory (required for Windows samples)
- `--dlls`: Path to Windows DLLs directory (required for Windows samples)
- `--timeout`: Timeout in seconds (default: 60)
- `--format`: Output formats: `json`, `navigator`, `stix`, `report`, `all` (default: `all`)
- `--output`: Output directory (default: current directory)
- `--verbose`: Enable verbose logging
- `--quiet`: Suppress output except errors

**Examples:**
```bash
# Analyze Windows PE with all outputs
detonate analyze malware.exe --rootfs ./rootfs/x86_windows --dlls ./dlls --output ./results

# Analyze Linux ELF, JSON output only
detonate analyze linux_bin --format json --output ./results

# Analyze with custom timeout
detonate analyze slow_malware.exe --timeout 120 --rootfs ./rootfs/x86_windows
```

**Output Files:**
```
./results/
├── navigator_4a8c.json
├── stix_4a8c.json
├── report_4a8c.md
└── log_4a8c.jsonl
```

---

#### `detonate serve`

Start the REST API server.

```bash
detonate serve [options]
```

**Options:**
- `--host`: Bind host (default: `127.0.0.1`)
- `--port`: Bind port (default: `8000`)
- `--workers`: Number of worker processes (default: 1)
- `--database`: SQLite database path (default: `/var/lib/detonate/detonate.db`)
- `--rootfs`: Default rootfs path for Windows samples
- `--dlls`: Default DLLs path for Windows samples
- `--verbose`: Enable verbose logging

**Examples:**
```bash
# Start server on default port
detonate serve

# Start server accessible from network
detonate serve --host 0.0.0.0 --port 8000

# Start with custom database location
detonate serve --database ./data/detonate.db
```

---

#### `detonate list`

List past analyses from the database.

```bash
detonate list [options]
```

**Options:**
- `--status`: Filter by status (`completed`, `failed`, `running`)
- `--platform`: Filter by platform (`windows`, `linux`)
- `--limit`: Maximum results (default: 20)
- `--format`: `table` | `json` (default: `table`)

**Examples:**
```bash
# List recent analyses
detonate list

# List failed Windows analyses
detonate list --status failed --platform windows

# Output as JSON
detonate list --format json
```

---

#### `detonate show`

Show details of a specific analysis.

```bash
detonate show <session_id> [options]
```

**Options:**
- `--format`: `summary` | `full` | `json` (default: `summary`)

---

#### `detonate export`

Export analysis results to various formats.

```bash
detonate export <session_id> --format <format> --output <path>
```

**Options:**
- `--format`: `navigator` | `stix` | `report` | `log`
- `--output`: Output file path

---

#### `detonate db init`

Initialize the SQLite database.

```bash
detonate db init --database <path>
```

---

#### `detonate db migrate`

Run database migrations.

```bash
detonate db migrate --database <path>
```

---

## Database Schema

### Table: `analyses`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal ID |
| `session_id` | TEXT | UNIQUE NOT NULL | UUID4 session identifier |
| `sample_sha256` | TEXT | NOT NULL | SHA256 hash of sample |
| `sample_md5` | TEXT | | MD5 hash of sample |
| `sample_path` | TEXT | NOT NULL | Path to sample file |
| `sample_size` | INTEGER | NOT NULL | File size in bytes |
| `file_type` | TEXT | | Detected file type (PE32, ELF, etc.) |
| `platform` | TEXT | NOT NULL | `windows` or `linux` |
| `architecture` | TEXT | NOT NULL | `x86`, `x86_64`, `arm`, `arm64` |
| `status` | TEXT | NOT NULL | `pending`, `running`, `completed`, `failed` |
| `error_message` | TEXT | | Error message if failed |
| `created_at` | DATETIME | NOT NULL | Analysis start time |
| `completed_at` | DATETIME | | Analysis completion time |
| `duration_seconds` | REAL | | Execution duration |

**Indexes:**
- `idx_analyses_session_id` (UNIQUE)
- `idx_analyses_sample_sha256`
- `idx_analyses_status`
- `idx_analyses_created_at`

---

### Table: `findings`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal ID |
| `analysis_id` | INTEGER | FOREIGN KEY → analyses.id | Parent analysis |
| `technique_id` | TEXT | NOT NULL | ATT&CK technique ID (e.g., T1059.001) |
| `technique_name` | TEXT | NOT NULL | ATT&CK technique name |
| `tactic` | TEXT | NOT NULL | ATT&CK tactic name |
| `confidence` | TEXT | NOT NULL | `high`, `medium`, `low` |
| `confidence_score` | REAL | NOT NULL | Numeric confidence (0.0–1.0) |
| `evidence_count` | INTEGER | NOT NULL | Number of API calls supporting this finding |
| `first_seen` | DATETIME | NOT NULL | First occurrence timestamp |
| `last_seen` | DATETIME | NOT NULL | Last occurrence timestamp |

**Indexes:**
- `idx_findings_analysis_id`
- `idx_findings_technique_id`
- `idx_findings_tactic`

---

### Table: `api_calls`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal ID |
| `analysis_id` | INTEGER | FOREIGN KEY → analyses.id | Parent analysis |
| `timestamp` | DATETIME | NOT NULL | Call timestamp |
| `api_name` | TEXT | | Windows API name |
| `syscall_name` | TEXT | | Linux syscall name |
| `address` | TEXT | | Call address in hex |
| `params_json` | TEXT | | JSON-encoded parameters |
| `return_value` | TEXT | | Return value (stringified) |
| `technique_id` | TEXT | | Mapped ATT&CK technique ID |
| `confidence` | TEXT | | Mapping confidence |

**Indexes:**
- `idx_api_calls_analysis_id`
- `idx_api_calls_api_name`
- `idx_api_calls_technique_id`

---

### Table: `strings`

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | Internal ID |
| `analysis_id` | INTEGER | FOREIGN KEY → analyses.id | Parent analysis |
| `value` | TEXT | NOT NULL | String value |
| `address` | TEXT | | Address where string was found |
| `context` | TEXT | | Context (API param, memory, etc.) |

**Indexes:**
- `idx_strings_analysis_id`

---

## Docker Configuration

### Dockerfile (Multi-Stage)

```dockerfile
# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.12-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy project files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --no-root --only main

# Copy source code
COPY src/ ./src/

# Download ATT&CK STIX data
RUN mkdir -p data/attack_stix && \
    curl -sL https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
    -o data/attack_stix/enterprise-attack.json

# Copy Qiling Linux rootfs (from submodule or manual copy)
COPY rootfs/x86_linux/ ./data/rootfs/x86_linux/
COPY rootfs/x8664_linux/ ./data/rootfs/x8664_linux/

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM python:3.12-slim AS runtime

# Create non-root user
RUN groupadd --gid 1000 detonate && \
    useradd --uid 1000 --gid detonate --shell /bin/bash --create-home detonate

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/src /app/src
COPY --from=builder /build/data /app/data

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    DETONATE_DATABASE=/var/lib/detonate/detonate.db \
    DETONATE_ROOTFS=/app/data/rootfs

# Create data directories
RUN mkdir -p /var/lib/detonate /output /samples && \
    chown -R detonate:nogroup /var/lib/detonate /output /app

# Switch to non-root user
USER detonate

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://127.0.0.1:8000/api/v1/health')" || exit 1

# Expose API port
EXPOSE 8000

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["serve"]
```

### docker-compose.yml (API Mode)

```yaml
version: '3.8'

services:
  detonate:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: detonate-api
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    networks:
      - isolated
    tmpfs:
      - /tmp:noexec,nosuid,size=512m
      - /dev/shm:noexec,nosuid,size=256m
    volumes:
      # Windows DLLs (user-provided)
      - ./dlls/x86:/opt/rootfs/x86_windows/dlls:ro
      - ./dlls/x86_64:/opt/rootfs/x8664_windows/dlls:ro
      # Sample input
      - ./samples:/samples:ro
      # Output directory
      - ./output:/output:rw
      # Database persistence
      - ./data/db:/var/lib/detonate:rw
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - DETONATE_DATABASE=/var/lib/detonate/detonate.db
      - DETONATE_ROOTFS=/app/data/rootfs
      - DETONATE_DLLS_X86=/opt/rootfs/x86_windows/dlls
      - DETONATE_DLLS_X64=/opt/rootfs/x8664_windows/dlls
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
          pids: 100
        reservations:
          cpus: '1'
          memory: 1G
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://127.0.0.1:8000/api/v1/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

networks:
  isolated:
    internal: true
    driver: bridge
```

### docker-compose.cli.yml (CLI Mode)

```yaml
version: '3.8'

services:
  detonate:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: detonate-cli
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    networks:
      - none
    tmpfs:
      - /tmp:noexec,nosuid,size=512m
    volumes:
      - ./dlls/x86:/opt/rootfs/x86_windows/dlls:ro
      - ./dlls/x86_64:/opt/rootfs/x8664_windows/dlls:ro
      - ./samples:/samples:ro
      - ./output:/output:rw
    environment:
      - DETONATE_ROOTFS=/app/data/rootfs
      - DETONATE_DLLS_X86=/opt/rootfs/x86_windows/dlls
      - DETONATE_DLLS_X64=/opt/rootfs/x8664_windows/dlls
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
          pids: 100
    network_mode: none
```

### .dockerignore

```
.git
.gitignore
*.md
!README.md
task.md
tests/
examples/
*.pyc
__pycache__
.venv
.pytest_cache
.mypy_cache
.coverage
htmlcov/
data/db/
output/
samples/
dlls/
```

---

## ATT&CK Mapping Reference

### Windows API → ATT&CK Techniques

| API | Technique ID | Technique Name | Tactic | Confidence Base |
|-----|--------------|----------------|--------|-----------------|
| `CreateProcessA/W` | T1106 | Native API | Execution | Medium |
| `CreateProcessA/W` (cmd.exe) | T1059.003 | Windows Command Shell | Execution | High |
| `CreateProcessA/W` (powershell) | T1059.001 | PowerShell | Execution | High |
| `CreateProcessA/W` (mshta) | T1059.005 | Visual Basic | Execution | High |
| `CreateProcessA/W` (wscript/cscript) | T1059.005 | Visual Basic | Execution | High |
| `CreateProcessA/W` (rundll32) | T1059.007 | JavaScript | Execution | Medium |
| `ShellExecuteA/W` | T1106 | Native API | Execution | Medium |
| `WinExec` | T1106 | Native API | Execution | Medium |
| `VirtualAllocEx` | T1055.012 | Process Hollowing | Defense Evasion | Medium |
| `WriteProcessMemory` | T1055 | Process Injection | Defense Evasion | Low |
| `CreateRemoteThread` | T1055.001 | Dynamic-link Library Injection | Defense Evasion | High |
| `NtCreateThreadEx` | T1055.001 | Dynamic-link Library Injection | Defense Evasion | High |
| `SetThreadContext` | T1055.012 | Process Hollowing | Defense Evasion | High |
| `ResumeThread` (suspended process) | T1055.012 | Process Hollowing | Defense Evasion | High |
| `NtUnmapViewOfSection` | T1055.012 | Process Hollowing | Defense Evasion | High |
| `RegOpenKeyExA/W` (Run) | T1547.001 | Registry Run Keys | Persistence | High |
| `RegOpenKeyExA/W` (RunOnce) | T1547.001 | Registry Run Keys | Persistence | High |
| `RegSetValueExA/W` (Run) | T1547.001 | Registry Run Keys | Persistence | High |
| `RegCreateKeyExA/W` | T1547.001 | Registry Run Keys | Persistence | Medium |
| `RegQueryValueExA/W` | T1012 | Query Registry | Discovery | Medium |
| `CreateServiceA/W` | T1543.003 | Windows Service | Persistence | High |
| `StartServiceA/W` | T1543.003 | Windows Service | Persistence | Medium |
| `OpenServiceA/W` | T1543.003 | Windows Service | Persistence | Low |
| `InternetOpenA/W` | T1071.001 | Web Protocols | Command & Control | Medium |
| `InternetConnectA/W` | T1071.001 | Web Protocols | Command & Control | High |
| `HttpOpenRequestA/W` | T1071.001 | Web Protocols | Command & Control | High |
| `socket` | T1071 | Application Layer Protocol | Command & Control | Low |
| `connect` | T1071 | Application Layer Protocol | Command & Control | Medium |
| `CryptEncrypt` | T1486 | Data Encrypted for Impact | Impact | Low |
| `CryptDecrypt` | T1486 | Data Encrypted for Impact | Impact | Low |
| `AdjustTokenPrivileges` | T1134 | Access Token Manipulation | Defense Evasion | Medium |
| `OpenProcessToken` | T1134 | Access Token Manipulation | Defense Evasion | Low |
| `LookupPrivilegeValueA/W` | T1134 | Access Token Manipulation | Defense Evasion | Low |
| `LoadLibraryA/W` | T1055.001 | Dynamic-link Library Injection | Defense Evasion | Low |
| `GetProcAddress` | T1055.001 | Dynamic-link Library Injection | Defense Evasion | Low |
| `CreateMutexA/W` | T1012 | Query Registry | Discovery | Low |
| `CreateFileA/W` (remote path) | T1083 | File and Directory Discovery | Discovery | Medium |
| `DeleteFileA/W` | T1070.004 | File Deletion | Defense Evasion | Medium |
| `NtCreateFile` | T1106 | Native API | Execution | Low |
| `NtOpenKey` | T1012 | Query Registry | Discovery | Medium |
| `NtSetValueKey` | T1547.001 | Registry Run Keys | Persistence | High |

### Linux Syscall → ATT&CK Techniques

| Syscall | Technique ID | Technique Name | Tactic | Confidence Base |
|---------|--------------|----------------|--------|-----------------|
| `execve` (bash) | T1059.004 | Unix Shell | Execution | High |
| `execve` (sh) | T1059.004 | Unix Shell | Execution | High |
| `execve` (python) | T1059.006 | Python | Execution | High |
| `execve` (perl) | T1059.007 | JavaScript | Execution | Medium |
| `execve` (ruby) | T1059.007 | JavaScript | Execution | Medium |
| `ptrace` | T1055.008 | Ptrace System Calls | Defense Evasion | High |
| `process_vm_writev` | T1055 | Process Injection | Defense Evasion | High |
| `clone` (suspicious flags) | T1055 | Process Injection | Defense Evasion | Medium |
| `open` (/etc/passwd) | T1003.008 | /etc/passwd and /etc/shadow | Credential Access | High |
| `openat` (/etc/shadow) | T1003.008 | /etc/passwd and /etc/shadow | Credential Access | High |
| `connect` (external IP) | T1071 | Application Layer Protocol | Command & Control | Medium |
| `socket` | T1071 | Application Layer Protocol | Command & Control | Low |
| `sendto` | T1071 | Application Layer Protocol | Command & Control | Medium |
| `recvfrom` | T1071 | Application Layer Protocol | Command & Control | Medium |
| `setuid` | T1548.001 | Setuid and Setgid | Privilege Escalation | High |
| `setgid` | T1548.001 | Setuid and Setgid | Privilege Escalation | High |
| `mmap` (RWX) | T1055 | Process Injection | Defense Evasion | Medium |
| `mprotect` (RWX) | T1055 | Process Injection | Defense Evasion | Medium |

---

## Implementation Sequence

### Phase 1: Project Scaffolding (Day 1)

- [ ] Create project structure with `src/`, `tests/`, `data/` directories
- [ ] Initialize `pyproject.toml` with Poetry
- [ ] Add dependencies: `qiling`, `structlog`, `fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `typer`, `stix2`
- [ ] Create `.gitignore`, `.dockerignore`
- [ ] Set up basic logging configuration
- [ ] Create `config.py` with pydantic-settings

### Phase 2: ATT&CK Data & Mapping (Day 2-3)

- [ ] Download enterprise-attack.json STIX data
- [ ] Implement `mapping/stix_data.py` to load and query STIX data
- [ ] Create `mapping/windows_map.py` with API → technique dictionary
- [ ] Create `mapping/linux_map.py` with syscall → technique dictionary
- [ ] Implement `mapping/engine.py` with confidence scoring logic
- [ ] Implement `mapping/patterns.py` for multi-call pattern detection
- [ ] Write unit tests for mapping engine

### Phase 3: Core Emulator (Day 4-5)

- [ ] Implement `core/emulator.py` with `DetonateEmulator` class
- [ ] Add platform/architecture auto-detection
- [ ] Implement Qiling initialization and configuration
- [ ] Add timeout enforcement mechanism
- [ ] Implement exception handling and partial result preservation
- [ ] Create `core/session.py` for session management
- [ ] Write integration tests with test binaries

### Phase 4: Hook Definitions (Day 6-8)

- [ ] Implement `core/hooks/windows.py` with Windows API hooks
- [ ] Implement `core/hooks/linux.py` with Linux syscall hooks
- [ ] Add parameter inspection logic for context-aware mapping
- [ ] Integrate hooks with structlog for JSON event emission
- [ ] Test hooks with known malware samples (or benign test binaries)

### Phase 5: Output Generators (Day 9-11)

- [ ] Configure `output/json_log.py` with structlog
- [ ] Implement `output/navigator.py` for Navigator layer generation
- [ ] Implement `output/stix.py` for STIX 2.1 bundle generation
- [ ] Implement `output/report.py` for Markdown report generation
- [ ] Test all output formats with sample analysis runs

### Phase 6: Database Layer (Day 12-13)

- [ ] Create `db/models.py` with SQLAlchemy ORM models
- [ ] Implement `db/store.py` with CRUD operations
- [ ] Create `db/init_db.py` for database initialization
- [ ] Add migration support (alembic or custom)
- [ ] Write database tests

### Phase 7: CLI Interface (Day 14-15)

- [ ] Implement `cli.py` with typer-based commands
- [ ] Add `analyze`, `serve`, `list`, `show`, `export` commands
- [ ] Implement progress bars and status output
- [ ] Add verbose/quiet logging modes
- [ ] Test CLI with various sample types

### Phase 8: REST API (Day 16-18)

- [ ] Create `api/app.py` with FastAPI app factory
- [ ] Implement `api/routes.py` with all endpoints
- [ ] Create `api/models.py` with Pydantic models
- [ ] Add `api/middleware.py` for request logging and error handling
- [ ] Implement file upload handling
- [ ] Add background task support for async analysis
- [ ] Write API tests with TestClient

### Phase 9: Docker Configuration (Day 19-20)

- [ ] Create multi-stage `Dockerfile`
- [ ] Create `docker-compose.yml` for API mode
- [ ] Create `docker-compose.cli.yml` for CLI mode
- [ ] Create `docker/entrypoint.sh` script
- [ ] Test Docker builds and container execution
- [ ] Document DLL acquisition and mounting process

### Phase 10: Testing & Integration (Day 21-23)

- [ ] Write comprehensive unit tests for all components
- [ ] Create integration tests with real binaries
- [ ] Test end-to-end analysis workflow
- [ ] Test all output formats
- [ ] Performance testing and optimization
- [ ] Security testing (container isolation, resource limits)

### Phase 11: Documentation (Day 24-25)

- [ ] Write comprehensive README.md
- [ ] Create API documentation (OpenAPI/Swagger)
- [ ] Document CLI usage with examples
- [ ] Create Docker deployment guide
- [ ] Document ATT&CK mapping methodology
- [ ] Add troubleshooting guide

### Phase 12: Polish & Release (Day 26-28)

- [ ] Code review and refactoring
- [ ] Final performance optimization
- [ ] Create example outputs in `examples/outputs/`
- [ ] Tag v0.1.0 release
- [ ] Publish to GitHub
- [ ] Create Docker Hub image

---

## Testing Strategy

### Unit Tests

- **Mapping Engine**: Test API → technique mapping with various inputs
- **Confidence Scoring**: Verify scoring logic for different scenarios
- **Pattern Detection**: Test multi-call pattern recognition
- **Output Generators**: Validate JSON structure and content
- **Database Operations**: Test CRUD operations in isolation

### Integration Tests

- **Emulator**: Run known binaries and verify hook capture
- **API Hooks**: Test Windows API hooks with PE executables
- **Syscall Hooks**: Test Linux syscall hooks with ELF binaries
- **End-to-End**: Full analysis pipeline from submission to output

### Test Binaries

Use benign test binaries for testing:
- `examples/rootfs/x86_linux/bin/x86_hello` (Qiling-provided)
- `examples/rootfs/x86_windows/bin/x86_hello.exe` (Qiling-provided)
- Custom test programs that call specific APIs (CreateProcess, RegSetValue, etc.)

### API Tests

- Test all REST endpoints with TestClient
- Test file upload and download
- Test pagination and filtering
- Test error handling and validation

### Docker Tests

- Verify container starts and health check passes
- Test CLI mode with sample analysis
- Test API mode with sample submission
- Verify resource limits and isolation

---

## Security Considerations

### Container Isolation

- **No network**: Default network mode is `none` or internal-only
- **Read-only filesystem**: Root filesystem is read-only except tmpfs mounts
- **Non-root user**: Container runs as `detonate` user (UID 1000)
- **Dropped capabilities**: All capabilities dropped (`cap_drop: ALL`)
- **Resource limits**: CPU, memory, and PID limits enforced
- **Seccomp/AppArmor**: Optional additional confinement profiles

### Sample Handling

- **Read-only mounts**: Samples mounted as read-only
- **Hash tracking**: All samples tracked by SHA256 hash
- **No storage in image**: Samples never stored in container image
- **Automatic cleanup**: Containers removed after execution (`--rm`)

### Emulation Safety

- **Qiling isolation**: Malware runs in emulated environment, not natively
- **Timeout enforcement**: Analysis terminated after timeout period
- **Exception handling**: Crashes contained within emulator
- **No native execution**: Binary never executes on host system

### API Security

- **Authentication**: Optional API key authentication (future enhancement)
- **Rate limiting**: Request rate limiting to prevent abuse
- **Input validation**: All inputs validated and sanitized
- **File type checking**: Verify uploaded files are valid binaries

### Data Protection

- **Database encryption**: Optional database encryption at rest
- **Log sanitization**: Sensitive data removed from logs
- **Access control**: Role-based access control for API (future)

---

## Dependencies

### Python Dependencies (pyproject.toml)

```toml
[tool.poetry]
name = "detonate"
version = "0.1.0"
description = "Malware analysis platform with ATT&CK mapping"
authors = ["Your Name <you@example.com>"]

[tool.poetry.dependencies]
python = "^3.10"
qiling = "^1.4"
structlog = "^24"
fastapi = "^0.115"
uvicorn = {extras = ["standard"], version = "^0.32"}
sqlalchemy = "^2.0"
pydantic = "^2.0"
pydantic-settings = "^2.0"
typer = {extras = ["all"], version = "^0.12"}
stix2 = "^3.0"
python-multipart = "^0.0"
aiofiles = "^24.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"
pytest-asyncio = "^0.23"
httpx = "^0.27"  # For TestClient
black = "^24.0"
ruff = "^0.6"
mypy = "^1.0"

[tool.poetry.scripts]
detonate = "detonate.cli:app"
```

### System Dependencies (Docker)

- `build-essential`: For keystone-engine compilation
- `cmake`: Build system for native dependencies
- `git`: For cloning submodules
- `libffi-dev`: For cffi bindings

---

## Future Enhancements

### Phase 2+ Features

- [ ] **Symbolic Execution**: Integrate with angr for path exploration
- [ ] **Fuzzing**: AFL-based fuzzing via unicornafl
- [ ] **YARA Integration**: YARA rule scanning on samples
- [ ] **Network Simulation**: FakeNet-NG integration for network emulation
- [ ] **Multi-sample Analysis**: Correlate behavior across multiple samples
- [ ] **Machine Learning**: ML-based classification of behavior patterns
- [ ] **Threat Intelligence**: Auto-enrichment with VirusTotal, MalwareBazaar APIs
- [ ] **Distributed Analysis**: Scale across multiple containers/nodes
- [ ] **Web UI**: React-based dashboard for analysis management
- [ ] **Plugin System**: Extensible hook and output format plugins

### ATT&CK Mapping Improvements

- [ ] **Sub-technique refinement**: More granular sub-technique mapping
- [ ] **Confidence calibration**: Improve confidence scoring accuracy
- [ ] **Context enrichment**: Use file paths, registry keys, network indicators for better mapping
- [ ] **Tactic inference**: Infer tactics from technique sequences
- [ ] **MITRE D3FEND**: Map defensive techniques to observed behavior

---

## References

- **Qiling Framework**: https://github.com/qilingframework/qiling
- **Qiling Documentation**: https://docs.qiling.io
- **MITRE ATT&CK**: https://attack.mitre.org
- **ATT&CK STIX Data**: https://github.com/mitre-attack/attack-stix-data
- **ATT&CK Navigator**: https://github.com/mitre-attack/attack-navigator
- **STIX 2.1 Specification**: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1-part1-stix-core.html
- **structlog**: https://www.structlog.org
- **FastAPI**: https://fastapi.tiangolo.com
- **CAPE Sandbox**: https://github.com/kevoreilly/CAPEv2

---

## Notes

- Windows DLLs must be provided by the user due to licensing restrictions
- Qiling's Windows emulation requires DLLs from the target Windows version
- Linux rootfs can be bundled in the Docker image (no licensing issues)
- ATT&CK STIX data is ~15MB and should be bundled for offline use
- Default timeout of 60 seconds is sufficient for most malware samples
- SQLite is sufficient for single-instance deployments; consider PostgreSQL for multi-user setups
