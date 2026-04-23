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

## Rootfs Setup

Detonate uses Qiling's official rootfs repository for Linux emulation. The rootfs is managed as a git submodule.

### First-Time Setup

```bash
# Option 1: Clone with submodules (recommended)
git clone --recursive https://github.com/xen0bit/detonate.git
cd detonate

# Option 2: Initialize submodules after cloning
git clone https://github.com/xen0bit/detonate.git
cd detonate
make rootfs-init
```

### Manual Rootfs Commands

```bash
# Initialize rootfs submodule
make rootfs-init

# Update to latest rootfs version
make rootfs-update

# List available architectures
make rootfs-list

# Remove rootfs (frees ~200MB)
make rootfs-clean
```

### Supported Architectures

| Priority | Platform | Architectures | Rootfs Directory | Status |
|----------|----------|--------------|------------------|--------|
| **High** | Linux | x86_64, x86, arm64 | `data/qiling_rootfs/<arch>_linux` | ✅ Tested |
| **Medium** | Linux | arm, mips, mipsel | `data/qiling_rootfs/<arch>_linux` | ⚠️ Community support |
| **Low** | Linux | riscv64 | `data/qiling_rootfs/riscv64_linux` | 🧪 Experimental |
| **User-provided** | Windows | x86, x86_64 | `data/rootfs/<arch>_windows/dlls` | 📝 See below |

### Architecture Aliases

Detonate automatically recognizes architecture aliases:

| Canonical | Aliases |
|-----------|---------|
| `x86_64` | `x64`, `amd64` |
| `x86` | `i386`, `i686` |
| `arm64` | `aarch64` |
| `arm` | `armv7` |
| `mips` | `mips32` |
| `mipsel` | `mips32el` |

### Windows DLL Setup

Windows rootfs is **not included** due to licensing restrictions. Users must provide their own Windows DLLs.

**Quick setup:**
```bash
# Create directories
mkdir -p data/rootfs/x86_windows/dlls
mkdir -p data/rootfs/x8664_windows/dlls

# Copy DLLs from Windows VM (see WINDOWS_DLL_SETUP.md)
# Required: kernel32.dll, ntdll.dll
```

📖 **See [WINDOWS_DLL_SETUP.md](WINDOWS_DLL_SETUP.md) for complete instructions.**

### Troubleshooting

**Rootfs not found errors:**
```bash
# Verify submodule is initialized
git submodule status

# Re-initialize if needed
make rootfs-init
```

**Architecture not recognized:**
```bash
# Check available rootfs
make rootfs-list

# Verify rootfs has required files
ls data/qiling_rootfs/x8664_linux/lib64/ld-linux-x86-64.so.2
```

**Windows DLL errors:**
```bash
# Check if DLLs exist
ls data/rootfs/x8664_windows/dlls/

# See detailed setup guide
cat WINDOWS_DLL_SETUP.md
```

**Go binaries fail to emulate:**
- Ensure rootfs is properly initialized: `make rootfs-init`
- Check for Go runtime errors in logs
- Try C sample (`trigger_syscalls_c`) as alternative
- Report specific error messages for troubleshooting

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

# Analyze with architecture alias
detonate analyze sample --arch amd64  # Same as x86_64
detonate analyze sample --arch aarch64  # Same as arm64
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

Detonate includes a modern, responsive web interface for submitting binaries, monitoring analyses, and exploring results.

### Access

After starting the server:

```bash
# Start the API server
uvicorn src.detonate.main:app --host 0.0.0.0 --port 8000
```

Then open your browser to:

- **Default URL**: `http://localhost:8000/web/index.html`
- **API Base**: `http://localhost:8000/api/v1`

**Authentication**: Currently no authentication is required. For production deployments, place behind a reverse proxy with authentication.

---

### Pages

#### Dashboard (`/web/index.html`)

System overview and quick access to recent activity.

**Features:**
- **Statistics Cards**: Total analyses, completed, running, failed
- **Activity Chart**: 30-day analysis trend (Chart.js line graph)
- **Recent Analyses Table**: Last 10 analyses with session ID, filename, platform, status, techniques count, and relative timestamp
- **Quick Actions**: Direct link to submit new analysis

![Dashboard Placeholder](_resources/screenshots/dashboard.png)

---

#### Submit Analysis (`/web/submit.html`)

Upload and configure new analysis jobs.

**Features:**
- **Drag-and-Drop Upload**: Drop binary files or click to browse
- **Platform Selection**: Auto-detect, Linux, or Windows
- **Architecture Selection**: Auto-detect, x86_64, x86, arm64, arm, mips, mipsel, riscv64
- **Timeout Configuration**: 1-300 seconds (default: 60s)
- **Progress Tracking**: Real-time status updates after submission
- **File Information**: Displays filename, size, and SHA256 hash before submission

![Submit Placeholder](_resources/screenshots/submit.png)

---

#### Analyses List (`/web/analyses.html`)

Browse, filter, and manage all analysis jobs.

**Features:**
- **Filtering**: By status (pending/running/completed/failed), platform (linux/windows), or search term
- **Pagination**: 20 items per page, configurable
- **Bulk Selection**: Select multiple analyses for batch deletion
- **Table Columns**:
  - Session ID (truncated, clickable)
  - Filename
  - SHA256 hash (with copy button)
  - Platform
  - Status badge (color-coded)
  - Techniques detected
  - Created timestamp
  - Actions (View, Delete)

![Analyses List Placeholder](_resources/screenshots/analyses_list.png)

---

#### Analysis Detail (`/web/analysis.html`)

Deep dive into a single analysis with four tabs:

**1. Overview Tab**
- File size, platform, architecture
- Sample hashes (MD5, SHA256) with copy buttons
- File type detection
- Timeline (submitted, started, completed, duration)
- Executive summary
- Tactics distribution chart (Chart.js bar graph)

**2. ATT&CK Techniques Tab**
- Matrix view of detected techniques grouped by tactic
- Color-coded by confidence (high/medium/low)
- Click any technique for detailed modal:
  - Technique ID and name
  - Tactic classification
  - Confidence level and score
  - Evidence count
  - API call evidence list
  - Link to MITRE ATT&CK website

**3. API Calls Tab**
- Paginated timeline of intercepted API calls
- Filter by API name or technique ID
- Export as JSON or CSV
- Columns: Sequence number, timestamp, API name, parameters (expandable), technique ID

**4. Reports Tab**
- Download buttons for all report formats:
  - ATT&CK Navigator Layer (JSON)
  - STIX 2.1 Bundle (JSON)
  - Markdown Report
  - JSON Log (JSONL)
- Live Markdown preview (rendered with marked.js)

![Analysis Detail Placeholder](_resources/screenshots/analysis_detail.png)

---

#### ATT&CK Navigator (`/web/navigator.html`)

Full-screen MITRE ATT&CK matrix visualization.

**Features:**
- **Tactic Grid**: All tactics as columns, techniques as color-coded cards
- **Confidence Legend**: High (70%+), Medium (40-69%), Low (<40%)
- **Search/Filter**: By technique ID, name, or tactic; minimum confidence threshold
- **Statistics**: Total techniques, breakdown by confidence level
- **Export**: Download as ATT&CK Navigator layer JSON
- **Technique Modal**: Full details with API evidence and MITRE links

![Navigator Placeholder](_resources/screenshots/navigator.png)

---

### Technical Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **CSS Framework** | PicoCSS v2 | Minimal, semantic HTML styling |
| **Custom CSS** | `web/css/custom.css` | Theme variables, component styles |
| **Charts** | Chart.js | Activity graphs, tactics distribution |
| **Markdown** | marked.js | Markdown report rendering |
| **JavaScript** | Vanilla ES6+ | No frameworks (React/Vue/jQuery) |
| **Backend** | FastAPI | Server-side rendering + REST API |
| **Templating** | FastAPI Templates | HTML served via static files |

**Design Principles:**
- Zero build step required
- No npm/node dependencies
- Single-file vendored libraries
- Works offline after initial load

---

### Theme System

**Light/Dark Mode Toggle:**
- Toggle button in navigation bar (🌙 Dark / ☀️ Light)
- Persists selection in `localStorage`
- Respects system preference (`prefers-color-scheme`)
- Applies to all pages instantly

**Theme Variables:**
```css
:root {
  --primary: #d32f2f;          /* Red accent color */
  --primary-hover: #b71c1c;
  --technique-high: rgba(255, 0, 0, 0.15);
  --technique-medium: rgba(255, 102, 0, 0.15);
  --technique-low: rgba(255, 170, 0, 0.15);
}
```

Dark mode adjusts technique backgrounds, chart colors, and text contrast automatically.

---

### Polling Behavior

For analyses in `pending` or `running` status:

- **Polling Interval**: 5 seconds
- **Auto-Stop**: Stops polling when status changes to `completed` or `failed`
- **Maximum Duration**: 10 minutes (600 seconds)
- **Manual Refresh**: Refresh button on analysis detail page
- **Visual Indicator**: Spinning icon + "Polling for updates..." message

**Polling Endpoint:**
```javascript
GET /api/v1/analyze/{session_id}
```

**Response includes:**
```json
{
  "session_id": "...",
  "status": "running",
  "techniques_count": 5,
  "completed_at": null,
  "duration_seconds": null
}
```

---

### Browser Compatibility

| Browser | Minimum Version | Notes |
|---------|----------------|-------|
| Chrome | 90+ | Full support |
| Firefox | 88+ | Full support |
| Safari | 14+ | Full support |
| Edge | 90+ | Full support |
| Mobile Safari | iOS 14+ | Touch-optimized |
| Mobile Chrome | Android 10+ | Touch-optimized |

**Required Features:**
- ES6+ JavaScript (arrow functions, async/await, fetch API)
- CSS Grid and Flexbox
- localStorage API
- Clipboard API (with fallback)
- Canvas API (for Chart.js)

---

### Vendored Dependencies

All third-party libraries are vendored in the `web/` directory:

```
web/
├── css/
│   ├── pico.min.css         # PicoCSS v2.0.6 (minified)
│   └── custom.css           # Detonate theme and components
├── js/
│   ├── chart.min.js         # Chart.js 4.4.1 (minified)
│   ├── marked.min.js        # marked.js 9.1.2 (minified)
│   ├── app.js               # Shared utilities (theme, toast, formatting)
│   ├── dashboard.js         # Dashboard page logic
│   ├── analyses.js          # Analyses list page logic
│   ├── submit.js            # Submit page logic
│   ├── analysis.js          # Analysis detail page logic
│   └── navigator.js         # ATT&CK Navigator page logic
├── index.html               # Dashboard
├── analyses.html            # Analyses list
├── submit.html              # Submit analysis
├── analysis.html            # Analysis detail
└── navigator.html           # ATT&CK Navigator
```

**No external CDN dependencies** - all resources load from local `web/` directory.

---

### API Endpoints

The Web UI consumes these REST API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze` | POST | Submit new analysis (multipart form with file) |
| `/api/v1/analyze/{session_id}` | GET | Get analysis status and results |
| `/api/v1/reports` | GET | List analyses with pagination and filters |
| `/api/v1/reports/{session_id}/navigator` | GET | Download ATT&CK Navigator layer |
| `/api/v1/reports/{session_id}/stix` | GET | Download STIX 2.1 bundle |
| `/api/v1/reports/{session_id}/report` | GET | Download Markdown report |
| `/api/v1/reports/{session_id}/log` | GET | Download JSONL event log |
| `/api/v1/reports/{session_id}` | DELETE | Delete analysis |
| `/api/v1/analyses/{session_id}/api_calls` | GET | Paginated API calls |
| `/api/v1/analyses/{session_id}/findings` | GET | Paginated ATT&CK findings |

---

### Troubleshooting

#### Issue: Page shows "Failed to load" errors

**Cause:** API server not running or CORS misconfiguration.

**Solution:**
```bash
# Verify server is running
curl http://localhost:8000/api/v1/reports

# Check CORS settings in main.py
# Should include: app.add_middleware(CORSMiddleware, ...)
```

---

#### Issue: Polling stops working

**Cause:** Network interruption or server restart.

**Solution:**
- Click manual refresh button
- Reload page (analysis state persists in database)
- Check browser console for errors

---

#### Issue: Dark mode not persisting

**Cause:** Browser localStorage blocked or cleared.

**Solution:**
- Ensure cookies/localStorage not blocked for localhost
- Check browser privacy settings
- Theme defaults to system preference if localStorage unavailable

---

#### Issue: Charts not rendering

**Cause:** Chart.js not loaded or canvas size issue.

**Solution:**
- Open browser DevTools → Console for errors
- Verify `web/js/chart.min.js` loads (check Network tab)
- Ensure container has explicit height (charts need defined dimensions)

---

#### Issue: File upload fails

**Cause:** File too large or timeout.

**Solution:**
- Check server logs for size limits
- Increase timeout for large binaries
- Verify file is valid ELF/PE binary
