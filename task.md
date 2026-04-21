# Detonate — Comprehensive Fix Plan

## Project Overview

**detonate** is a Docker-based malware analysis platform that uses Qiling emulation to observe binary behavior and map it to MITRE ATT&CK techniques. It produces four output formats (ATT&CK Navigator layers, STIX 2.1 bundles, Markdown reports, and structured JSON logs) through both a CLI and a REST API.

The project has a well-structured codebase with 32 source files, comprehensive tests (199 passing), and a Docker deployment setup. However, it cannot actually build, run, or function end-to-end due to several critical issues.

---

## Issue Inventory

### Issue 1: Qiling Constructor API Mismatch (Critical)

**File:** `src/detonate/core/emulator.py:166-181`

**Problem:** The `_run_emulation()` method passes `archname=` and `ostype=` as strings to `Qiling()`, but the installed Qiling (v1.4+) uses different parameter names and enum types:

```python
# Current (broken):
ql = Qiling(
    argv=[str(self.sample_path)],
    rootfs=str(self.rootfs_path),
    archname=ql_arch,     # Wrong parameter name
    ostype=profile,         # Wrong parameter name and type
    console=False,
)
```

**Correct API:**
```python
from qiling.const import QL_ARCH, QL_OS

ql = Qiling(
    argv=[str(self.sample_path)],
    rootfs=str(self.rootfs_path),
    archtype=QL_ARCH.X8664,  # Enum, not string
    ostype=QL_OS.LINUX,       # Enum, not string
    console=False,
)
```

**Verified:** `Qiling(argv=['/bin/true'], rootfs='/', archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, console=False)` works correctly.

**Fix:**
- Add `from qiling.const import QL_ARCH, QL_OS` to emulator.py
- Replace `arch_map` dict with proper enum mapping
- Change `archname=` to `archtype=` and `ostype=` to use `QL_OS` enum
- Pass `console=False` to suppress Qiling's default stdout output

---

### Issue 2: Empty Rootfs Directories (Critical)

**Files:** `data/rootfs/x86_linux/`, `data/rootfs/x8664_linux/`

**Problem:** Both rootfs directories are empty. Qiling requires a rootfs with at minimum the dynamic linker (`ld-linux-*`) and libc to emulate dynamically-linked binaries. When empty rootfs paths are passed, Qiling fails with:

```
FileNotFoundError: [Errno 2] No such file or directory: '.../lib64/ld-linux-x86-64.so.2'
```

**Fix:**
- For **local development** on Linux, default the rootfs to `/` (the system root) when no custom rootfs is specified. This allows analyzing local Linux binaries without needing a separate rootfs.
- For **Docker deployment**, the rootfs should be populated either by downloading Qiling's default rootfs or by copying the minimal required files from the container's filesystem.
- Update `config.py` `get_rootfs_path()` to return `/` for Linux when the configured rootfs directory is empty or doesn't contain the expected structure.
- Add a `--rootfs` default that falls back intelligently: if `/` is a valid Linux root (has `/lib64/ld-linux-x86-64.so.2` or `/lib/ld-linux.so.2`), use it; otherwise require explicit `--rootfs`.

---

### Issue 3: Default Database Path Permission Error (High)

**File:** `src/detonate/config.py:18`

**Problem:** Default database path `/var/lib/detonate/detonate.db` requires root permissions. Running `detonate analyze` locally fails with:

```
PermissionError: [Errno 13] Permission denied: '/var/lib/detonate'
```

**Fix:**
- Change default `database` setting from `/var/lib/detonate/detonate.db` to `./data/detonate.db` (relative to current directory)
- Keep the Docker/deployment default as `/var/lib/detonate/detonate.db` via the `DETONATE_DATABASE` environment variable (which docker-compose.yml already sets)
- Update `init_database()` to create parent directories (it already does `path.parent.mkdir(parents=True, exist_ok=True)`)

---

### Issue 4: Linux Syscall Hooking API Incorrect (Critical)

**File:** `src/detonate/core/hooks/linux.py` — `install()` method (~line 100)

**Problem:** The `install()` method uses two incorrect Qiling APIs:

```python
# Current (broken):
for syscall_num, hook_func in self.hooks.items():
    try:
        self.ql.hook_intno(hook_func, syscall_num)        # Wrong: this hooks int 0x80, not syscall instruction
        self.ql.hook_syscall(self._capture_return_value, syscall_num)  # Wrong: hook_syscall doesn't exist on ql
    except Exception as e:
        log.debug("hook_install_failed", syscall=syscall_num, error=str(e))
```

**Issues:**
1. `ql.hook_intno(callback, intno)` hooks software interrupts (int 0x80), NOT the `syscall` instruction used by x86_64 Linux. This means none of the Linux syscall hooks actually fire.
2. `ql.hook_syscall` does not exist as a method on `Qiling` — it exists on `ql.os` as `ql.os.hook_syscall()`, but that's also not the correct way to hook individual syscalls by name/number.

**Correct API (verified):**
```python
# Use ql.os.set_syscall() for hooking individual syscalls by name or number:
# ql.os.set_syscall(target, handler, intercept=QL_INTERCEPT.CALL)
# target: syscall name (str) or number (int)
# handler: callback function receiving the ql instance
```

The `set_syscall` method is inherited from `QlOsPosix` and works for both Linux and other POSIX OSes. It supports:
- `QL_INTERCEPT.CALL` — replace the syscall implementation entirely
- `QL_INTERCEPT.ENTER` — run handler before the syscall
- `QL_INTERCEPT.EXIT` — run handler after the syscall (for return value capture)

**Fix:**
- Replace `install()` to use `self.ql.os.set_syscall(name_or_number, handler)` for each syscall
- Use syscall names (strings) where possible: `"execve"`, `"openat"`, etc. — these are more portable than numbers
- For return value capture, use `QL_INTERCEPT.EXIT` or wrap handlers to read return values after the call
- Remove the `_capture_return_value` method that relies on the non-existent `ql.hook_syscall`
- The Linux hook handler methods (e.g., `hook_sys_execve`) need to be updated to match Qiling's expected callback signature: `def handler(ql)` — they currently receive `(ql, intno)` which is the `hook_intno` signature

**Additional issue with hook callbacks:** The current Linux hooks are written with the wrong signature. They expect `(ql, intno)` from `hook_intno`, but `set_syscall` handlers receive just `(ql)`. The hooks also read parameters using `ql.os.f_param_read()` which is a Windows/PE-specific API — Linux syscalls read parameters from registers (e.g., `ql.os.f_param_read()` doesn't exist for Linux). Linux syscalls pass arguments in registers:
- x86_64: rdi, rsi, rdx, r10, r8, r9
- Access via: `ql.reg.read(ql.reg.read("rdi"))` or `ql.os.get_syscall_arg(0)`, etc.

This is a significant rewrite of `linux.py`. The correct approach for reading syscall parameters on Linux is:

```python
# For x86_64 Linux:
arg0 = ql.os.get_syscall_arg(0)  # rdi
arg1 = ql.os.get_syscall_arg(1)  # rsi
# etc.

# Or directly via registers:
arg0 = ql.reg.read("rdi")
```

And for reading strings from memory (e.g., filename for open/openat):
```python
filename = ql.mem.string(arg0)
```

**This means the entire `linux.py` hook implementation needs to be rewritten to use the correct register-based parameter reading instead of `ql.os.f_param_read()` which is Windows-only.**

---

### Issue 5: Deprecated `datetime.utcnow()` (Medium)

**File:** `src/detonate/output/navigator.py:120`

**Problem:** Uses `datetime.utcnow()` which is deprecated in Python 3.12+ (13 deprecation warnings in tests).

```python
# Current:
analysis_date = datetime.utcnow()
```

**Fix:**
```python
from datetime import timezone
analysis_date = datetime.now(timezone.utc)
```

Also update test files that use `datetime.utcnow()` in `tests/test_navigator.py`.

---

### Issue 6: Docker Build Failures (Medium)

**File:** `Dockerfile`

**Problems:**
1. `COPY data/rootfs/x86_linux/ ./data/rootfs/x86_linux/` — these directories are empty, Docker `COPY` of empty directories fails or creates no content
2. `COPY pyproject.toml poetry.lock ./` — `poetry.lock` doesn't exist, causing `COPY` to fail
3. `RUN poetry install --no-root --only main` — will fail without `poetry.lock`
4. Healthcheck uses `python -c "import requests; ..."` but `requests` is not a dependency

**Fix:**
- Generate `poetry.lock` by running `poetry lock` locally and commit it
- For rootfs: either download Qiling's rootfs during Docker build, or copy from the container's own filesystem
- For the healthcheck, use `curl` (which is already installed) or `python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health')"`
- Add a step to download ATT&CK STIX data (currently curl's from GitHub, which is fine)

---

### Issue 7: Docker Compose Healthcheck (Medium)

**File:** `docker-compose.yml:47`

**Problem:** Healthcheck uses Python `requests` library which is not a project dependency:

```yaml
test: ["CMD", "python", "-c", "import requests; requests.get('http://127.0.0.1:8000/api/v1/health')"]
```

**Fix:** Use `curl` (already installed in the Docker image):

```yaml
test: ["CMD", "curl", "-sf", "http://127.0.0.1:8000/api/v1/health"]
```

Or use Python's built-in `urllib`:

```yaml
test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health')"]
```

---

### Issue 8: No Safe Test Samples (High)

**Directory:** `examples/samples/` (empty)

**Problem:** There are no sample binaries for end-to-end testing. The README mentions "Test binaries are provided in `examples/samples/`" but the directory is empty. Windows PE analysis requires user-provided DLLs (licensing concern), but we can provide:

1. **Minimal safe ELF x86_64 binary** — a tiny program that does `exit(0)`, suitable for testing Linux analysis end-to-end
2. **Minimal safe ELF x86 binary** — same but 32-bit
3. **Safe ELF that triggers observable syscalls** — a program that calls `open("/etc/passwd", O_RDONLY)`, `read()`, `write()`, `socket()`, etc. so we can verify hooks are working
4. **Minimal PE header (for Windows detection testing)** — just the MZ/PE header bytes so `is_pe()` detection works, not a functional PE

**Fix:** Create these samples using the system's `gcc` or assembler. The "trigger" binary should be safe (no actual malicious behavior) but should exercise interesting syscall patterns.

Implementation plan for safe test samples:
- `examples/samples/hello_x8664` — minimal ELF that prints "Hello" and exits (tests basic emulation)
- `examples/samples/minimal_x8664` — minimal ELF that just does `exit(0)` (tests shortest path)
- `examples/samples/trigger_x8664` — safe ELF that calls open/read/write/setuid/socket (tests hook coverage)
- `examples/samples/fake_pe_x86.exe` — minimal PE header bytes only (tests PE detection, not execution)

---

## Implementation Order

### Phase 1: Core Emulator Fixes (Critical Path)

These fixes are needed just to get `detonate analyze` working at all.

1. **Fix `emulator.py`** — Update Qiling constructor to use `QL_ARCH`/`QL_OS` enums
2. **Fix `config.py`** — Change default database path and rootfs fallback logic
3. **Fix `linux.py`** — Rewrite syscall hooking to use `ql.os.set_syscall()` with correct callback signatures and register-based parameter reading
4. **Update `windows.py`** — Minor: `f_param_read()` is correct for Windows, but verify it works with current Qiling API

### Phase 2: Safe Test Samples

5. **Create safe ELF test binaries** — Build using `gcc` or assembler
6. **Create a mock PE header** for detection testing
7. **Add end-to-end test script** that analyzes the test samples and verifies output

### Phase 3: Quality & Deployment Fixes

8. **Fix `navigator.py`** — Replace `datetime.utcnow()` with `datetime.now(timezone.utc)`
9. **Fix Dockerfile** — Generate `poetry.lock`, handle empty rootfs, fix healthcheck
10. **Fix `docker-compose.yml`** — Fix healthcheck command
11. **Populate rootfs** — Add script or documentation for setting up Linux rootfs

### Phase 4: Verification

12. **Run full test suite** — `pytest` must pass (199 tests)
13. **End-to-end CLI test** — `detonate analyze` with safe samples produces all 4 output formats
14. **End-to-end API test** — `detonate serve` starts and responds to health check

---

## Detailed Fix Specifications

### Fix 1: `src/detonate/core/emulator.py`

```python
# Replace the arch_map and Qiling() call in _run_emulation():

# OLD:
arch_map = {
    "x86": "x86",
    "x86_64": "x8664",
    "arm": "arm",
    "arm64": "arm64",
}
ql_arch = arch_map.get(self.architecture, "x86")
# ...
profile = "windows" if self.platform == "windows" else "linux"
ql = Qiling(
    argv=[str(self.sample_path)],
    rootfs=str(self.rootfs_path),
    archname=ql_arch,
    ostype=profile,
    console=False,
)

# NEW:
from qiling.const import QL_ARCH, QL_OS

arch_map = {
    "x86": QL_ARCH.X86,
    "x86_64": QL_ARCH.X8664,
    "arm": QL_ARCH.ARM,
    "arm64": QL_ARCH.ARM64,
}
ql_arch = arch_map.get(self.architecture, QL_ARCH.X8664)

os_map = {
    "windows": QL_OS.WINDOWS,
    "linux": QL_OS.LINUX,
}
ql_os = os_map.get(self.platform, QL_OS.LINUX)

ql = Qiling(
    argv=[str(self.sample_path)],
    rootfs=str(self.rootfs_path),
    archtype=ql_arch,
    ostype=ql_os,
    console=False,
)
```

Also update `get_rootfs_path()` in `config.py` and the path resolution logic to default to `/` for Linux when no explicit rootfs is given and the configured path doesn't exist or is empty.

### Fix 2: `src/detonate/config.py`

```python
# Change default database path from /var/lib/detonate/detonate.db to ./data/detonate.db
database: str = "./data/detonate.db"

# Update get_rootfs_path() to fall back to system rootfs for Linux:
def get_rootfs_path(self, platform: str, arch: str) -> Path:
    path = Path(self.rootfs) / platform_map.get(platform, "x86_linux")
    # For Linux, fall back to system rootfs if custom rootfs is empty/missing
    if platform == "linux" and not _is_valid_rootfs(path):
        return Path("/")  # Use host filesystem as rootfs
    return path

def _is_valid_rootfs(path: Path) -> bool:
    """Check if the rootfs path contains the minimum required files."""
    if not path.exists():
        return False
    # Check for dynamic linker presence
    ld_paths = [
        path / "lib64" / "ld-linux-x86-64.so.2",
        path / "lib" / "ld-linux.so.2",
    ]
    return any(p.exists() for p in ld_paths)
```

### Fix 3: `src/detonate/core/hooks/linux.py`

Major rewrite needed. The `install()` method must use `ql.os.set_syscall()` with the correct callback signatures. Hook callbacks receive just `(ql)` and read parameters from registers via `ql.reg.read()` or `ql.os.get_syscall_arg()`.

Key changes:
- Replace `ql.hook_intno()` + `ql.hook_syscall()` with `ql.os.set_syscall(name, handler)`
- Change all hook callbacks from `(ql, intno)` to `(ql)`
- Replace `ql.os.f_param_read(n)` (Windows-specific) with `ql.reg.read()` or `ql.os.get_syscall_arg(n)` for Linux
- Use `ql.mem.string(addr)` for reading string arguments from memory
- For return value capture, either use `QL_INTERCEPT.EXIT` or check `ql.reg.read("rax")` after the syscall

### Fix 4: `src/detonate/output/navigator.py`

Replace all `datetime.utcnow()` with `datetime.now(timezone.utc)`. Also update test file `tests/test_navigator.py` correspondingly.

### Fix 5: Test Samples

Create using system compiler:

```bash
# hello_x8664 — minimal ELF that exits(0)
cat > /tmp/hello.S << 'EOF'
.global _start
_start:
    mov $60, %rax    # sys_exit
    xor %rdi, %rdi   # exit code 0
    syscall
EOF
as -o hello_x8664.o hello_x8664.S && ld -o hello_x8664 hello_x8664.o

# trigger_x8664 — safe ELF that exercises interesting syscalls
# (open /etc/passwd for reading, read, write to stdout, socket, setuid)
# This should be a simple C program compiled statically
```

### Fix 6: Dockerfile Updates

- Remove `COPY poetry.lock` line or make it conditional
- Add step to populate Linux rootfs from container filesystem
- Fix healthcheck to use `curl` instead of `python requests`
- Add `poetry.lock` generation step

### Fix 7: docker-compose.yml Healthcheck

```yaml
# Replace:
test: ["CMD", "python", "-c", "import requests; requests.get('http://127.0.0.1:8000/api/v1/health')"]
# With:
test: ["CMD", "curl", "-sf", "http://127.0.0.1:8000/api/v1/health"]
```

---

## Verification Checklist

After all fixes are applied:

- [ ] `pytest` passes (199+ tests)
- [ ] `detonate analyze /bin/ls --platform linux --arch x86_64` completes without error
- [ ] `detonate analyze /bin/true --platform linux --arch x86_64 --format all` produces all 4 output files
- [ ] `detonate serve` starts without error
- [ ] `curl http://localhost:8000/health` returns healthy status
- [ ] `detonate db init` creates database
- [ ] `detonate list-analyses` shows results
- [ ] `detonate export <session_id> --format report` produces markdown
- [ ] `detonate export <session_id> --format navigator` produces valid Navigator JSON
- [ ] `detonate export <session_id> --format stix` produces valid STIX bundle
- [ ] `detonate export <session_id> --format log` produces valid JSONL
- [ ] Safe test samples in `examples/samples/` work end-to-end
- [ ] `docker build -t detonate:latest .` succeeds