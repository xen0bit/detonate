# Qiling Rootfs Submodule Integration - Implementation Plan

## Executive Summary

Integrate the official Qiling rootfs repository (`https://github.com/qilingframework/rootfs.git`) as a git submodule to enable reliable emulation of complex binaries (including Go) and extend detonate to support all major architectures provided by Qiling.

**Key Benefits:**
- ✅ Proper system libraries for all architectures (x86_64, x86, arm64, arm, mips, mipsel, riscv64)
- ✅ Improved Go binary emulation (proper libc, dynamic linker)
- ✅ Multi-architecture support with automatic detection
- ✅ Simplified setup via `make rootfs-init`
- ✅ Clear Windows DLL documentation for users

**Priority:** Focus on x86_64, x86, arm64 first (high priority), then extend to other architectures incrementally.

---

## Table of Contents

1. [Implementation Phases](#implementation-phases)
2. [File Changes](#file-changes)
3. [User Flows](#user-flows)
4. [Testing & Validation](#testing--validation)
5. [Acceptance Criteria](#acceptance-criteria)
6. [Troubleshooting Guide](#troubleshooting-guide)

---

## Implementation Phases

### Phase 1: Git Submodule Setup

**Objective:** Add Qiling rootfs as git submodule with shallow clone for fast initialization.

**Commands:**
```bash
# Initialize submodule (shallow clone, depth=1)
git submodule add --depth 1 https://github.com/qilingframework/rootfs.git data/qiling_rootfs

# Verify submodule
git submodule status

# Expected output:
# <commit-hash> data/qiling_rootfs (heads/master)
```

**Directory Structure After Phase 1:**
```
detonate/
├── data/
│   ├── qiling_rootfs/              # NEW: Git submodule
│   │   ├── x8664_linux/
│   │   │   ├── bin/
│   │   │   ├── lib/
│   │   │   ├── lib64/
│   │   │   ├── etc/
│   │   │   └── kernel/
│   │   ├── x86_linux/
│   │   ├── arm64_linux/
│   │   ├── arm_linux/
│   │   ├── mips32_linux/
│   │   ├── mips32el_linux/
│   │   ├── riscv64_linux/
│   │   └── ... (all Qiling architectures)
│   └── rootfs/                     # Existing (for Windows DLLs)
├── .gitmodules                     # NEW: Submodule configuration
└── ...
```

**Commit:**
```bash
git add .gitmodules
git commit -m "Add Qiling rootfs as git submodule for multi-architecture support"
```

---

### Phase 2: Configuration Updates

#### 2.1 Update `src/detonate/config.py`

**Changes:**

1. **Default rootfs path** (line 87):
   ```python
   # OLD:
   rootfs: str = "/app/data/rootfs"
   
   # NEW:
   rootfs: str = "./data/qiling_rootfs"
   ```

2. **Enhanced `get_rootfs_path()` method** (replace lines 92-105):
   ```python
   def get_rootfs_path(self, platform: str, arch: str) -> Path:
       """Get rootfs path for given platform and architecture.
       
       Supported architectures (priority order):
       - High: x86_64, x86, arm64
       - Medium: arm, mips, mipsel
       - Low: riscv64
       
       Architecture aliases supported:
       - x86_64: x64, amd64
       - x86: i386, i686
       - arm64: aarch64
       
       Args:
           platform: Target platform (linux, windows)
           arch: Architecture name (auto-detected or user-specified)
       
       Returns:
           Path to rootfs directory for given platform/arch
       
       Raises:
           ValueError: If architecture unsupported
       """
       # Normalize architecture names with aliases
       arch_aliases = {
           # x86_64 aliases
           "x86_64": "x8664",
           "x64": "x8664",
           "amd64": "x8664",
           # x86 aliases
           "x86": "x86",
           "i386": "x86",
           "i686": "x86",
           # ARM64 aliases
           "arm64": "arm64",
           "aarch64": "arm64",
           # ARM aliases
           "arm": "arm",
           "armv7": "arm",
           # MIPS aliases
           "mips": "mips32",
           "mips32": "mips32",
           "mipsel": "mips32el",
           # RISC-V
           "riscv64": "riscv64",
       }
       
       normalized_arch = arch_aliases.get(arch.lower(), arch.lower())
       
       if platform == "windows":
           # Windows uses separate rootfs (user-provided DLLs)
           path_name = f"{normalized_arch}_windows"
           # Point to user-provided Windows DLLs in data/rootfs/
           return Path("./data/rootfs") / path_name
       else:  # linux
           path_name = f"{normalized_arch}_linux"
           path = Path(self.rootfs) / path_name
           
           # Validate rootfs has required files
           if not _is_valid_rootfs(path):
               # Fall back to system rootfs for Linux
               return Path("/")
           
           return path
   ```

3. **Enhanced `_is_valid_rootfs()` function** (replace lines 127-140):
   ```python
   def _is_valid_rootfs(path: Path) -> bool:
       """Check if the rootfs path contains minimum required files.
       
       Validates presence of architecture-specific dynamic linker.
       
       Args:
           path: Path to rootfs directory
       
       Returns:
           True if rootfs is valid, False otherwise
       """
       if not path.exists():
           return False
       
       # Architecture-specific dynamic linker paths
       ld_paths = [
           # x86_64
           path / "lib64" / "ld-linux-x86-64.so.2",
           # x86
           path / "lib" / "ld-linux.so.2",
           # ARM64
           path / "lib64" / "ld-linux-aarch64.so.1",
           # ARM
           path / "lib" / "ld-linux-armhf.so.3",
           # MIPS
           path / "lib" / "ld.so.1",
           # RISC-V 64
           path / "lib64" / "ld-linux-riscv64-lp64d.so.1",
       ]
       
       return any(p.exists() for p in ld_paths)
   ```

4. **Add Windows DLL validation helper** (add after `_is_valid_rootfs`):
   ```python
   def validate_windows_dlls(arch: str) -> tuple[bool, str | None]:
       """Validate that required Windows DLLs are present.
       
       Args:
           arch: Architecture (x86 or x86_64)
       
       Returns:
           Tuple of (is_valid, error_message)
           - is_valid: True if DLLs present
           - error_message: None if valid, helpful message if missing
       """
       dll_dir = Path("./data/rootfs") / f"{arch}_windows" / "dlls"
       
       if not dll_dir.exists():
           return False, (
               f"Windows DLLs not found at {dll_dir}\n"
               f"Please copy required DLLs from a Windows installation:\n"
               f"  mkdir -p {dll_dir}\n"
               f"  cp kernel32.dll ntdll.dll user32.dll advapi32.dll {dll_dir}/\n"
               f"\n"
               f"See WINDOWS_DLL_SETUP.md for detailed instructions."
           )
       
       # Check for essential DLLs
       required_dlls = ["kernel32.dll", "ntdll.dll"]
       missing = [dll for dll in required_dlls if not (dll_dir / dll).exists()]
       
       if missing:
           return False, (
               f"Missing required Windows DLLs: {', '.join(missing)}\n"
               f"Please copy these DLLs to: {dll_dir}\n"
               f"\n"
               f"See WINDOWS_DLL_SETUP.md for detailed instructions."
           )
       
       return True, None
   ```

---

#### 2.2 Update `src/detonate/core/emulator.py`

**Changes:**

1. **Expand architecture mapping** (lines 164-169):
   ```python
   # OLD:
   arch_map = {
       "x86": QL_ARCH.X86,
       "x86_64": QL_ARCH.X8664,
       "arm": QL_ARCH.ARM,
       "arm64": QL_ARCH.ARM64,
   }
   
   # NEW:
   arch_map = {
       # x86 family
       "x86": QL_ARCH.X86,
       "i386": QL_ARCH.X86,
       "i686": QL_ARCH.X86,
       "x86_64": QL_ARCH.X8664,
       "x64": QL_ARCH.X8664,
       "amd64": QL_ARCH.X8664,
       # ARM family
       "arm": QL_ARCH.ARM,
       "armv7": QL_ARCH.ARM,
       "arm64": QL_ARCH.ARM64,
       "aarch64": QL_ARCH.ARM64,
       # MIPS family
       "mips": QL_ARCH.MIPS,
       "mips32": QL_ARCH.MIPS,
       "mipsel": QL_ARCH.MIPSEL,
       "mips32el": QL_ARCH.MIPSEL,
       # RISC-V
       "riscv64": QL_ARCH.RISCV64,
   }
   ```

2. **Add Windows DLL validation** (add in `_run_emulation()` before Qiling initialization):
   ```python
   # Validate Windows DLLs if analyzing Windows binary
   if self.platform == "windows":
       from ..config import validate_windows_dlls
       
       is_valid, error_msg = validate_windows_dlls(self.architecture)
       if not is_valid:
           raise FileNotFoundError(error_msg)
   ```

---

#### 2.3 Update `.gitignore`

**Add to end of file:**
```gitignore
# Qiling rootfs submodule (tracked separately)
data/qiling_rootfs/

# User-provided Windows DLLs (do not commit)
data/rootfs/*_windows/
!data/rootfs/.gitkeep
```

---

### Phase 3: Makefile Targets

**Add to `Makefile` after existing targets (before "Web UI development" section):**

```makefile
# =============================================================================
# Rootfs Management
# =============================================================================

# Initialize Qiling rootfs submodule (first-time setup)
# Uses shallow clone (--depth 1) for fast initialization
rootfs-init:
	@echo "========================================"
	@echo "Initializing Qiling rootfs submodule..."
	@echo "========================================"
	@if [ -d "data/qiling_rootfs" ]; then \
		echo "✓ Rootfs submodule already exists"; \
		echo "Updating to latest version..."; \
		git submodule update --remote data/qiling_rootfs; \
	else \
		echo "Cloning Qiling rootfs repository (shallow clone)..."; \
		git submodule add --depth 1 https://github.com/qilingframework/rootfs.git data/qiling_rootfs; \
	fi
	@echo ""
	@echo "Available rootfs architectures:"
	@ls -1 data/qiling_rootfs/ | grep -E "_(linux|windows)$$" | while read dir; do \
		echo "  - $$dir"; \
	done
	@echo ""
	@echo "Priority architectures (tested):"
	@echo "  ✓ x86_64 (x8664_linux)"
	@echo "  ✓ x86 (x86_linux)"
	@echo "  ✓ arm64 (arm64_linux)"
	@echo ""
	@echo "Extended architectures (community support):"
	@echo "  - arm (arm_linux)"
	@echo "  - mips (mips32_linux)"
	@echo "  - mipsel (mips32el_linux)"
	@echo "  - riscv64 (riscv64_linux)"
	@echo ""
	@echo "========================================"
	@echo "Rootfs initialization complete!"
	@echo "========================================"

# Update rootfs submodule to latest version
rootfs-update:
	@echo "Updating Qiling rootfs submodule to latest version..."
	git submodule update --remote data/qiling_rootfs
	@echo "✓ Rootfs updated successfully"
	@echo ""
	@echo "Run 'make rootfs-list' to see available architectures"

# List available rootfs architectures
rootfs-list:
	@echo "Available Qiling rootfs architectures:"
	@echo ""
	@echo "Linux:"
	@ls -1 data/qiling_rootfs/ | grep "_linux$$" | while read dir; do \
		echo "  - $$dir"; \
	done
	@echo ""
	@echo "Windows (user-provided DLLs required):"
	@echo "  - x86_windows (data/rootfs/x86_windows/dlls/)"
	@echo "  - x8664_windows (data/rootfs/x8664_windows/dlls/)"
	@echo ""
	@echo "See WINDOWS_DLL_SETUP.md for Windows DLL setup instructions"

# Clean rootfs (use with caution - removes submodule)
rootfs-clean:
	@echo "WARNING: This will remove the Qiling rootfs submodule!"
	@echo "You will need to run 'make rootfs-init' to re-download."
	@echo ""
	@read -p "Continue? [y/N] " confirm && [ "$$confirm" = "y" ] && \
		(rm -rf data/qiling_rootfs && \
		git submodule deinit -f data/qiling_rootfs 2>/dev/null || true && \
		echo "✓ Rootfs submodule removed") || \
		echo "Cancelled"

# Update install target to include rootfs initialization
install: rootfs-init
	@echo ""
	@echo "Installing Python dependencies with uv..."
	uv sync
	@echo ""
	@echo "========================================"
	@echo "Installation complete!"
	@echo "========================================"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Build test samples: make samples"
	@echo "  2. Run end-to-end tests: make test-e2e"
	@echo "  3. Analyze a sample: detonate analyze <binary>"
	@echo ""
	@echo "For Windows binary analysis:"
	@echo "  - See WINDOWS_DLL_SETUP.md for DLL setup"
	@echo ""
```

**Update existing `install` target** (if present) to include `rootfs-init`.

---

### Phase 4: Documentation

#### 4.1 Create `WINDOWS_DLL_SETUP.md` (NEW FILE)

```markdown
# Windows DLL Setup Guide

## Why Windows DLLs Are Not Included

Windows system DLLs (kernel32.dll, ntdll.dll, etc.) are proprietary Microsoft binaries subject to licensing restrictions. They cannot be redistributed with detonate.

**Users must provide their own Windows DLLs** from a clean Windows installation or test environment.

## ⚠️ Important Security Warnings

1. **Never use DLLs from production systems** - Only use from isolated test VMs
2. **Ensure compliance with Microsoft licensing** - DLLs are for analysis/testing only
3. **Keep DLLs isolated** - Do not mix with host system files
4. **Use clean installations** - Avoid DLLs from compromised systems

## Setup Instructions

### Step 1: Create Directory Structure

```bash
# Create Windows DLL directories
mkdir -p data/rootfs/x86_windows/dlls
mkdir -p data/rootfs/x8664_windows/dlls
```

### Step 2: Obtain DLLs from Windows

**Option A: From Windows VM (Recommended)**

1. Start a clean Windows VM (Windows 10/11 evaluation image)
2. Copy required DLLs from `C:\Windows\System32\`:
   ```bash
   # On Windows VM (PowerShell)
   $dlls = @("kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "shell32.dll")
   Copy-Item C:\Windows\System32\$dlls -Destination \\host\detonate\data\rootfs\x8664_windows\dlls\
   ```

**Option B: From Windows Installation Media**

1. Mount Windows ISO
2. Extract `install.wim` or `install.esd`
3. Use 7-zip or wimlib to extract DLLs from `Windows\System32\`

**Option C: From Qiling Windows Rootfs**

Qiling provides some Windows rootfs files. Check:
```bash
# If using Qiling Windows rootfs
ls /path/to/qiling/rootfs/x8664_windows/
```

### Step 3: Required DLLs (x86_64)

Minimum required DLLs for basic analysis:

| DLL | Purpose | Required |
|-----|---------|----------|
| `kernel32.dll` | Core Windows API | ✅ Yes |
| `ntdll.dll` | Native API | ✅ Yes |
| `user32.dll` | User interface | ⚠️ For GUI malware |
| `advapi32.dll` | Registry, services | ⚠️ For persistence malware |
| `shell32.dll` | Shell operations | ⚠️ For file operations |
| `ws2_32.dll` | Networking | ⚠️ For network malware |
| `msvcrt.dll` | C runtime | ⚠️ For MSVC-compiled binaries |

**Recommended:** Start with kernel32.dll and ntdll.dll, add others as needed.

### Step 4: Verify Setup

```bash
# List DLLs
ls -lh data/rootfs/x8664_windows/dlls/

# Expected output:
# -rw-r--r-- 1 user user 1.5M kernel32.dll
# -rw-r--r-- 1 user user 2.1M ntdll.dll
# ...

# Test with detonate
detonate analyze malware.exe --platform windows --arch x86_64 --dlls data/rootfs/x8664_windows/dlls
```

## Architecture-Specific DLLs

### x86_64 (64-bit Windows)
- Source: `C:\Windows\System32\`
- Destination: `data/rootfs/x8664_windows/dlls/`

### x86 (32-bit Windows)
- Source (64-bit Windows): `C:\Windows\SysWOW64\`
- Source (32-bit Windows): `C:\Windows\System32\`
- Destination: `data/rootfs/x86_windows/dlls/`

## Troubleshooting

### Error: "Missing required Windows DLLs"

**Solution:**
```bash
# Verify DLLs exist
ls data/rootfs/x8664_windows/dlls/kernel32.dll

# Re-copy from Windows VM
# (See Step 2 above)
```

### Error: "DLL load failed"

**Possible causes:**
- DLL architecture mismatch (x86 vs x86_64)
- Missing dependent DLLs
- Corrupted DLL files

**Solution:**
1. Verify architecture matches sample binary
2. Copy additional DLLs (dependencies)
3. Use clean DLLs from fresh Windows installation

### Analysis Fails Immediately

**Check:**
```bash
# Verify DLLs are readable
file data/rootfs/x8664_windows/dlls/*.dll

# Check permissions
chmod 644 data/rootfs/x8664_windows/dlls/*.dll
```

## Legal Considerations

- DLLs are for **analysis and testing only**
- Do not distribute DLLs
- Do not use DLLs in production environments
- Comply with Microsoft's licensing terms
- Delete DLLs when no longer needed

## References

- [Qiling Windows Emulation](https://docs.qiling.io/en/latest/)
- [Windows 10 Evaluation VMs](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
- [Wimlib for Extracting install.wim](https://wimlib.net/)

---

**Need help?** Open an issue with:
- Windows version used
- Architecture (x86/x86_64)
- Error message from detonate
```

---

#### 4.2 Update `README.md`

**Add after "Installation" section:**

```markdown
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

**Architecture not supported:**
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
```

**Update "Usage" section** to mention architecture aliases:
```markdown
# Analyze with architecture alias
detonate analyze sample --arch amd64  # Same as x86_64
detonate analyze sample --arch aarch64  # Same as arm64
```

---

#### 4.3 Update `examples/samples/README.md`

**Update "Go Sample" section:**

```markdown
## Go Sample: trigger_syscalls_go

### Overview

Statically-linked Go binary that safely triggers syscalls mapped to ATT&CK techniques. Uses CGO for the ptrace syscall.

### ⚠️ Qiling Emulation Limitations

**Important:** Go binaries have complex runtime initialization (goroutines, garbage collector, network stack) that may exceed Qiling's userspace emulation capabilities, even with the official rootfs.

**With the new Qiling rootfs:**
- ✅ Proper system libraries available (libc, ld-linux)
- ✅ Better syscall emulation
- ⚠️ Go runtime may still cause emulation failures

**For reliable detonate testing, use the C `trigger_syscalls_c` sample instead.**

### Build Commands

```bash
# Native x86_64 build (statically linked)
GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go trigger_syscalls.go

# ARM64 cross-compile (requires aarch64-linux-gnu-gcc)
GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 \
    go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go_arm64 trigger_syscalls.go
```

### Testing with New Rootfs

```bash
# Initialize rootfs first
make rootfs-init

# Analyze Go sample
detonate analyze trigger_syscalls_go \
    --platform linux \
    --arch x86_64 \
    --format all \
    --output ./results

# Check results
# Expected: Improved emulation over previous attempts
# May still hit Go runtime initialization issues
```

### Expected Behavior

**With minimal rootfs (old):**
- ❌ Immediate failure (missing libraries)

**With Qiling official rootfs (new):**
- ⚠️ May progress further into Go runtime initialization
- ⚠️ May still fail at goroutine scheduler setup
- ✅ Better error messages for debugging

**Recommended workflow:**
1. Try Go sample with new rootfs
2. If emulation fails, check logs for specific error
3. Use C sample (`trigger_syscalls_c`) for reliable testing
4. Report Go-specific errors for Qiling improvement
```

---

### Phase 5: Build Script Updates

#### 5.1 Update `examples/samples/build_all.sh`

**Add ARM64 build with auto-detection (after trigger_x86_64 build):**

```bash
# Build trigger_syscalls_c (C comprehensive syscall trigger)
echo "[4/8] Building trigger_syscalls_c (C x86_64)..."
gcc -static -o trigger_syscalls_c trigger_syscalls.c
echo "      -> trigger_syscalls_c ($(stat -c%s trigger_syscalls_c) bytes)"

# Build trigger_syscalls_c_arm64 (C ARM64 cross-compile)
echo "[5/8] Building trigger_syscalls_c_arm64 (C ARM64)..."
if command -v aarch64-linux-gnu-gcc &> /dev/null; then
    aarch64-linux-gnu-gcc -static -o trigger_syscalls_c_arm64 trigger_syscalls.c
    echo "      -> trigger_syscalls_c_arm64 ($(stat -c%s trigger_syscalls_c_arm64) bytes)"
else
    echo "      -> SKIPPED (install aarch64-linux-gnu-gcc for ARM64 support)"
fi

# Build fake_pe_x86.exe (minimal PE header)
echo "[6/8] Building fake_pe_x86.exe..."
# ... (existing code)

# Build Go samples (if prerequisites available)
if check_go_prerequisites; then
    # Build trigger_syscalls_go (Go x86_64)
    echo "[7/8] Building trigger_syscalls_go (Go x86_64)..."
    cd "${SCRIPT_DIR}"
    GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go trigger_syscalls.go 2>&1 | grep -v "warning:" || true
    if [ -f trigger_syscalls_go ]; then
        echo "      -> trigger_syscalls_go ($(stat -c%s trigger_syscalls_go) bytes)"
    else
        echo "      -> WARNING: Go build failed"
    fi
    
    # Build trigger_syscalls_go_arm64 (Go ARM64 cross-compile)
    echo "[8/8] Building trigger_syscalls_go_arm64 (Go ARM64)..."
    if command -v aarch64-linux-gnu-gcc &> /dev/null; then
        GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 \
            go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go_arm64 trigger_syscalls.go 2>&1 | grep -v "warning:" || true
        if [ -f trigger_syscalls_go_arm64 ]; then
            echo "      -> trigger_syscalls_go_arm64 ($(stat -c%s trigger_syscalls_go_arm64) bytes)"
        else
            echo "      -> WARNING: ARM64 Go build failed"
        fi
    else
        echo "      -> SKIPPED (aarch64-linux-gnu-gcc not available)"
    fi
else
    echo "[7/8] Skipping Go builds (missing prerequisites)"
    echo "[8/8] Skipping Go ARM64 builds"
fi
```

---

## User Flows

### Flow 1: First-Time User Setup

**User Story:** "As a new user, I want to quickly set up detonate so I can start analyzing binaries."

**Steps:**
1. Clone repository
   ```bash
   git clone --recursive https://github.com/xen0bit/detonate.git
   cd detonate
   ```

2. Install dependencies
   ```bash
   make install
   ```
   **Expected output:**
   ```
   ========================================
   Initializing Qiling rootfs submodule...
   ========================================
   Cloning Qiling rootfs repository (shallow clone)...
   
   Available rootfs architectures:
     - x8664_linux
     - x86_linux
     - arm64_linux
     - arm_linux
     - mips32_linux
     - mips32el_linux
     - riscv64_linux
   
   Priority architectures (tested):
     ✓ x86_64 (x8664_linux)
     ✓ x86 (x86_linux)
     ✓ arm64 (arm64_linux)
   
   ========================================
   Rootfs initialization complete!
   ========================================
   
   Installing Python dependencies with uv...
   ...
   Installation complete!
   ```

3. Build test samples
   ```bash
   make samples
   ```

4. Run end-to-end tests
   ```bash
   make test-e2e
   ```

**Validation:**
- ✅ Rootfs submodule initialized
- ✅ All priority architectures available (x86_64, x86, arm64)
- ✅ Test samples built successfully
- ✅ E2E tests pass

---

### Flow 2: Analyze Linux Binary (x86_64)

**User Story:** "As a security analyst, I want to analyze a suspicious Linux ELF binary so I can understand its behavior."

**Steps:**
1. Ensure rootfs is initialized
   ```bash
   make rootfs-init
   ```

2. Analyze binary
   ```bash
   detonate analyze suspicious_binary \
       --platform linux \
       --arch x86_64 \
       --format all \
       --output ./analysis_results
   ```

3. Review outputs
   ```bash
   ls ./analysis_results/
   # - navigator_*.json (ATT&CK Navigator layer)
   # - stix_*.json (STIX 2.1 bundle)
   # - report_*.md (Markdown report)
   # - log_*.jsonl (Structured event log)
   ```

**Validation:**
- ✅ Analysis completes without rootfs errors
- ✅ All 4 output formats generated
- ✅ ATT&CK techniques detected
- ✅ No "missing rootfs" errors

---

### Flow 3: Analyze ARM64 Binary

**User Story:** "As an IoT security researcher, I want to analyze ARM64 malware so I can understand threats to embedded devices."

**Steps:**
1. Verify ARM64 rootfs available
   ```bash
   make rootfs-list
   # Should show: arm64_linux
   ```

2. Build ARM64 test sample (optional)
   ```bash
   cd examples/samples
   aarch64-linux-gnu-gcc -static -o trigger_syscalls_c_arm64 trigger_syscalls.c
   ```

3. Analyze ARM64 binary
   ```bash
   detonate analyze arm64_malware \
       --platform linux \
       --arch arm64 \
       --format all \
       --output ./arm64_analysis
   ```

**Validation:**
- ✅ ARM64 rootfs recognized
- ✅ Analysis completes without architecture errors
- ✅ Syscalls properly intercepted
- ✅ ATT&CK techniques detected

---

### Flow 4: Analyze Windows Binary

**User Story:** "As a malware analyst, I want to analyze Windows PE malware so I can extract IOCs and ATT&CK mappings."

**Steps:**
1. Set up Windows DLLs
   ```bash
   mkdir -p data/rootfs/x8664_windows/dlls
   # Copy DLLs from Windows VM (see WINDOWS_DLL_SETUP.md)
   cp kernel32.dll ntdll.dll data/rootfs/x8664_windows/dlls/
   ```

2. Verify DLLs
   ```bash
   ls -lh data/rootfs/x8664_windows/dlls/
   ```

3. Analyze Windows binary
   ```bash
   detonate analyze malware.exe \
       --platform windows \
       --arch x86_64 \
       --dlls data/rootfs/x8664_windows/dlls \
       --format all \
       --output ./windows_analysis
   ```

**Error Handling:**
If DLLs missing:
```
Error: Missing required Windows DLLs: kernel32.dll, ntdll.dll
Please copy these DLLs to: data/rootfs/x8664_windows/dlls

See WINDOWS_DLL_SETUP.md for detailed instructions.
```

**Validation:**
- ✅ Helpful error message if DLLs missing
- ✅ Analysis proceeds if DLLs present
- ✅ Windows APIs properly intercepted
- ✅ ATT&CK techniques detected

---

### Flow 5: Analyze Go Binary

**User Story:** "As a researcher, I want to test if detonate can analyze statically-compiled Go binaries."

**Steps:**
1. Build Go sample
   ```bash
   cd examples/samples
   GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go trigger_syscalls.go
   ```

2. Verify rootfs initialized
   ```bash
   make rootfs-init
   ```

3. Analyze Go binary
   ```bash
   detonate analyze trigger_syscalls_go \
       --platform linux \
       --arch x86_64 \
       --format all \
       --output ./go_analysis
   ```

4. Check results
   ```bash
   cat ./go_analysis/log_*.jsonl | grep technique_id
   ```

**Expected Outcomes:**

**Best case:**
```
✓ Analysis completes
✓ Multiple techniques detected (mmap, socket, open, etc.)
✓ ATT&CK mapping successful
```

**Likely case (Go runtime issues):**
```
⚠️ Emulation progresses further than before
⚠️ May fail at Go runtime initialization (goroutines, GC)
✓ Better error messages for debugging
```

**Fallback:**
```
If Go analysis fails, use C sample:
detonate analyze trigger_syscalls_c --arch x86_64
```

**Validation:**
- ✅ Rootfs properly loaded (no "missing library" errors)
- ⚠️ Go runtime may still cause issues (documented limitation)
- ✅ Clear error messages if emulation fails
- ✅ C sample works as reliable alternative

---

### Flow 6: Update Rootfs

**User Story:** "As a power user, I want to update to the latest Qiling rootfs so I can benefit from improvements."

**Steps:**
1. Update submodule
   ```bash
   make rootfs-update
   ```
   **Expected output:**
   ```
   Updating Qiling rootfs submodule to latest version...
   ✓ Rootfs updated successfully
   ```

2. Verify update
   ```bash
   cd data/qiling_rootfs
   git log --oneline -1
   ```

3. Test with sample
   ```bash
   detonate analyze trigger_syscalls_c --arch x86_64
   ```

**Validation:**
- ✅ Submodule updates to latest commit
- ✅ Analysis still works after update
- ✅ No breaking changes

---

## Testing & Validation

### Test Matrix

| Test ID | Architecture | Sample Binary | Expected Techniques | Priority | Status |
|---------|-------------|---------------|---------------------|----------|--------|
| T001 | x86_64 | `trigger_syscalls_c` | 10+ | P0 | ⏳ Pending |
| T002 | x86 | `minimal_x86` | 1-2 | P0 | ⏳ Pending |
| T003 | arm64 | `trigger_syscalls_c_arm64` | 10+ | P0 | ⏳ Pending |
| T004 | x86_64 | `trigger_syscalls_go` | 2-10 (may fail) | P1 | ⏳ Pending |
| T005 | arm | TBD | TBD | P1 | ⏳ Future |
| T006 | mips | TBD | TBD | P1 | ⏳ Future |

### Validation Commands

```bash
# Test x86_64
detonate analyze examples/samples/trigger_syscalls_c \
    --platform linux --arch x86_64 \
    --output /tmp/test_x8664

# Verify output files
ls /tmp/test_x8664/*.json /tmp/test_x8664/*.md /tmp/test_x8664/*.jsonl

# Check techniques detected
grep -o '"technique_id":"T[0-9.]*"' /tmp/test_x8664/log_*.jsonl | sort -u | wc -l
# Expected: ≥10

# Test x86
detonate analyze examples/samples/minimal_x86 \
    --platform linux --arch x86 \
    --output /tmp/test_x86

# Test arm64
detonate analyze examples/samples/trigger_syscalls_c_arm64 \
    --platform linux --arch arm64 \
    --output /tmp/test_arm64

# Test Go (expect improvements over previous attempts)
detonate analyze examples/samples/trigger_syscalls_go \
    --platform linux --arch x86_64 \
    --output /tmp/test_go
```

### Success Criteria

| Criterion | Before | After | Status |
|-----------|--------|-------|--------|
| Rootfs initialization | Manual | `make rootfs-init` | ⏳ Pending |
| x86_64 analysis | Works | Works better | ⏳ Pending |
| x86 analysis | Works | Works | ⏳ Pending |
| arm64 analysis | Not available | Works | ⏳ Pending |
| Go binary analysis | Fails | Improved (may still fail) | ⏳ Pending |
| Windows DLL errors | Confusing | Clear message + docs | ⏳ Pending |
| Architecture aliases | Not supported | Supported | ⏳ Pending |

---

## Acceptance Criteria

### Phase 1: Git Submodule
- [ ] Submodule added with `--depth 1`
- [ ] `.gitmodules` file committed
- [ ] Submodule status shows correct path
- [ ] Rootfs directories accessible

### Phase 2: Configuration
- [ ] `config.py` default rootfs path updated
- [ ] Architecture aliases working (x64→x8664, aarch64→arm64, etc.)
- [ ] `_is_valid_rootfs()` checks all architecture linkers
- [ ] Windows DLL validation with helpful error messages
- [ ] `emulator.py` arch_map expanded

### Phase 3: Makefile
- [ ] `rootfs-init` target works (first-time setup)
- [ ] `rootfs-update` target works (updates submodule)
- [ ] `rootfs-list` target shows architectures
- [ ] `install` target includes `rootfs-init`
- [ ] All targets documented

### Phase 4: Documentation
- [ ] `WINDOWS_DLL_SETUP.md` created with complete instructions
- [ ] `README.md` updated with rootfs setup section
- [ ] Architecture support table added
- [ ] Troubleshooting section added
- [ ] `.gitignore` updated for submodule and Windows DLLs

### Phase 5: Build Scripts
- [ ] `build_all.sh` includes ARM64 build
- [ ] Auto-detection for cross-compilers
- [ ] Helpful skip messages when compilers unavailable
- [ ] Step numbering updated (8 total steps)

### Phase 6: Testing
- [ ] x86_64 analysis works with new rootfs
- [ ] x86 analysis works with new rootfs
- [ ] arm64 analysis works with new rootfs
- [ ] Go sample tested (document results)
- [ ] All priority architectures validated

---

## Troubleshooting Guide

### Common Issues

#### Issue 1: "Rootfs not found" Error

**Symptoms:**
```
Error: Rootfs not found: ./data/qiling_rootfs/x8664_linux
```

**Cause:** Submodule not initialized.

**Solution:**
```bash
make rootfs-init
```

---

#### Issue 2: "Missing required Windows DLLs" Error

**Symptoms:**
```
Error: Missing required Windows DLLs: kernel32.dll, ntdll.dll
```

**Cause:** Windows DLLs not provided.

**Solution:**
```bash
# See detailed instructions
cat WINDOWS_DLL_SETUP.md

# Quick fix
mkdir -p data/rootfs/x8664_windows/dlls
# Copy DLLs from Windows VM
```

---

#### Issue 3: Architecture Not Recognized

**Symptoms:**
```
Error: Unsupported architecture: amd64
```

**Cause:** Using alias not in mapping.

**Solution:**
- Use canonical name: `x86_64` instead of `amd64`
- Or ensure alias is in `arch_aliases` dict in `config.py`

---

#### Issue 4: Go Binary Emulation Fails

**Symptoms:**
```
Error: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
```

**Cause:** Go runtime complexity exceeds Qiling capabilities.

**Solution:**
1. Verify rootfs initialized: `make rootfs-init`
2. Check logs for specific error point
3. Use C sample as alternative: `trigger_syscalls_c`
4. Report error for Qiling improvement

---

#### Issue 5: ARM64 Build Fails

**Symptoms:**
```
aarch64-linux-gnu-gcc: command not found
```

**Cause:** Cross-compiler not installed.

**Solution:**
```bash
# Install cross-compiler
sudo apt install -y gcc-aarch64-linux-gnu

# Or skip ARM64, use x86_64 sample
```

---

#### Issue 6: Submodule Clone Fails

**Symptoms:**
```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

**Cause:** Network issue or authentication required.

**Solution:**
```bash
# Check network connectivity
ping github.com

# Try manual clone
cd data
git clone --depth 1 https://github.com/qilingframework/rootfs.git qiling_rootfs
```

---

## Rollback Plan

If issues arise, rollback steps:

```bash
# Remove submodule
git submodule deinit -f data/qiling_rootfs
rm -rf data/qiling_rootfs

# Remove .gitmodules
git rm .gitmodules

# Revert config changes
git checkout src/detonate/config.py
git checkout src/detonate/core/emulator.py

# Restore old rootfs (if backed up)
# Or recreate minimal rootfs
mkdir -p data/rootfs/x8664_linux/tmp
```

---

## Future Enhancements

1. **Automated rootfs testing** - Test all architectures in CI/CD
2. **Windows rootfs automation** - Script DLL extraction from Windows ISO
3. **Rootfs caching** - Cache rootfs in CI to speed up builds
4. **Architecture detection** - Auto-detect binary architecture from ELF/PE headers
5. **Custom rootfs support** - Allow users to provide custom rootfs paths

---

## References

- [Qiling Rootfs Repository](https://github.com/qilingframework/rootfs)
- [Qiling Documentation](https://docs.qiling.io/en/latest/)
- [Unicorn Engine](https://www.unicorn-engine.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

**Document Version:** 1.0  
**Last Updated:** 2026-04-23  
**Author:** detonate development team  
**Status:** Implementation Plan
