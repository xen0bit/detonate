# Detonate Test Samples

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
| `trigger_syscalls` | x86_64 | Go syscall trigger | 45+ syscalls, 16+ ATT&CK techniques |
| `trigger_syscalls_arm64` | arm64 | Go ARM64 cross-compile | Same as x86_64, different arch |
| `fake_pe_x86.exe` | x86 | PE detection test | Not executable - header only |

## Building from Source

### Prerequisites

```bash
# Required for C samples
sudo apt install -y gcc gcc-multilib

# Required for Go samples
sudo apt install -y golang-go gcc gcc-aarch64-linux-gnu
```

### Build All Samples

```bash
# Build all samples (C + Go)
./build_all.sh

# Build C samples only
gcc -static -o minimal_x86_64 minimal_x86_64.c
gcc -static -m32 -o minimal_x86 minimal_x86.c
gcc -static -o trigger_x86_64 trigger_x86_64.c

# Build Go samples (x86_64)
CGO_ENABLED=1 go build -ldflags="-s -w" -o trigger_syscalls trigger_syscalls.go

# Build Go samples (ARM64 cross-compile)
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
    go build -ldflags="-s -w" -o trigger_syscalls_arm64 trigger_syscalls.go
```

### Verify Static Linking

```bash
# Should show "statically linked" or "not a dynamic executable"
file trigger_syscalls
ldd trigger_syscalls
ldd trigger_syscalls_arm64
```

## Running End-to-End Tests

```bash
# Run full e2e test suite (includes Go sample analysis)
./test_e2e.sh

# Or manually analyze a sample
detonate analyze trigger_syscalls --platform linux --arch x86_64 --format all --output ./results
```

## Expected ATT&CK Techniques

### trigger_x86_64 (C Sample)

| Syscall | Technique | Tactic | Confidence |
|---------|-----------|--------|------------|
| `openat("/etc/passwd")` | T1005 (Data from Local System) | collection | medium |
| `read()` | T1005 | collection | low |
| `socket(AF_INET, SOCK_STREAM)` | T1071.001 (Web Protocols) | command-and-control | medium |
| `setuid(0)` | T1548.001 (Setuid and Setgid) | privilege-escalation | high |

### trigger_syscalls (Go Sample)

The Go sample triggers **45+ syscalls** mapped to **16+ unique ATT&CK techniques**:

| Tactic | Technique ID | Technique Name | Syscall/Behavior | Confidence |
|--------|-------------|----------------|------------------|------------|
| Execution | T1059.004 | Unix Shell | execve(/bin/sh) | 0.9 |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | open(/etc/passwd, /etc/shadow, /etc/sudoers) | 0.9-0.95 |
| Privilege Escalation | T1548.001 | Setuid and Setgid | setuid(0), setgid(0), setresuid() | 0.85-0.9 |
| Discovery | T1082 | System Information Discovery | uname(), sysinfo() | 0.7 |
| Discovery | T1083 | File and Directory Discovery | getcwd(), readlink(), stat() | 0.4-0.6 |
| Discovery | T1016 | System Network Configuration Discovery | gethostname() | 0.7 |
| Persistence | T1053.003 | Cron | access(/etc/cron.d/) | 0.85 |
| Persistence | T1543.002 | Systemd Service | access(/etc/systemd/system/) | 0.85 |
| Privilege Escalation | T1611 | Escape to Host | open(/var/run/docker.sock), mount(/proc), pivot_root(), unshare() | 0.9-0.95 |
| Reconnaissance | T1592.004 | Cloud Service Dashboard | connect(169.254.169.254:80) | 0.9 |
| Defense Evasion | T1070.004 | File Deletion | unlink(tempfile) | 0.6 |
| Defense Evasion | T1070.003 | Clear Command History | rename(.bash_history) | 0.9 |
| Defense Evasion | T1055 | Process Injection | mmap(RWX), mprotect(RWX) | 0.4-0.6 |
| Defense Evasion | T1055.008 | Ptrace System Calls | ptrace(PTRACE_TRACEME) | 0.9 |
| Command and Control | T1071 | Application Layer Protocol | socket(), connect(8.8.8.8), sendto() | 0.3-0.6 |
| Collection | T1005 | Data from Local System | read(), write() | 0.2-0.3 |

**Total: 16 unique techniques, 45+ syscall invocations**

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

### Safety Guarantees

- **Read-only operations**: All file accesses are read-only (O_RDONLY)
- **Self-contained temp files**: Created in `/tmp/detonate_test_*`, deleted on exit
- **No actual privilege escalation**: setuid/setgid fail safely in emulation
- **No destructive operations**: rename() targets non-existent `.bash_history`
- **Clean exit**: All resources properly closed

### ATT&CK Techniques (Intended)

The Go sample is designed to trigger these techniques (when fully emulated):

| Tactic | Technique ID | Technique Name | Syscall/Behavior | Confidence |
|--------|-------------|----------------|------------------|------------|
| Defense Evasion | T1055.008 | Ptrace System Calls | ptrace(PTRACE_TRACEME) | 0.9 |
| Credential Access | T1003.008 | OS Credential Dumping | open(/etc/passwd, /etc/shadow) | 0.9-0.95 |
| Privilege Escalation | T1548.001 | Setuid and Setgid | setuid(0), setgid(0) | 0.85-0.9 |
| Discovery | T1082 | System Information Discovery | getcwd(), gethostname() | 0.6-0.7 |
| Discovery | T1083 | File and Directory Discovery | readlink(), stat() | 0.4-0.6 |
| Persistence | T1053.003 | Cron | access(/etc/cron.d/) | 0.85 |
| Persistence | T1543.002 | Systemd Service | access(/etc/systemd/system/) | 0.85 |
| Privilege Escalation | T1611 | Escape to Host | stat(/var/run/docker.sock) | 0.85 |
| Defense Evasion | T1070.004 | File Deletion | unlink(tempfile) | 0.6 |
| Defense Evasion | T1070.003 | Clear Command History | rename(.bash_history) | 0.9 |
| Defense Evasion | T1055 | Process Injection | mmap(RWX), mprotect(RX) | 0.4-0.6 |
| Command and Control | T1071 | Application Layer Protocol | socket(), connect() | 0.3-0.6 |

### Cross-Compilation

```bash
# Install cross-compilers
sudo apt install -y gcc-arm-linux-gnueabi    # ARM 32-bit
sudo apt install -y gcc-aarch64-linux-gnu    # ARM64

# Build for ARM64
GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 \
    go build -o trigger_syscalls_arm64 trigger_syscalls.go
```

### Troubleshooting

**CGO build fails:**
```bash
# Ensure gcc is installed and in PATH
gcc --version

# Set CGO flags if needed
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -g"
export CGO_LDFLAGS="-O2 -g"
```

**Static linking verification:**
```bash
# Should show "statically linked" or "not a dynamic executable"
file trigger_syscalls
ldd trigger_syscalls
```

**Emulation fails in Qiling:**
This is expected for Go binaries due to complex runtime initialization. Use the C `trigger_x86_64` sample for reliable emulation testing.

### Build Commands

```bash
# Native x86_64 build
CGO_ENABLED=1 go build -ldflags="-s -w" -o trigger_syscalls trigger_syscalls.go

# ARM64 cross-compile
CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
    go build -ldflags="-s -w" -o trigger_syscalls_arm64 trigger_syscalls.go
```

### Safety Guarantees

- **Read-only operations**: All file accesses are read-only (O_RDONLY)
- **Self-contained temp files**: Created in `/tmp/detonate_test_*`, deleted on exit
- **Network timeouts**: 10-second context timeout prevents hangs
- **No actual privilege escalation**: setuid/setgid fail safely in emulation
- **No destructive operations**: rename() targets non-existent `.bash_history`
- **Clean exit**: All resources properly closed

### Expected detonate Output

When analyzed with `detonate analyze trigger_syscalls`, expect:
- **16+ unique ATT&CK techniques** detected
- **High confidence scores (0.8+)** for ptrace, execve, credential access
- **Medium confidence (0.5-0.7)** for discovery, network operations
- **Pattern detection** for process injection (mmap + mprotect RWX sequence)
- All four output formats generated (Navigator, STIX, Markdown, JSON)

### Cross-Compilation

```bash
# Install cross-compilers
sudo apt install -y gcc-arm-linux-gnueabi    # ARM 32-bit
sudo apt install -y gcc-aarch64-linux-gnu    # ARM64
sudo apt install -y gcc-mips-linux-gnu       # MIPS
sudo apt install -y gcc-mips64-linux-gnuabi64  # MIPS64

# Build for ARM 32-bit
GOOS=linux GOARCH=arm GOARM=7 CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 \
    go build -o trigger_syscalls_arm trigger_syscalls.go

# Build for ARM64 (recommended)
GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 \
    go build -o trigger_syscalls_arm64 trigger_syscalls.go
```

### Troubleshooting

**CGO build fails:**
```bash
# Ensure gcc is installed and in PATH
gcc --version

# Set CGO flags if needed
export CGO_ENABLED=1
export CGO_CFLAGS="-O2 -g"
export CGO_LDFLAGS="-O2 -g"
```

**Static linking verification:**
```bash
# Should show "statically linked" or "not a dynamic executable"
file trigger_syscalls
ldd trigger_syscalls
```

**Ptrace syscall not detected:**
- Verify CGO is enabled: `go env CGO_ENABLED` (should be `1`)
- Check gcc is available: `which gcc`
- Ensure ptrace headers exist: `ls /usr/include/sys/ptrace.h`

## Safety

These binaries are **completely safe**:
- No malicious code
- No network connections (emulated only)
- No actual privilege changes
- Designed for testing analysis infrastructure
- All file operations are read-only or self-contained
- Temp files created in `/tmp` and cleaned up on exit
