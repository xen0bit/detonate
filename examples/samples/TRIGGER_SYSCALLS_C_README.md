# C Sample: trigger_syscalls_c

## Overview

Comprehensive C binary that safely triggers syscalls mapped to **10+ ATT&CK techniques**. Unlike the Go version, the C sample has minimal runtime overhead and emulates reliably in Qiling.

## Build Commands

```bash
# Native x86_64 build (statically linked)
gcc -static -o trigger_syscalls_c trigger_syscalls.c

# ARM64 cross-compile
aarch64-linux-gnu-gcc -static -o trigger_syscalls_c_arm64 trigger_syscalls.c
```

## Verified ATT&CK Coverage

When analyzed with `detonate analyze trigger_syscalls_c`, the sample consistently triggers:

| # | Technique ID | Technique Name | Tactic | Confidence | Syscall |
|---|-------------|----------------|--------|------------|---------|
| 1 | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | Credential Access | 0.9-0.95 | open/read |
| 2 | T1548.001 | Setuid and Setgid | Privilege Escalation | 0.85-0.9 | setuid/setgid/setresuid |
| 3 | T1055 | Process Injection | Defense Evasion | 0.4-0.6 | mmap/mprotect |
| 4 | T1071 | Application Layer Protocol | Command and Control | 0.3-0.6 | socket/connect/sendto |
| 5 | T1070.004 | File Deletion | Defense Evasion | 0.6 | unlink |
| 6 | T1082 | System Information Discovery | Discovery | 0.7 | uname/gethostname |
| 7 | T1083 | File and Directory Discovery | Discovery | 0.4-0.6 | stat/readlink |
| 8 | T1053.003 | Cron | Persistence | 0.85 | access |
| 9 | T1543.002 | Systemd Service | Persistence | 0.85 | access |
| 10 | T1611 | Escape to Host | Privilege Escalation | 0.85-0.95 | stat (docker.sock) |
| 11 | T1005 | Data from Local System | Collection | 0.2-0.3 | read |

**Test Results:** 31 API calls captured, 10-11 unique techniques detected.

## Syscalls Triggered

```
open (O_RDONLY)          -> /etc/passwd, /etc/shadow, /etc/hostname, /etc/hosts
read                     -> Read file contents
setuid(0)                -> Privilege escalation attempt
setgid(0)                -> Privilege escalation attempt
syscall(SYS_setresuid)   -> Set real/effective/saved UID
syscall(SYS_setresgid)   -> Set real/effective/saved GID
getcwd                   -> Get current directory
gethostname              -> Get hostname
uname                    -> Get system info
readlink                 -> Read /proc/self/exe
stat                     -> Check file existence
access                   -> Check persistence paths
open (O_CREAT|O_WRONLY)  -> Create temp file
write                    -> Write to temp file
unlink                   -> Delete temp file
mmap (PROT_READ|WRITE|EXEC) -> RWX memory allocation
mprotect (PROT_READ|EXEC)   -> Change memory protection
munmap                   -> Free memory
socket (AF_INET)         -> TCP and UDP sockets
connect                  -> Connect to 8.8.8.8:53
sendto                   -> Send UDP DNS query
close                    -> Close file descriptors
```

## Safety Guarantees

- **Read-only file access**: All credential files opened with `O_RDONLY`
- **Self-contained temp files**: Created in `/tmp/`, deleted immediately
- **No actual privilege escalation**: setuid/setgid fail safely in emulation
- **Network timeouts**: Connections to 8.8.8.8:53 timeout quickly in emulation
- **No destructive operations**: Only deletes self-created temp files
- **Clean exit**: All file descriptors properly closed

## Comparison: C vs Go Sample

| Feature | C Sample (`trigger_syscalls_c`) | Go Sample (`trigger_syscalls_go`) |
|---------|----------------------------------|-----------------------------------|
| **Binary size** | ~795 KB | ~3.6 MB |
| **Static linking** | Yes (gcc -static) | Yes (CGO + extldflags) |
| **Qiling compatibility** | ✓ Excellent - minimal runtime | ✗ Limited - complex Go runtime |
| **Syscalls triggered** | 31 API calls | 425+ API calls (runtime overhead) |
| **Techniques detected** | 10-11 unique | 2-3 (runtime crashes emulation) |
| **Build time** | <1 second | 5-10 seconds |
| **Recommended for** | **Primary testing** | Build verification only |

## Usage with detonate

```bash
# Analyze C sample
detonate analyze trigger_syscalls_c \
    --platform linux \
    --arch x86_64 \
    --format all \
    --output ./results

# Expected output files:
# - log_*.jsonl (structured event log)
# - navigator_*.json (ATT&CK Navigator layer)
# - stix_*.json (STIX 2.1 bundle)
# - report_*.md (Markdown report)
```

## Troubleshooting

**Build fails with undefined references:**
```bash
# Ensure glibc development headers are installed
sudo apt install -y libc6-dev

# For ARM64 cross-compile
sudo apt install -y libc6-dev-arm64-cross
```

**Emulation fails:**
The C sample is optimized for Qiling and should work reliably. If issues occur:
- Verify the binary is statically linked: `ldd trigger_syscalls_c`
- Check file permissions: `chmod +x trigger_syscalls_c`
- Try the simpler `trigger_x86_64` sample for basic testing

## Source Code Structure

The sample is organized in 8 sections, each triggering related syscalls:

1. **Credential Access** - open/read /etc/passwd, /etc/shadow
2. **Privilege Escalation** - setuid, setgid, setresuid, setresgid
3. **Discovery** - getcwd, gethostname, uname, readlink, stat
4. **Persistence Recon** - access on cron/systemd paths
5. **Container Escape** - stat on docker.sock, .dockerenv
6. **Defense Evasion** - create/delete temp file, rename .bash_history
7. **Process Injection** - mmap(RWX), mprotect(RX), munmap
8. **Network** - socket, connect, sendto

Each section includes printf statements for runtime verification and is clearly commented with ATT&CK technique mappings.
