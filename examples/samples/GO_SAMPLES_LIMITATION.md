# Go Sample Limitations

## Summary

Go binaries (`trigger_syscalls_go`) **cannot be successfully emulated** by Qiling due to fundamental limitations in the Unicorn/Qiling emulation engine when handling statically-linked Go binaries.

## Why Go Binaries Fail

### 1. **Runtime Complexity**
- Go binaries include the entire Go runtime (~3MB for a minimal program)
- Complex memory management with 70+ `mmap` calls during initialization
- Goroutine scheduler, garbage collector, and other runtime components

### 2. **Memory Mapping Issues**
```
Error: UcError: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
Location: mprotect syscall at address 0x67e000
```
- Go's `.data.rel.ro` section modifications trigger Unicorn memory protection
- Large memory regions (20KB+) cannot be properly emulated
- Self-modifying code patterns fail

### 3. **Syscall Noise**
Even when the binary runs (without CGO), the Go runtime generates:
- 424 total syscalls (vs 29 for C equivalent)
- 351 `write` calls to stderr from runtime
- 72 `mmap` calls for runtime initialization
- Only 3 unique syscall types captured (write, mmap, openat)

### 4. **Detection Failure**
| Metric | C Sample | Go Sample |
|--------|----------|-----------|
| API Calls | 29 | 424 |
| ATT&CK Findings | 10 | 2 |
| Detection Quality | High | Low |
| Emulation Success | ✅ | ❌ |

## Comparison

### C Sample (trigger_syscalls_c)
```
API calls: 29
Findings: 10 techniques
- T1003.008: Credential Dumping (high)
- T1548.001: Setuid/Setgid (high)
- T1053.003: Cron (high)
- T1543.002: Systemd (high)
- T1082: System Discovery (medium)
- T1083: File Discovery (medium)
- T1070.004: File Deletion (medium)
- T1055: Process Injection (medium)
- T1071: Network Protocol (low)
- T1005: Data Collection (low)
```

### Go Sample (trigger_syscalls_go_nocgo)
```
API calls: 424
Findings: 2 techniques
- T1055: Process Injection (low) - from mmap spam
- T1005: Data Collection (low) - from write spam
```

## Recommendation

**Use C samples for all testing and demonstration purposes.**

The C sample (`trigger_syscalls_c`) provides:
- ✅ Full syscall coverage
- ✅ 10 ATT&CK technique detections
- ✅ Clean emulation without errors
- ✅ Minimal syscall noise (29 vs 424)
- ✅ Smaller binary (776KB vs 3.5MB)

## Future Work

Potential improvements for Go binary support:

1. **Native Execution Mode**
   - Run Go binaries natively instead of emulation
   - Use eBPF or ptrace for syscall capture
   - Requires kernel-level integration

2. **Qiling Improvements**
   - Better Go runtime support in Qiling
   - Custom memory handlers for Go binaries
   - Reduced emulation overhead

3. **Alternative Emulators**
   - Evaluate other emulation frameworks
   - Consider hybrid native/emulated approach

## Building Go Samples

If you still want to build Go samples (for research purposes):

```bash
# Without CGO (still won't emulate properly)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
  -ldflags="-s -w" \
  -o trigger_syscalls_go_nocgo \
  trigger_syscalls_go_nocgo.go

# With CGO (fails immediately in Qiling)
CGO_ENABLED=1 go build \
  -ldflags="-extldflags '-static'" \
  -o trigger_syscalls_go \
  trigger_syscalls.go
```

## References

- Qiling Issues: https://github.com/qilingframework/qiling/issues
- Unicorn Memory: https://github.com/unicorn-engine/unicorn
- Go Binary Size: https://www.reddit.com/r/golang/comments/8b5x7b/why_are_go_binaries_so_large/
