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
   ```powershell
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
