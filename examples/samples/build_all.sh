#!/bin/bash
# Build all safe test samples for detonate
# Requires: gcc (with multilib support for x86), standard C library, Go (optional)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building detonate test samples ==="

# =============================================================================
# Prerequisite check for Go builds
# =============================================================================
check_go_prerequisites() {
    local missing=()
    
    # Check Go
    if ! command -v go &> /dev/null; then
        missing+=("golang-go (or go from https://go.dev)")
    fi
    
    # Check gcc for CGO
    if ! command -v gcc &> /dev/null; then
        missing+=("gcc")
    fi
    
    # Check ARM64 cross-compiler
    if ! command -v aarch64-linux-gnu-gcc &> /dev/null; then
        missing+=("gcc-aarch64-linux-gnu")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo ""
        echo "WARNING: Missing prerequisites for Go builds:"
        for pkg in "${missing[@]}"; do
            echo "  - $pkg"
        done
        echo ""
        echo "Install with:"
        echo "  sudo apt install -y golang-go gcc gcc-aarch64-linux-gnu"
        echo ""
        echo "Continuing with C builds only..."
        return 1
    fi
    
    echo "All Go build prerequisites found"
    return 0
}

# =============================================================================
# C samples
# =============================================================================

# Build minimal_x86_64 (64-bit, exit only)
echo "[1/7] Building minimal_x86_64..."
gcc -static -o minimal_x86_64 minimal_x86_64.c
echo "      -> minimal_x86_64 ($(stat -c%s minimal_x86_64) bytes)"

# Build minimal_x86 (32-bit, exit only)
echo "[2/7] Building minimal_x86..."
gcc -static -m32 -o minimal_x86 minimal_x86.c 2>/dev/null || {
    echo "      WARNING: 32-bit build failed (install gcc-multilib?)"
    echo "      -> minimal_x86 SKIPPED"
}
if [ -f minimal_x86 ]; then
    echo "      -> minimal_x86 ($(stat -c%s minimal_x86) bytes)"
fi

# Build trigger_x86_64 (64-bit, multiple syscalls)
echo "[3/7] Building trigger_x86_64..."
gcc -static -o trigger_x86_64 trigger_x86_64.c
echo "      -> trigger_x86_64 ($(stat -c%s trigger_x86_64) bytes)"

# Build trigger_syscalls_c (C comprehensive syscall trigger)
echo "[4/7] Building trigger_syscalls_c (C x86_64)..."
gcc -static -o trigger_syscalls_c trigger_syscalls.c
echo "      -> trigger_syscalls_c ($(stat -c%s trigger_syscalls_c) bytes)"

# Build trigger_syscalls_c_arm64 (C ARM64 cross-compile)
echo "[5/7] Building trigger_syscalls_c_arm64 (C ARM64)..."
aarch64-linux-gnu-gcc -static -o trigger_syscalls_c_arm64 trigger_syscalls.c 2>/dev/null && \
    echo "      -> trigger_syscalls_c_arm64 ($(stat -c%s trigger_syscalls_c_arm64) bytes)" || \
    echo "      -> trigger_syscalls_c_arm64: SKIPPED (cross-compiler not available)"

# Build fake_pe_x86.exe (minimal PE header)
echo "[6/7] Building fake_pe_x86.exe..."
# Create minimal PE header: MZ stub + minimal PE header
# This is not a functional executable, just enough for PE detection
printf 'MZ' > fake_pe_x86.exe
printf '\x00\x00\x00\x00\x00\x00\x00\x00' >> fake_pe_x86.exe  # bytes 2-9
printf '\x40\x00\x00\x00' >> fake_pe_x86.exe  # e_lfanew = 0x40 (PE header at offset 64)
# Pad to offset 0x40
dd if=/dev/zero bs=1 count=50 >> fake_pe_x86.exe 2>/dev/null
# PE signature: "PE\0\0"
printf 'PE\x00\x00' >> fake_pe_x86.exe
# COFF header (20 bytes minimal)
printf '\x64\x86\x00\x00' >> fake_pe_x86.exe  # Machine: i386
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # NumberOfSections: 0
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # TimeDateStamp
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # PointerToSymbolTable
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # NumberOfSymbols
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # SizeOfOptionalHeader
printf '\x00\x00\x00\x00' >> fake_pe_x86.exe  # Characteristics
echo "      -> fake_pe_x86.exe ($(stat -c%s fake_pe_x86.exe) bytes)"

# =============================================================================
# Go samples
# =============================================================================
# Build Go samples (if prerequisites available)
if check_go_prerequisites; then
    # Build trigger_syscalls_go (Go x86_64)
    echo "[7/7] Building trigger_syscalls_go (Go x86_64)..."
    cd "${SCRIPT_DIR}"
    GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go trigger_syscalls.go 2>&1 | grep -v "warning:" || true
    if [ -f trigger_syscalls_go ]; then
        echo "      -> trigger_syscalls_go ($(stat -c%s trigger_syscalls_go) bytes)"
    else
        echo "      -> WARNING: Go build failed"
    fi
    
    # Build trigger_syscalls_go_arm64 (Go ARM64 cross-compile)
    echo "[8/8] Building trigger_syscalls_go_arm64 (Go ARM64)..."
    GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 \
        go build -ldflags="-extldflags '-static'" -o trigger_syscalls_go_arm64 trigger_syscalls.go 2>&1 | grep -v "warning:" || true
    if [ -f trigger_syscalls_go_arm64 ]; then
        echo "      -> trigger_syscalls_go_arm64 ($(stat -c%s trigger_syscalls_go_arm64) bytes)"
    else
        echo "      -> WARNING: ARM64 Go build failed"
    fi
else
    echo "[7/7] Skipping Go builds (missing prerequisites)"
    echo "[8/8] Skipping Go ARM64 builds"
fi

echo ""
echo "=== Build complete ==="
echo "Run './test_e2e.sh' to validate samples with detonate"
