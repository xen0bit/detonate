#!/bin/bash
# Build all safe test samples for detonate
# Requires: gcc (with multilib support for x86), standard C library

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building detonate test samples ==="

# Build minimal_x86_64 (64-bit, exit only)
echo "[1/4] Building minimal_x86_64..."
gcc -static -o minimal_x86_64 minimal_x86_64.c
echo "      -> minimal_x86_64 ($(stat -c%s minimal_x86_64) bytes)"

# Build minimal_x86 (32-bit, exit only)
echo "[2/4] Building minimal_x86..."
gcc -static -m32 -o minimal_x86 minimal_x86.c 2>/dev/null || {
    echo "      WARNING: 32-bit build failed (install gcc-multilib?)"
    echo "      -> minimal_x86 SKIPPED"
}
if [ -f minimal_x86 ]; then
    echo "      -> minimal_x86 ($(stat -c%s minimal_x86) bytes)"
fi

# Build trigger_x86_64 (64-bit, multiple syscalls)
echo "[3/4] Building trigger_x86_64..."
gcc -static -o trigger_x86_64 trigger_x86_64.c
echo "      -> trigger_x86_64 ($(stat -c%s trigger_x86_64) bytes)"

# Build fake_pe_x86.exe (minimal PE header)
echo "[4/4] Building fake_pe_x86.exe..."
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

echo ""
echo "=== Build complete ==="
echo "Run './test_e2e.sh' to validate samples with detonate"
