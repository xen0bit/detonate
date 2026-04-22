// minimal_x86.c - Minimal 32-bit ELF that just exits with code 0
// Used for testing x86 Qiling emulation
// Compile: gcc -static -m32 -o minimal_x86 minimal_x86.c

#include <stdlib.h>

int main(void) {
    return 0;
}
