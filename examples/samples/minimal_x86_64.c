// minimal_x86_64.c - Minimal 64-bit ELF that just exits with code 0
// Used for testing basic Qiling emulation path
// Compile: gcc -static -o minimal_x86_64 minimal_x86_64.c

#include <stdlib.h>

int main(void) {
    return 0;
}
