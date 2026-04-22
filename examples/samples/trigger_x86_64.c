// trigger_x86_64.c - Safe ELF that triggers observable syscalls for hook testing
// Used for end-to-end verification that detonate captures and maps syscalls correctly
// Compile: gcc -static -o trigger_x86_64 trigger_x86_64.c
//
// Syscalls triggered (with expected ATT&CK mappings):
// - openat(AT_FDCWD, "/etc/passwd", O_RDONLY) - file access observation
// - read() - reading from file descriptor
// - write(STDOUT_FILENO, ...) - console output
// - socket(AF_INET, SOCK_STREAM, 0) - T1071.001 (Web Protocols)
// - setuid(0) - T1548.001 (Setuid and Setgid)
// - exit(0) - clean termination
//
// SAFE: This binary performs no malicious actions. All operations are benign
// and designed solely to exercise the hooking infrastructure.

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

int main(void) {
    // Trigger file access (openat on x86_64 Linux)
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        read(fd, buf, sizeof(buf));
        close(fd);
    }
    
    // Trigger write to stdout
    write(STDOUT_FILENO, "Trigger executed\n", 17);
    
    // Trigger socket creation (network activity)
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        close(sock);
    }
    
    // Trigger setuid (privilege escalation attempt - safe in emulation)
    setuid(0);
    
    return 0;
}
