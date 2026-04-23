/*
 * trigger_syscalls.c - Comprehensive syscall trigger for detonate testing
 * Simplified version optimized for Qiling emulation
 * 
 * Build (x86_64):
 *   gcc -static -o trigger_syscalls_c trigger_syscalls.c
 * 
 * Build (ARM64 cross-compile):
 *   aarch64-linux-gnu-gcc -static -o trigger_syscalls_c_arm64 trigger_syscalls.c
 * 
 * SAFE: All operations are benign and self-contained.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/utsname.h>
#include <signal.h>

int main(void) {
    int fd;
    char buf[64];
    struct stat st;
    struct utsname uts;
    
    printf("=== detonate C syscall trigger ===\n");
    printf("SAFE: All operations are benign\n\n");

    /* 1. Credential access (T1003.008) - open/read /etc/passwd */
    printf("[1/8] Credential access (T1003.008)...\n");
    fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
        printf("  read /etc/passwd\n");
    }
    
    fd = open("/etc/shadow", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
        printf("  read /etc/shadow\n");
    }

    /* 2. Privilege escalation (T1548.001) - setuid/setgid */
    printf("[2/8] Privilege escalation (T1548.001)...\n");
    setuid(0);
    setgid(0);
    syscall(SYS_setresuid, 0, 0, 0);
    syscall(SYS_setresgid, 0, 0, 0);
    printf("  setuid/setgid triggered\n");

    /* 3. Discovery (T1082, T1083, T1016) */
    printf("[3/8] Discovery (T1082, T1083, T1016)...\n");
    getcwd(buf, sizeof(buf));
    gethostname(buf, sizeof(buf));
    uname(&uts);
    readlink("/proc/self/exe", buf, sizeof(buf));
    stat("/bin", &st);
    stat("/etc", &st);
    printf("  discovery syscalls triggered\n");

    /* 4. Persistence recon (T1053.003, T1543.002) */
    printf("[4/8] Persistence recon (T1053.003, T1543.002)...\n");
    access("/etc/cron.d/", F_OK);
    access("/etc/systemd/system/", F_OK);
    access("/var/spool/cron/", F_OK);
    printf("  persistence recon triggered\n");

    /* 5. Container escape (T1611) */
    printf("[5/8] Container escape (T1611)...\n");
    stat("/var/run/docker.sock", &st);
    stat("/.dockerenv", &st);
    printf("  container escape indicators triggered\n");

    /* 6. Defense evasion (T1070.003, T1070.004) */
    printf("[6/8] Defense evasion (T1070.003, T1070.004)...\n");
    snprintf(buf, sizeof(buf), "/tmp/detonate_%ld", time(NULL));
    fd = open(buf, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, "test\n", 5);
        close(fd);
        unlink(buf);
        printf("  temp file created and deleted\n");
    }
    /* rename .bash_history would require getpwuid which breaks static linking */

    /* 7. Process injection (T1055) - mmap/mprotect */
    printf("[7/8] Process injection (T1055)...\n");
    void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr != MAP_FAILED) {
        printf("  mmap(RWX) at %p\n", addr);
        mprotect(addr, 4096, PROT_READ | PROT_EXEC);
        munmap(addr, 4096);
        printf("  mprotect/munmap completed\n");
    }

    /* 8. Network (T1071) */
    printf("[8/8] Network (T1071)...\n");
    {
        struct sockaddr_in addr_in;
        
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            memset(&addr_in, 0, sizeof(addr_in));
            addr_in.sin_family = AF_INET;
            addr_in.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &addr_in.sin_addr);
            connect(fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
            close(fd);
            printf("  socket/connect triggered\n");
        }
        
        /* UDP socket for sendto */
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd >= 0) {
            unsigned char dns_query[] = {
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
                'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
                0x00, 0x01, 0x00, 0x01
            };
            sendto(fd, dns_query, sizeof(dns_query), 0,
                   (struct sockaddr *)&addr_in, sizeof(addr_in));
            close(fd);
            printf("  sendto triggered\n");
        }
    }

    /* Collection (T1005) */
    printf("\n[Collection] (T1005)...\n");
    fd = open("/etc/hostname", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
        printf("  read /etc/hostname\n");
    }
    
    fd = open("/etc/hosts", O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
        printf("  read /etc/hosts\n");
    }

    printf("\n=== Complete ===\n");
    return 0;
}
