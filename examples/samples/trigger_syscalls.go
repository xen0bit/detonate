// Package main - Safe Go syscall trigger for detonate testing
// Uses CGO for ptrace syscall (not available in pure Go)
//
// Build (x86_64):
//   GO111MODULE=off CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls trigger_syscalls.go
//
// Build (ARM64 cross-compile):
//   GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 go build -ldflags="-extldflags '-static'" -o trigger_syscalls_arm64 trigger_syscalls.go
//
// SAFE: This binary performs no malicious actions. All operations are benign.
// NOTE: Go runtime initialization is complex and may not fully emulate in Qiling.
// For best results, use the C trigger_x86_64 sample.

package main

/*
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

// CGO wrapper for ptrace (T1055.008)
static int ptrace_traceme() {
    return ptrace(PTRACE_TRACEME, 0, NULL, 0);
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	fmt.Println("=== detonate Go syscall trigger ===")
	fmt.Println("SAFE: All operations are benign")
	fmt.Println()

	// 1. Ptrace (T1055.008)
	fmt.Println("[1/9] Ptrace (T1055.008)...")
	ret := C.ptrace_traceme()
	fmt.Printf("  ptrace: %v\n", ret)

	// 2. Credential access (T1003.008)
	fmt.Println("[2/9] Credential access (T1003.008)...")
	for _, f := range []string{"/etc/passwd", "/etc/shadow"} {
		if fd, err := syscall.Open(f, syscall.O_RDONLY, 0); err == nil {
			buf := make([]byte, 64)
			syscall.Read(fd, buf)
			syscall.Close(fd)
			fmt.Printf("  read %s\n", f)
		}
	}

	// 3. Privilege escalation (T1548.001)
	fmt.Println("[3/9] Privilege escalation (T1548.001)...")
	syscall.Setuid(0)
	syscall.Setgid(0)
	fmt.Println("  setuid/setgid triggered")

	// 4. Discovery (T1082, T1083, T1016)
	fmt.Println("[4/9] Discovery (T1082, T1083, T1016)...")
	os.Getwd()
	os.Hostname()
	os.Readlink("/proc/self/exe")
	fmt.Println("  discovery triggered")

	// 5. Persistence recon (T1053.003, T1543.002)
	fmt.Println("[5/9] Persistence recon (T1053.003, T1543.002)...")
	for _, p := range []string{"/etc/cron.d/", "/etc/systemd/system/"} {
		syscall.Access(p, syscall.F_OK)
	}
	fmt.Println("  persistence recon triggered")

	// 6. Container escape (T1611)
	fmt.Println("[6/9] Container escape (T1611)...")
	os.Stat("/var/run/docker.sock")
	os.Stat("/.dockerenv")
	fmt.Println("  container escape triggered")

	// 7. Defense evasion (T1070.003, T1070.004)
	fmt.Println("[7/9] Defense evasion (T1070.003, T1070.004)...")
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("detonate_%d", time.Now().UnixNano()))
	if f, err := os.Create(tmp); err == nil {
		f.WriteString("test\n")
		f.Close()
		os.Remove(tmp)
		fmt.Printf("  temp file: %s\n", tmp)
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		os.Rename(filepath.Join(home, ".bash_history"), filepath.Join(home, ".bash_history.bak"))
		fmt.Println("  rename triggered")
	}

	// 8. Process injection (T1055)
	fmt.Println("[8/9] Process injection (T1055)...")
	addr, _, errno := syscall.Syscall6(syscall.SYS_MMAP, 0, 4096, 7, 0x20|0x20, ^uintptr(0), 0)
	if errno == 0 && addr != 0 {
		fmt.Printf("  mmap at 0x%x\n", addr)
		syscall.Syscall(syscall.SYS_MPROTECT, addr, 4096, 5)
		syscall.Syscall(syscall.SYS_MUNMAP, addr, 4096, 0)
	}

	// 9. Network (T1071)
	fmt.Println("[9/9] Network (T1071)...")
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err == nil {
		addr := &syscall.SockaddrInet4{Port: 53, Addr: [4]byte{8, 8, 8, 8}}
		syscall.Connect(fd, addr)
		syscall.Close(fd)
		fmt.Println("  socket/connect triggered")
	}

	fmt.Println()
	fmt.Println("=== Complete ===")
}
