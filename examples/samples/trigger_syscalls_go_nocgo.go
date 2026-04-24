// Package main - Safe Go syscall trigger for detonate testing
// NO CGO - Minimal runtime, direct syscalls for Qiling compatibility
// Build with: GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o trigger_syscalls_go_nocgo trigger_syscalls_go_nocgo.go

//go:build go1.20

package main

import (
	"syscall"
	"unsafe"
)

const (
	AT_FDCWD   = ^uintptr(100)
	F_OK       = 0x0
	O_RDONLY   = 0x0
	O_WRONLY   = 0x1
	O_CREAT    = 0x40
	O_RDWR     = 0x2
	O_TRUNC    = 0x200
)

// Direct syscall wrappers - no error handling to minimize code
func openat(path string, flags, mode int) int {
	b := append([]byte(path), 0)
	r, _, _ := syscall.Syscall6(syscall.SYS_OPENAT, AT_FDCWD, uintptr(unsafe.Pointer(&b[0])), uintptr(flags), uintptr(mode), 0, 0)
	return int(r)
}

func read(fd int, buf []byte) int {
	r, _, _ := syscall.Syscall(syscall.SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return int(r)
}

func writeSyscall(fd int, buf []byte) int {
	r, _, _ := syscall.Syscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return int(r)
}

func close(fd int) {
	syscall.Syscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
}

func unlink(path string) {
	b := append([]byte(path), 0)
	syscall.Syscall(syscall.SYS_UNLINK, uintptr(unsafe.Pointer(&b[0])), 0, 0)
}

func access(path string, mode uint32) {
	b := append([]byte(path), 0)
	syscall.Syscall(syscall.SYS_ACCESS, uintptr(unsafe.Pointer(&b[0])), uintptr(mode), 0)
}

func stat(path string) {
	b := append([]byte(path), 0)
	buf := make([]byte, 144)
	syscall.Syscall(syscall.SYS_STAT, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&buf[0])), 0)
}

func getcwd() {
	buf := make([]byte, 4096)
	syscall.Syscall(syscall.SYS_GETCWD, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
}

func uname() {
	buf := make([]byte, 390)
	syscall.Syscall(syscall.SYS_UNAME, uintptr(unsafe.Pointer(&buf[0])), 0, 0)
}

func readlink(path string) {
	b := append([]byte(path), 0)
	buf := make([]byte, 256)
	syscall.Syscall(syscall.SYS_READLINK, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
}

func socket(family, typ, proto int) int {
	r, _, _ := syscall.Syscall(syscall.SYS_SOCKET, uintptr(family), uintptr(typ), uintptr(proto))
	return int(r)
}

func connect(fd int, addr []byte) {
	syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
}

func sendto(fd int, data, addr []byte) {
	syscall.Syscall6(syscall.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0, uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
}

// Suppress panic output to reduce write syscalls
func init() {
	// Redirect stderr to /dev/null to suppress runtime errors
	devNull := openat("/dev/null", O_WRONLY, 0)
	if devNull >= 0 && devNull != 2 {
		syscall.Syscall(syscall.SYS_DUP2, uintptr(devNull), 2, 0)
		close(devNull)
	}
}

func main() {
	var buf [256]byte

	// 1. Credential access (T1003.008) - /etc/passwd, /etc/shadow
	if fd := openat("/etc/passwd", O_RDONLY, 0); fd >= 0 {
		read(fd, buf[:])
		close(fd)
	}
	if fd := openat("/etc/shadow", O_RDONLY, 0); fd >= 0 {
		read(fd, buf[:])
		close(fd)
	}

	// 2. Privilege escalation (T1548.001) - setuid/setgid/setresuid/setresgid
	syscall.Setuid(0)
	syscall.Setgid(0)
	syscall.Syscall6(syscall.SYS_SETRESUID, 0, 0, 0, 0, 0, 0)
	syscall.Syscall6(syscall.SYS_SETRESGID, 0, 0, 0, 0, 0, 0)

	// 3. Discovery (T1082, T1083, T1016)
	getcwd()
	uname()
	readlink("/proc/self/exe")
	stat("/bin")
	stat("/etc")

	// 4. Persistence recon (T1053.003, T1543.002)
	access("/etc/cron.d/", F_OK)
	access("/etc/systemd/system/", F_OK)
	access("/var/spool/cron/", F_OK)

	// 5. Container escape (T1611)
	stat("/var/run/docker.sock")
	stat("/.dockerenv")

	// 6. Defense evasion (T1070.004)
	tmp := "/tmp/detonate_go"
	if fd := openat(tmp, O_CREAT|O_WRONLY|O_TRUNC, 0644); fd >= 0 {
		writeSyscall(fd, []byte("test\n"))
		close(fd)
		unlink(tmp)
	}

	// 7. Process injection (T1055) - mmap(RWX), mprotect, munmap
	addr, _, _ := syscall.Syscall6(syscall.SYS_MMAP, 0, 4096, 7, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS, ^uintptr(0), 0)
	if addr != 0 {
		syscall.Syscall(syscall.SYS_MPROTECT, addr, 4096, 5)
		syscall.Syscall(syscall.SYS_MUNMAP, addr, 4096, 0)
	}

	// 8. Network (T1071) - TCP connect, UDP sendto
	sockAddr := []byte{2, 0, 0, 53, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0}
	if fd := socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); fd >= 0 {
		connect(fd, sockAddr)
		close(fd)
	}
	if fd := socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0); fd >= 0 {
		dns := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		sendto(fd, dns, sockAddr)
		close(fd)
	}

	// 9. Collection (T1005)
	if fd := openat("/etc/hostname", O_RDONLY, 0); fd >= 0 {
		read(fd, buf[:])
		close(fd)
	}
	if fd := openat("/etc/hosts", O_RDONLY, 0); fd >= 0 {
		read(fd, buf[:])
		close(fd)
	}

	syscall.Exit(0)
}
