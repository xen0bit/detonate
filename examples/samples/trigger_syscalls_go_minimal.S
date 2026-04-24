# Minimal assembly syscall trigger for detonate testing
# Build with: go tool asm -o trigger_syscalls_go_minimal.o trigger_syscalls_go_minimal.S
# Then: go tool link -o trigger_syscalls_go_minimal trigger_syscalls_go_minimal.o

TEXT ·main(SB),$0-0
	// 1. openat /etc/passwd (T1003.008)
	MOVQ $257, AX              // SYS_OPENAT
	MOVQ $-100, DI             // AT_FDCWD
	LEAQ ·passwd(SB), SI       // path
	MOVQ $0, DX                // O_RDONLY
	MOVQ $0, R10               // mode
	SYSCALL

	// 2. read
	MOVQ AX, DI                // fd
	LEAQ ·buf(SB), SI          // buf
	MOVQ $64, DX               // count
	MOVQ $0, AX                // SYS_READ
	SYSCALL

	// 3. close
	MOVQ $3, AX                // SYS_CLOSE
	SYSCALL

	// 4. setuid 0 (T1548.001)
	MOVQ $105, AX              // SYS_SETUID
	MOVQ $0, DI
	SYSCALL

	// 5. setgid 0
	MOVQ $106, AX              // SYS_SETGID
	MOVQ $0, DI
	SYSCALL

	// 6. mmap RWX (T1055)
	MOVQ $9, AX                // SYS_MMAP
	XORQ DI, DI                // addr (NULL)
	MOVQ $4096, SI             // length
	MOVQ $7, DX                // PROT_READ|WRITE|EXEC
	MOVQ $34, R10              // MAP_PRIVATE|ANONYMOUS
	MOVQ $-1, R8               // fd
	XORQ R9, R9                // offset
	SYSCALL

	// 7. mprotect
	MOVQ $10, AX               // SYS_MPROTECT
	MOVQ AX, DI                // addr (from mmap return)
	MOVQ $4096, SI             // length
	MOVQ $5, DX                // PROT_READ|EXEC
	SYSCALL

	// 8. munmap
	MOVQ $11, AX               // SYS_MUNMAP
	SYSCALL

	// 9. socket (T1071)
	MOVQ $41, AX               // SYS_SOCKET
	MOVQ $2, DI                // AF_INET
	MOVQ $1, SI                // SOCK_STREAM
	XORQ DX, DX                // protocol
	SYSCALL

	// 10. exit
	MOVQ $60, AX               // SYS_EXIT
	XORQ DI, DI                // status 0
	SYSCALL

DATA ·passwd(SB)/8, $"/etc/passwd\x00"
GLOBL ·passwd(SB),$0,$8
DATA ·buf(SB)/64, $0
GLOBL ·buf(SB),$0,$64
