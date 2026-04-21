"""Linux syscall hooks for Qiling emulation."""

from datetime import datetime, timezone
from typing import Any

import structlog
from qiling.const import QL_INTERCEPT

from ..session import AnalysisSession, APICallRecord

log = structlog.get_logger()


class LinuxHooks:
    """
    Linux syscall hook installer.

    Hooks key syscalls to capture malicious behavior and map
    to ATT&CK techniques.
    """

    # Syscall numbers for x86_64
    SYS_EXECVE = 59
    SYS_EXECVEAT = 322
    SYS_PTRACE = 101
    SYS_PROCESS_VM_WRITEV = 310
    SYS_OPEN = 2
    SYS_OPENAT = 257
    SYS_READ = 0
    SYS_WRITE = 1
    SYS_UNLINK = 87
    SYS_UNLINKAT = 263
    SYS_SOCKET = 41
    SYS_CONNECT = 42
    SYS_SENDTO = 44
    SYS_RECVFROM = 45
    SYS_CLONE = 56
    SYS_FORK = 57
    SYS_VFORK = 58
    SYS_KILL = 62
    SYS_SETUID = 105
    SYS_SETGID = 106
    SYS_SETREUID = 113
    SYS_SETREGID = 114
    SYS_MMAP = 9
    SYS_MPROTECT = 10
    SYS_MREMAP = 25

    # Syscall name to number mapping for registration
    SYSCALL_NAMES = {
        SYS_EXECVE: "execve",
        SYS_EXECVEAT: "execveat",
        SYS_PTRACE: "ptrace",
        SYS_PROCESS_VM_WRITEV: "process_vm_writev",
        SYS_OPEN: "open",
        SYS_OPENAT: "openat",
        SYS_UNLINK: "unlink",
        SYS_UNLINKAT: "unlinkat",
        SYS_SOCKET: "socket",
        SYS_CONNECT: "connect",
        SYS_SENDTO: "sendto",
        SYS_RECVFROM: "recvfrom",
        SYS_CLONE: "clone",
        SYS_FORK: "fork",
        SYS_VFORK: "vfork",
        SYS_KILL: "kill",
        SYS_SETUID: "setuid",
        SYS_SETGID: "setgid",
        SYS_MMAP: "mmap",
        SYS_MPROTECT: "mprotect",
        SYS_MREMAP: "mremap",
    }

    def __init__(self, session: AnalysisSession, ql: Any):
        """
        Initialize Linux hooks.

        Args:
            session: Active analysis session
            ql: Qiling instance
        """
        self.session = session
        self.ql = ql
        
        # Track pending syscalls for return value capture
        self._pending_syscalls: dict[str, APICallRecord] = {}

        # Syscall number to hook method mapping
        self.hooks = {
            self.SYS_EXECVE: self.hook_sys_execve,
            self.SYS_EXECVEAT: self.hook_sys_execveat,
            self.SYS_PTRACE: self.hook_sys_ptrace,
            self.SYS_PROCESS_VM_WRITEV: self.hook_sys_process_vm_writev,
            self.SYS_OPEN: self.hook_sys_open,
            self.SYS_OPENAT: self.hook_sys_openat,
            self.SYS_READ: self.hook_sys_read,
            self.SYS_WRITE: self.hook_sys_write,
            self.SYS_UNLINK: self.hook_sys_unlink,
            self.SYS_UNLINKAT: self.hook_sys_unlinkat,
            self.SYS_SOCKET: self.hook_sys_socket,
            self.SYS_CONNECT: self.hook_sys_connect,
            self.SYS_SENDTO: self.hook_sys_sendto,
            self.SYS_RECVFROM: self.hook_sys_recvfrom,
            self.SYS_CLONE: self.hook_sys_clone,
            self.SYS_FORK: self.hook_sys_fork,
            self.SYS_VFORK: self.hook_sys_vfork,
            self.SYS_KILL: self.hook_sys_kill,
            self.SYS_SETUID: self.hook_sys_setuid,
            self.SYS_SETGID: self.hook_sys_setgid,
            self.SYS_MMAP: self.hook_sys_mmap,
            self.SYS_MPROTECT: self.hook_sys_mprotect,
            self.SYS_MREMAP: self.hook_sys_mremap,
        }

    def install(self) -> None:
        """Install all syscall hooks using ql.os.set_syscall() with two-phase (ENTER/EXIT) architecture."""
        for syscall_num, hook_func in self.hooks.items():
            try:
                syscall_name = self.SYSCALL_NAMES.get(syscall_num, f"syscall_{syscall_num}")
                
                # Install ENTER hook - captures params and creates pending record
                self.ql.os.set_syscall(syscall_name, hook_func, QL_INTERCEPT.ENTER)
                
                # Install EXIT hook - captures return value and finalizes the record
                self.ql.os.set_syscall(syscall_name, self._create_exit_handler(syscall_name), QL_INTERCEPT.EXIT)
                
            except Exception as e:
                log.debug("hook_install_failed", syscall=syscall_num, error=str(e))

    def _create_exit_handler(self, syscall_name: str):
        """Create an EXIT handler that captures the return value and finalizes the pending record."""
        def exit_handler(ql: Any, *args) -> None:
            # Find the pending record for this syscall
            if self._pending_syscalls:
                # Get the most recent pending record for this syscall
                for seq, (name, record) in list(self._pending_syscalls.items())[::-1]:
                    if name == syscall_name:
                        # Capture return value from RAX
                        try:
                            record.return_value = ql.arch.regs.rax
                        except Exception:
                            record.return_value = -1
                        
                        # Add technique evidence if not already added
                        if record.technique_id is None:
                            technique_id, technique_name, tactic, confidence = self._detect_technique(
                                syscall_name, record.params
                            )
                            if technique_id != "unknown":
                                self.session.add_technique_evidence(
                                    technique_id=technique_id,
                                    technique_name=technique_name,
                                    tactic=tactic,
                                    confidence=self._score_to_label(confidence),
                                    confidence_score=confidence,
                                    api_call=record,
                                )
                        
                        # Remove from pending
                        del self._pending_syscalls[seq]
                        break
        return exit_handler

    def _get_caller_address(self) -> str:
        """Get the instruction pointer of the syscall caller."""
        try:
            # x86_64 uses RIP
            return hex(self.ql.arch.regs.rip)
        except Exception:
            try:
                # Fallback to PC for other architectures
                return hex(self.ql.arch.regs.pc)
            except Exception:
                return "0x0"

    def _decode_prot_flags(self, prot: int) -> list[str]:
        """Decode memory protection flags to human-readable labels."""
        flags = []
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4
        PROT_NONE = 0x0

        if prot == PROT_NONE:
            return ["PROT_NONE"]
        if prot & PROT_READ:
            flags.append("PROT_READ")
        if prot & PROT_WRITE:
            flags.append("PROT_WRITE")
        if prot & PROT_EXEC:
            flags.append("PROT_EXEC")
        return flags if flags else ["PROT_NONE"]

    def _decode_clone_flags(self, flags: int) -> list[str]:
        """Decode clone syscall flags to human-readable labels."""
        result = []
        CLONE_VM = 0x00000100
        CLONE_FS = 0x00000200
        CLONE_FILES = 0x00000400
        CLONE_SIGHAND = 0x00000800
        CLONE_PIDFD = 0x00001000
        CLONE_PTRACE = 0x00002000
        CLONE_VFORK = 0x00004000
        CLONE_PARENT = 0x00008000
        CLONE_THREAD = 0x00010000
        CLONE_NEWNS = 0x00020000
        CLONE_SYSVSEM = 0x00040000
        CLONE_SETTLS = 0x00080000
        CLONE_PARENT_SETTID = 0x00100000
        CLONE_CHILD_CLEARTID = 0x00200000
        CLONE_DETACHED = 0x00400000
        CLONE_UNTRACED = 0x00800000
        CLONE_CHILD_SETTID = 0x01000000
        CLONE_NEWCGROUP = 0x02000000
        CLONE_NEWUTS = 0x04000000
        CLONE_NEWIPC = 0x08000000
        CLONE_NEWUSER = 0x10000000
        CLONE_NEWPID = 0x20000000
        CLONE_NEWNET = 0x40000000
        CLONE_IO = 0x80000000

        flag_map = {
            CLONE_VM: "CLONE_VM",
            CLONE_FS: "CLONE_FS",
            CLONE_FILES: "CLONE_FILES",
            CLONE_SIGHAND: "CLONE_SIGHAND",
            CLONE_PIDFD: "CLONE_PIDFD",
            CLONE_PTRACE: "CLONE_PTRACE",
            CLONE_VFORK: "CLONE_VFORK",
            CLONE_PARENT: "CLONE_PARENT",
            CLONE_THREAD: "CLONE_THREAD",
            CLONE_NEWNS: "CLONE_NEWNS",
            CLONE_SYSVSEM: "CLONE_SYSVSEM",
            CLONE_SETTLS: "CLONE_SETTLS",
            CLONE_PARENT_SETTID: "CLONE_PARENT_SETTID",
            CLONE_CHILD_CLEARTID: "CLONE_CHILD_CLEARTID",
            CLONE_DETACHED: "CLONE_DETACHED",
            CLONE_UNTRACED: "CLONE_UNTRACED",
            CLONE_CHILD_SETTID: "CLONE_CHILD_SETTID",
            CLONE_NEWCGROUP: "CLONE_NEWCGROUP",
            CLONE_NEWUTS: "CLONE_NEWUTS",
            CLONE_NEWIPC: "CLONE_NEWIPC",
            CLONE_NEWUSER: "CLONE_NEWUSER",
            CLONE_NEWPID: "CLONE_NEWPID",
            CLONE_NEWNET: "CLONE_NEWNET",
            CLONE_IO: "CLONE_IO",
        }

        for flag_val, flag_name in flag_map.items():
            if flags & flag_val:
                result.append(flag_name)
        return result if result else [f"0x{flags:x}"]

    def _decode_socket_domain(self, domain: int) -> str:
        """Decode socket domain to human-readable label."""
        domains = {
            0: "AF_UNSPEC",
            1: "AF_UNIX",
            2: "AF_INET",
            10: "AF_INET6",
        }
        return domains.get(domain, f"AF_{domain}")

    def _decode_socket_type(self, type_: int) -> str:
        """Decode socket type to human-readable label."""
        types = {
            1: "SOCK_STREAM",
            2: "SOCK_DGRAM",
            3: "SOCK_RAW",
            4: "SOCK_RDM",
            5: "SOCK_SEQPACKET",
        }
        # Handle SOCK_NONBLOCK and SOCK_CLOEXEC flags
        base_type = type_ & 0x0F
        result = types.get(base_type, f"SOCK_{type_}")
        if type_ & 0o4000:  # SOCK_NONBLOCK
            result += "|SOCK_NONBLOCK"
        if type_ & 0o200000:  # SOCK_CLOEXEC
            result += "|SOCK_CLOEXEC"
        return result

    def _record_syscall(
        self,
        syscall_name: str,
        params: dict[str, Any],
        return_value: Any = None,
        technique_id: str | None = None,
        confidence: str | None = None,
    ) -> APICallRecord:
        """
        Record a syscall call with full context.

        Args:
            syscall_name: Name of the syscall
            params: Syscall parameters (already decoded where applicable)
            return_value: Return value from syscall (captured after execution)
            technique_id: Optional ATT&CK technique ID if immediately known
            confidence: Optional confidence level

        Returns:
            APICallRecord with all context populated
        """
        # Increment sequence counter for ordering
        self.session._call_sequence += 1

        # Get caller's instruction pointer
        caller_addr = self._get_caller_address()

        # Decode known flag/prot parameters in place
        decoded_params = dict(params)
        if "prot" in decoded_params and isinstance(decoded_params["prot"], int):
            decoded_params["prot_decoded"] = self._decode_prot_flags(decoded_params["prot"])
        if "flags" in decoded_params and isinstance(decoded_params["flags"], int):
            if syscall_name == "clone":
                decoded_params["flags_decoded"] = self._decode_clone_flags(decoded_params["flags"])
            elif syscall_name == "mmap":
                # mmap flags: MAP_SHARED, MAP_PRIVATE, etc.
                decoded_params["flags_decoded"] = f"0x{decoded_params['flags']:x}"
            elif syscall_name in ("socket", "connect", "sendto", "recvfrom"):
                # For socket-related syscalls, flags might be domain/type
                if syscall_name == "socket":
                    if "domain" in decoded_params:
                        decoded_params["domain_decoded"] = self._decode_socket_domain(decoded_params["domain"])
                    if "type" in decoded_params:
                        decoded_params["type_decoded"] = self._decode_socket_type(decoded_params["type"])

        record = APICallRecord(
            timestamp=datetime.now(timezone.utc),
            api_name=None,
            syscall_name=syscall_name,
            params=decoded_params,
            return_value=return_value,
            address=caller_addr,
            technique_id=technique_id,
            confidence=confidence,
            sequence_number=self.session._call_sequence,
        )

        self.session.add_api_call(record)
        return record

    def _detect_technique(self, syscall_name: str, params: dict[str, Any]) -> tuple[str, str, str, float]:
        """
        Detect ATT&CK technique from syscall.

        Returns:
            Tuple of (technique_id, technique_name, tactic, confidence_score)
        """
        from ...mapping.linux_map import SYSCALL_TO_TECHNIQUE

        key = syscall_name
        if key in SYSCALL_TO_TECHNIQUE:
            mapping = SYSCALL_TO_TECHNIQUE[key]

            # Check for parameter-based refinement
            if "param_checks" in mapping:
                for param_name, checks in mapping["param_checks"].items():
                    param_value = params.get(param_name, "")
                    if isinstance(param_value, str):
                        for check_value, technique in checks.items():
                            if check_value.lower() in param_value.lower():
                                return (
                                    technique["id"],
                                    technique["name"],
                                    technique["tactic"],
                                    technique["confidence"],
                                )

            return (
                mapping["technique_id"],
                mapping["technique_name"],
                mapping["tactic"],
                mapping["confidence"],
            )

        return ("unknown", "Unknown Technique", "unknown", 0.2)

    def _read_string(self, addr: int) -> str:
        """Read string from memory address."""
        try:
            return self.ql.mem.string(addr)
        except Exception:
            return ""

    def _read_argv(self, addr: int) -> list[str]:
        """Read argv array from memory."""
        argv = []
        try:
            ptr_size = 8  # x86_64
            i = 0
            while True:
                str_addr_bytes = self.ql.mem.read(addr + i * ptr_size, ptr_size)
                str_addr = int.from_bytes(str_addr_bytes, "little")
                if str_addr == 0:
                    break
                argv.append(self._read_string(str_addr))
                i += 1
        except Exception:
            pass
        return argv

    def hook_sys_execve(self, ql: Any, *args) -> None:
        """Hook execve syscall ENTER - capture params and create pending record."""
        # x86_64: rdi = filename, rsi = argv, rdx = envp
        filename_addr = ql.arch.regs.rdi
        argv_addr = ql.arch.regs.rsi

        filename = self._read_string(filename_addr)
        argv = self._read_argv(argv_addr)

        params = {"filename": filename, "argv": argv}
        record = self._record_syscall("execve", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("execve", record)

        log.info("syscall", syscall="execve", params=params, technique_id="pending")

        if filename:
            self.session.add_string(filename)

    def hook_sys_execveat(self, ql: Any, *args) -> None:
        """Hook execveat syscall ENTER - capture params and create pending record."""
        dirfd = ql.arch.regs.rdi
        pathname_addr = ql.arch.regs.rsi

        pathname = self._read_string(pathname_addr)

        params = {"dirfd": dirfd, "pathname": pathname}
        record = self._record_syscall("execveat", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("execveat", record)

        log.info("syscall", syscall="execveat", params=params, technique_id="pending")

        if pathname:
            self.session.add_string(pathname)

    def hook_sys_ptrace(self, ql: Any, *args) -> None:
        """Hook ptrace syscall ENTER - capture params and create pending record."""
        request = ql.arch.regs.rdi
        pid = ql.arch.regs.rsi

        params = {"request": request, "pid": pid}
        record = self._record_syscall("ptrace", params, return_value=None)

        # Add technique evidence immediately (known from syscall type)
        technique_id = "T1055.008"
        technique_name = "Ptrace System Calls"
        tactic = "defense-evasion"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("ptrace", record)

    def hook_sys_process_vm_writev(self, ql: Any, *args) -> None:
        """Hook process_vm_writev ENTER - capture params and create pending record."""
        pid = ql.arch.regs.rdi

        params = {"pid": pid}
        record = self._record_syscall("process_vm_writev", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1055"
        technique_name = "Process Injection"
        tactic = "defense-evasion"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.85,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("process_vm_writev", record)

    def hook_sys_open(self, ql: Any, *args) -> None:
        """Hook open syscall ENTER - capture params and create pending record."""
        filename_addr = ql.arch.regs.rdi
        filename = self._read_string(filename_addr)

        params = {"filename": filename}
        record = self._record_syscall("open", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("open", record)

        if filename:
            self.session.add_string(filename)

    def hook_sys_openat(self, ql: Any, *args) -> None:
        """Hook openat syscall ENTER - capture params and create pending record."""
        dirfd = ql.arch.regs.rdi
        pathname_addr = ql.arch.regs.rsi

        pathname = self._read_string(pathname_addr)

        params = {"dirfd": dirfd, "pathname": pathname}
        record = self._record_syscall("openat", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("openat", record)

        if pathname:
            self.session.add_string(pathname)

    def hook_sys_read(self, ql: Any, *args) -> None:
        """Hook read syscall ENTER - capture params and create pending record."""
        fd = ql.arch.regs.rdi
        buf_addr = ql.arch.regs.rsi
        count = ql.arch.regs.rdx

        params = {"fd": fd, "buf": hex(buf_addr), "count": count}
        record = self._record_syscall("read", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("read", record)

    def hook_sys_write(self, ql: Any, *args) -> None:
        """Hook write syscall ENTER - capture params and create pending record."""
        fd = ql.arch.regs.rdi
        buf_addr = ql.arch.regs.rsi
        count = ql.arch.regs.rdx

        params = {"fd": fd, "buf": hex(buf_addr), "count": count}
        record = self._record_syscall("write", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("write", record)

        # If writing to stdout/stderr, try to capture the output
        if fd in (1, 2):
            try:
                output = ql.mem.read(buf_addr, min(count, 256))
                try:
                    output_str = output.decode("utf-8", errors="replace")
                    log.info("syscall", syscall="write", fd=fd, output=output_str[:100])
                except Exception:
                    pass
            except Exception:
                pass

    def hook_sys_unlink(self, ql: Any, *args) -> None:
        """Hook unlink syscall ENTER - capture params and create pending record."""
        pathname_addr = ql.arch.regs.rdi
        pathname = self._read_string(pathname_addr)

        params = {"pathname": pathname}
        record = self._record_syscall("unlink", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1070.004"
        technique_name = "File Deletion"
        tactic = "defense-evasion"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="medium",
            confidence_score=0.6,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("unlink", record)

    def hook_sys_unlinkat(self, ql: Any, *args) -> None:
        """Hook unlinkat syscall ENTER - capture params and create pending record."""
        pathname_addr = ql.arch.regs.rsi
        pathname = self._read_string(pathname_addr)

        params = {"pathname": pathname}
        record = self._record_syscall("unlinkat", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1070.004"
        technique_name = "File Deletion"
        tactic = "defense-evasion"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="medium",
            confidence_score=0.6,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("unlinkat", record)

        log.info("syscall", syscall="unlinkat", params=params, technique_id=technique_id)

        if pathname:
            self.session.add_string(pathname)

    def hook_sys_socket(self, ql: Any, *args) -> None:
        """Hook socket syscall ENTER - capture params and create pending record."""
        domain = ql.arch.regs.rdi
        type_ = ql.arch.regs.rsi
        protocol = ql.arch.regs.rdx

        params = {"domain": domain, "type": type_, "protocol": protocol}
        record = self._record_syscall("socket", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("socket", record)

    def hook_sys_connect(self, ql: Any, *args) -> None:
        """Hook connect syscall ENTER - capture params and create pending record."""
        sockfd = ql.arch.regs.rdi

        params = {"sockfd": sockfd}
        record = self._record_syscall("connect", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("connect", record)

    def hook_sys_sendto(self, ql: Any, *args) -> None:
        """Hook sendto syscall ENTER - capture params and create pending record."""
        sockfd = ql.arch.regs.rdi
        length = ql.arch.regs.rdx

        params = {"sockfd": sockfd, "length": length}
        record = self._record_syscall("sendto", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("sendto", record)

    def hook_sys_recvfrom(self, ql: Any, *args) -> None:
        """Hook recvfrom syscall ENTER - capture params and create pending record."""
        sockfd = ql.arch.regs.rdi
        length = ql.arch.regs.rdx

        params = {"sockfd": sockfd, "length": length}
        record = self._record_syscall("recvfrom", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("recvfrom", record)

    def hook_sys_clone(self, ql: Any, *args) -> None:
        """Hook clone syscall ENTER - capture params and create pending record."""
        flags = ql.arch.regs.rdi

        params = {"flags": flags}
        record = self._record_syscall("clone", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("clone", record)

    def hook_sys_fork(self, ql: Any, *args) -> None:
        """Hook fork syscall ENTER - capture params and create pending record."""
        params = {}
        record = self._record_syscall("fork", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("fork", record)

        log.info("syscall", syscall="fork", params=params, technique_id="pending")

    def hook_sys_vfork(self, ql: Any, *args) -> None:
        """Hook vfork syscall ENTER - capture params and create pending record."""
        params = {}
        record = self._record_syscall("vfork", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("vfork", record)

        log.info("syscall", syscall="vfork", params=params, technique_id="pending")

    def hook_sys_kill(self, ql: Any, *args) -> None:
        """Hook kill syscall ENTER - capture params and create pending record."""
        pid = ql.arch.regs.rdi
        sig = ql.arch.regs.rsi

        params = {"pid": pid, "sig": sig}
        record = self._record_syscall("kill", params, return_value=None)

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("kill", record)

    def hook_sys_setuid(self, ql: Any, *args) -> None:
        """Hook setuid syscall ENTER - capture params and create pending record."""
        uid = ql.arch.regs.rdi

        params = {"uid": uid}
        record = self._record_syscall("setuid", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1548.001"
        technique_name = "Setuid and Setgid"
        tactic = "privilege-escalation"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("setuid", record)

    def hook_sys_setgid(self, ql: Any, *args) -> None:
        """Hook setgid syscall ENTER - capture params and create pending record."""
        gid = ql.arch.regs.rdi

        params = {"gid": gid}
        record = self._record_syscall("setgid", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1548.001"
        technique_name = "Setuid and Setgid"
        tactic = "privilege-escalation"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("setgid", record)

    def hook_sys_mmap(self, ql: Any, *args) -> None:
        """Hook mmap syscall ENTER - capture params and create pending record."""
        addr = ql.arch.regs.rdi
        length = ql.arch.regs.rsi
        prot = ql.arch.regs.rdx
        flags = ql.arch.regs.r10

        params = {"addr": hex(addr), "length": length, "prot": prot, "flags": flags}
        record = self._record_syscall("mmap", params, return_value=None)

        # Check for RWX (read-write-execute) - detect immediately from params
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        if (prot & PROT_READ) and (prot & PROT_WRITE) and (prot & PROT_EXEC):
            technique_id = "T1055"
            technique_name = "Process Injection"
            tactic = "defense-evasion"
            self.session.add_technique_evidence(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence="medium",
                confidence_score=0.6,
                api_call=record,
            )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("mmap", record)

        log.info("syscall", syscall="mmap", params=params, technique_id="T1055" if (prot & 0x7) == 0x7 else "pending")

    def hook_sys_mprotect(self, ql: Any, *args) -> None:
        """Hook mprotect syscall ENTER - capture params and create pending record."""
        addr = ql.arch.regs.rdi
        length = ql.arch.regs.rsi
        prot = ql.arch.regs.rdx

        params = {"addr": hex(addr), "length": length, "prot": prot}
        record = self._record_syscall("mprotect", params, return_value=None)

        # Check for RWX - detect immediately from params
        PROT_READ = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC = 0x4

        if (prot & PROT_READ) and (prot & PROT_WRITE) and (prot & PROT_EXEC):
            technique_id = "T1055"
            technique_name = "Process Injection"
            tactic = "defense-evasion"
            self.session.add_technique_evidence(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence="medium",
                confidence_score=0.6,
                api_call=record,
            )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("mprotect", record)

        log.info("syscall", syscall="mprotect", params=params, technique_id="T1055" if (prot & 0x7) == 0x7 else "pending")

    def hook_sys_mremap(self, ql: Any, *args) -> None:
        """Hook mremap syscall ENTER - capture params and create pending record."""
        addr = ql.arch.regs.rdi
        old_len = ql.arch.regs.rsi
        new_len = ql.arch.regs.rdx
        flags = ql.arch.regs.r10

        params = {"addr": hex(addr), "old_len": old_len, "new_len": new_len, "flags": flags}
        record = self._record_syscall("mremap", params, return_value=None)

        # Add technique evidence immediately
        technique_id = "T1055"
        technique_name = "Process Injection"
        tactic = "defense-evasion"
        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="low",
            confidence_score=0.4,
            api_call=record,
        )

        # Store as pending - EXIT handler will capture return value
        self._pending_syscalls[record.sequence_number] = ("mremap", record)

        log.info("syscall", syscall="mremap", params=params, technique_id=technique_id)

    @staticmethod
    def _score_to_label(score: float) -> str:
        """Convert confidence score to label."""
        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        return "low"
