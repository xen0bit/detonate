"""Windows API hooks for Qiling emulation."""

from datetime import datetime
from typing import Any

import structlog

from ..session import AnalysisSession, APICallRecord

log = structlog.get_logger()


class WindowsHooks:
    """
    Windows API hook installer.

    Hooks key Windows APIs to capture malicious behavior and map
    to ATT&CK techniques.
    """

    def __init__(self, session: AnalysisSession, ql: Any):
        """
        Initialize Windows hooks.

        Args:
            session: Active analysis session
            ql: Qiling instance
        """
        self.session = session
        self.ql = ql

        # API to hook mapping
        self.hooks = {
            # Process execution
            "CreateProcessA": self.hook_CreateProcessA,
            "CreateProcessW": self.hook_CreateProcessW,
            "ShellExecuteA": self.hook_ShellExecuteA,
            "ShellExecuteW": self.hook_ShellExecuteW,
            "WinExec": self.hook_WinExec,
            # Process injection
            "VirtualAllocEx": self.hook_VirtualAllocEx,
            "WriteProcessMemory": self.hook_WriteProcessMemory,
            "CreateRemoteThread": self.hook_CreateRemoteThread,
            "NtCreateThreadEx": self.hook_NtCreateThreadEx,
            "SetThreadContext": self.hook_SetThreadContext,
            # Registry
            "RegOpenKeyExA": self.hook_RegOpenKeyExA,
            "RegOpenKeyExW": self.hook_RegOpenKeyExW,
            "RegQueryValueExA": self.hook_RegQueryValueExA,
            "RegSetValueExA": self.hook_RegSetValueExA,
            "RegCreateKeyExA": self.hook_RegCreateKeyExA,
            # File operations
            "CreateFileA": self.hook_CreateFileA,
            "CreateFileW": self.hook_CreateFileW,
            "ReadFile": self.hook_ReadFile,
            "WriteFile": self.hook_WriteFile,
            "DeleteFileA": self.hook_DeleteFileA,
            # Services
            "CreateServiceA": self.hook_CreateServiceA,
            "StartServiceA": self.hook_StartServiceA,
            # Network
            "InternetOpenA": self.hook_InternetOpenA,
            "InternetConnectA": self.hook_InternetConnectA,
            "HttpOpenRequestA": self.hook_HttpOpenRequestA,
            "socket": self.hook_socket,
            "connect": self.hook_connect,
            # Crypto
            "CryptEncrypt": self.hook_CryptEncrypt,
            "CryptDecrypt": self.hook_CryptDecrypt,
            # Privilege
            "AdjustTokenPrivileges": self.hook_AdjustTokenPrivileges,
            "OpenProcessToken": self.hook_OpenProcessToken,
            # DLL loading
            "LoadLibraryA": self.hook_LoadLibraryA,
            "LoadLibraryW": self.hook_LoadLibraryW,
            "GetProcAddress": self.hook_GetProcAddress,
            # Synchronization
            "CreateMutexA": self.hook_CreateMutexA,
            "CreateMutexW": self.hook_CreateMutexW,
            # Native APIs
            "NtCreateFile": self.hook_NtCreateFile,
            "NtOpenKey": self.hook_NtOpenKey,
            "NtSetValueKey": self.hook_NtSetValueKey,
        }

    def install(self) -> None:
        """Install all hooks."""
        for api_name, hook_func in self.hooks.items():
            try:
                self.ql.os.set_api(api_name, hook_func)
            except Exception as e:
                log.debug("hook_install_failed", api=api_name, error=str(e))

    def _record_api_call(
        self,
        api_name: str,
        params: dict[str, Any],
        return_value: Any = None,
        address: str | None = None,
        technique_id: str | None = None,
        confidence: str | None = None,
    ) -> APICallRecord:
        """
        Record an API call with full context.

        Args:
            api_name: Name of the API function
            params: Dictionary of parameter names to values
            return_value: Return value from the API call (captured after hook returns)
            address: Caller address (defaults to current PC if not provided)
            technique_id: Optional ATT&CK technique ID
            confidence: Optional confidence level

        Returns:
            APICallRecord for this API call
        """
        from datetime import datetime, timezone

        # Timezone-aware timestamp (Python 3.12+ compatible)
        timestamp = datetime.now(timezone.utc)

        # Extract caller address from program counter if not provided
        if address is None:
            try:
                address = hex(self.ql.arch.pc)
            except Exception:
                address = "0x0"

        # Increment sequence number for ordering
        self.session._call_sequence += 1
        sequence_number = self.session._call_sequence

        # Build the record
        record = APICallRecord(
            timestamp=timestamp,
            api_name=api_name,
            syscall_name=None,
            params=params,
            return_value=return_value,
            address=address,
            technique_id=technique_id,
            confidence=confidence,
            sequence_number=sequence_number,
        )

        # Add to session
        self.session.add_api_call(record)

        # Emit structured log event with session context
        log.bind(
            session_id=self.session.session_id,
            sample_sha256=self.session.sample_sha256,
            platform=self.session.platform,
        ).info(
            "api_call",
            api=api_name,
            params=params,
            return_value=return_value,
            address=address,
            technique_id=technique_id,
            confidence=confidence,
            sequence_number=sequence_number,
        )

        return record

    def _detect_technique(self, api_name: str, params: dict[str, Any]) -> tuple[str, str, str, float]:
        """
        Detect ATT&CK technique from API call.

        Returns:
            Tuple of (technique_id, technique_name, tactic, confidence_score)
        """
        # Import mapping here to avoid circular imports
        from ...mapping.windows_map import API_TO_TECHNIQUE

        key = f"{api_name}"
        if key in API_TO_TECHNIQUE:
            mapping = API_TO_TECHNIQUE[key]

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

        # Default: unknown technique
        return ("unknown", "Unknown Technique", "unknown", 0.2)

    # Process execution hooks
    def hook_CreateProcessA(self, ql: Any) -> None:
        """
        Hook CreateProcessA to detect process execution.

        Captures command line, return value, and PROCESS_INFORMATION (pid/handles)
        for tracking child processes.
        """
        # Read parameters from stack (stdcall: params pushed right-to-left)
        # lpApplicationName = param 0, lpCommandLine = param 1
        lpApplicationName_ptr = ql.os.f_param_read(0)
        lpCommandLine_ptr = ql.os.f_param_read(1)

        # Read strings with graceful error handling
        app_name = ""
        cmd_line = ""
        try:
            if lpApplicationName_ptr:
                app_name = ql.mem.string(lpApplicationName_ptr)
        except Exception:
            app_name = "<invalid_pointer>"

        try:
            if lpCommandLine_ptr:
                cmd_line = ql.mem.string(lpCommandLine_ptr)
        except Exception:
            cmd_line = "<invalid_pointer>"

        # Use command line if application name is empty (common pattern)
        if not app_name and cmd_line:
            app_name = cmd_line.split()[0] if cmd_line else ""

        # PROCESS_INFORMATION structure is at param 7 (offset varies by calling convention)
        # For stdcall on x86, it's the 8th parameter (index 7)
        # Structure: hProcess (4), hThread (4), dwProcessId (4), dwThreadId (4) = 16 bytes
        proc_info_ptr = ql.os.f_param_read(7)
        proc_info = {}
        try:
            if proc_info_ptr:
                # Read PROCESS_INFORMATION structure (16 bytes on x86)
                proc_info["hProcess"] = ql.mem.read(proc_info_ptr, 4)
                proc_info["hThread"] = ql.mem.read(proc_info_ptr + 4, 4)
                proc_info["dwProcessId"] = int.from_bytes(ql.mem.read(proc_info_ptr + 8, 4), 'little')
                proc_info["dwThreadId"] = int.from_bytes(ql.mem.read(proc_info_ptr + 12, 4), 'little')
        except Exception:
            proc_info = {"error": "failed_to_read_PROCESS_INFORMATION"}

        params = {
            "lpApplicationName": app_name,
            "lpCommandLine": cmd_line,
            "PROCESS_INFORMATION": proc_info,
        }

        # Record the call (return_value will be populated by hook wrapper)
        record = self._record_api_call("CreateProcessA", params)

        # Detect ATT&CK technique from command line
        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateProcessA", params
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

        # Extract strings of interest
        if app_name:
            self.session.add_string(app_name)
        if cmd_line:
            self.session.add_string(cmd_line)

    def hook_CreateProcessW(self, ql: Any) -> None:
        """Hook CreateProcessW (Unicode version)."""
        cmd_line_ptr = ql.os.f_param_read(1)
        cmd_line = ql.mem.wstring(cmd_line_ptr) if cmd_line_ptr else ""

        params = {"lpCommandLine": cmd_line}
        record = self._record_api_call("CreateProcessW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateProcessW", params
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

    def hook_ShellExecuteA(self, ql: Any) -> None:
        """Hook ShellExecuteA."""
        file_ptr = ql.os.f_param_read(1)
        file_name = ql.mem.string(file_ptr) if file_ptr else ""

        params = {"lpFile": file_name}
        record = self._record_api_call("ShellExecuteA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ShellExecuteA", params
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

    def hook_ShellExecuteW(self, ql: Any) -> None:
        """Hook ShellExecuteW (Unicode)."""
        file_ptr = ql.os.f_param_read(1)
        file_name = ql.mem.wstring(file_ptr) if file_ptr else ""

        params = {"lpFile": file_name}
        self._record_api_call("ShellExecuteW", params)

    def hook_WinExec(self, ql: Any) -> None:
        """Hook WinExec."""
        cmd_ptr = ql.os.f_param_read(0)
        cmd_line = ql.mem.string(cmd_ptr) if cmd_ptr else ""

        params = {"lpCmdLine": cmd_line}
        record = self._record_api_call("WinExec", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "WinExec", params
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

    # Process injection hooks
    def hook_VirtualAllocEx(self, ql: Any) -> None:
        """
        Hook VirtualAllocEx for process injection detection.

        Decodes protection flags and flags RWX (PAGE_EXECUTE_READWRITE) allocations
        as suspicious, especially in remote processes.
        """
        # VirtualAllocEx parameters:
        # hProcess (0), lpAddress (1), dwSize (2), flAllocationType (3), flProtect (4)
        hProcess = ql.os.f_param_read(0)
        lpAddress = ql.os.f_param_read(1)
        dwSize = ql.os.f_param_read(2)
        flAllocationType = ql.os.f_param_read(3)
        flProtect = ql.os.f_param_read(4)

        # Decode protection flags
        PAGE_NOACCESS = 0x01
        PAGE_READONLY = 0x02
        PAGE_READWRITE = 0x04
        PAGE_WRITECOPY = 0x08
        PAGE_EXECUTE = 0x10
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_EXECUTE_WRITECOPY = 0x80
        PAGE_GUARD = 0x100
        PAGE_NOCACHE = 0x200
        PAGE_WRITECOMBINE = 0x400

        protect_flags = []
        if flProtect & PAGE_NOACCESS:
            protect_flags.append("PAGE_NOACCESS")
        if flProtect & PAGE_READONLY:
            protect_flags.append("PAGE_READONLY")
        if flProtect & PAGE_READWRITE:
            protect_flags.append("PAGE_READWRITE")
        if flProtect & PAGE_WRITECOPY:
            protect_flags.append("PAGE_WRITECOPY")
        if flProtect & PAGE_EXECUTE:
            protect_flags.append("PAGE_EXECUTE")
        if flProtect & PAGE_EXECUTE_READ:
            protect_flags.append("PAGE_EXECUTE_READ")
        if flProtect & PAGE_EXECUTE_READWRITE:
            protect_flags.append("PAGE_EXECUTE_READWRITE")
        if flProtect & PAGE_EXECUTE_WRITECOPY:
            protect_flags.append("PAGE_EXECUTE_WRITECOPY")
        if flProtect & PAGE_GUARD:
            protect_flags.append("PAGE_GUARD")
        if flProtect & PAGE_NOCACHE:
            protect_flags.append("PAGE_NOCACHE")
        if flProtect & PAGE_WRITECOMBINE:
            protect_flags.append("PAGE_WRITECOMBINE")

        # Check for RWX (suspicious)
        suspicious_rwx = bool(flProtect & PAGE_EXECUTE_READWRITE)

        # Decode allocation type
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        MEM_RESET = 0x80000
        alloc_types = []
        if flAllocationType & MEM_COMMIT:
            alloc_types.append("MEM_COMMIT")
        if flAllocationType & MEM_RESERVE:
            alloc_types.append("MEM_RESERVE")
        if flAllocationType & MEM_RESET:
            alloc_types.append("MEM_RESET")

        # Determine if this is a remote process allocation
        # hProcess != current process handle suggests remote
        # In Qiling, we can check if hProcess is a known handle
        is_remote = False
        target_pid = None
        try:
            # Try to resolve the handle to a process
            # Qiling may have handle tracking in ql.os.handle_manager or similar
            if hasattr(ql.os, 'handle_manager'):
                handle_info = ql.os.handle_manager.get(hProcess)
                if handle_info and hasattr(handle_info, 'pid'):
                    target_pid = handle_info.pid
                    # Compare to current process (ql.os.pid or similar)
                    current_pid = getattr(ql.os, 'pid', None)
                    if current_pid is not None and target_pid != current_pid:
                        is_remote = True
        except Exception:
            pass

        params = {
            "hProcess": hex(hProcess) if hProcess else "0x0",
            "lpAddress": hex(lpAddress) if lpAddress else "0x0",
            "dwSize": dwSize,
            "flAllocationType": "|".join(alloc_types) if alloc_types else hex(flAllocationType),
            "flProtect": "|".join(protect_flags) if protect_flags else hex(flProtect),
            "flProtect_raw": flProtect,
            "suspicious_rwx": suspicious_rwx,
            "is_remote": is_remote,
            "target_pid": target_pid,
        }

        # Record the call
        record = self._record_api_call("VirtualAllocEx", params)

        # Detect technique with RWX boost
        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "VirtualAllocEx", params
        )

        # Boost confidence for RWX + remote process (classic injection pattern)
        if suspicious_rwx and is_remote:
            confidence = max(confidence, 0.95)

        if technique_id != "unknown":
            self.session.add_technique_evidence(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                confidence=self._score_to_label(confidence),
                confidence_score=confidence,
                api_call=record,
            )

    def hook_WriteProcessMemory(self, ql: Any) -> None:
        """Hook WriteProcessMemory."""
        hProcess = ql.os.f_param_read(0)
        lpBaseAddress = ql.os.f_param_read(1)
        nSize = ql.os.f_param_read(3)

        params = {
            "hProcess": hex(hProcess) if hProcess else "0x0",
            "lpBaseAddress": hex(lpBaseAddress) if lpBaseAddress else "0x0",
            "nSize": nSize,
        }
        record = self._record_api_call("WriteProcessMemory", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "WriteProcessMemory", params
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

    def hook_CreateRemoteThread(self, ql: Any) -> None:
        """Hook CreateRemoteThread for process injection detection."""
        hProcess = ql.os.f_param_read(0)
        lpStartAddress = ql.os.f_param_read(4)

        params = {
            "hProcess": hex(hProcess) if hProcess else "0x0",
            "lpStartAddress": hex(lpStartAddress) if lpStartAddress else "0x0",
        }
        record = self._record_api_call("CreateRemoteThread", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateRemoteThread", params
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

    def hook_NtCreateThreadEx(self, ql: Any) -> None:
        """Hook NtCreateThreadEx."""
        params = {"native_api": "NtCreateThreadEx"}
        record = self._record_api_call("NtCreateThreadEx", params)

        technique_id = "T1055.001"
        technique_name = "Dynamic-link Library Injection"
        tactic = "defense-evasion"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

    def hook_SetThreadContext(self, ql: Any) -> None:
        """Hook SetThreadContext for process hollowing detection."""
        hThread = ql.os.f_param_read(0)

        params = {"hThread": hex(hThread) if hThread else "0x0"}
        record = self._record_api_call("SetThreadContext", params)

        technique_id = "T1055.012"
        technique_name = "Process Hollowing"
        tactic = "defense-evasion"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.85,
            api_call=record,
        )

    # Registry hooks
    def hook_RegOpenKeyExA(self, ql: Any) -> None:
        """Hook RegOpenKeyExA."""
        hKey = ql.os.f_param_read(0)
        lpSubKey = ql.os.f_param_read(1)
        sub_key = ql.mem.string(lpSubKey) if lpSubKey else ""

        params = {"hKey": hKey, "lpSubKey": sub_key}
        record = self._record_api_call("RegOpenKeyExA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RegOpenKeyExA", params
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

    def hook_RegOpenKeyExW(self, ql: Any) -> None:
        """Hook RegOpenKeyExW (Unicode)."""
        lpSubKey = ql.os.f_param_read(1)
        sub_key = ql.mem.wstring(lpSubKey) if lpSubKey else ""

        params = {"lpSubKey": sub_key}
        self._record_api_call("RegOpenKeyExW", params)

    def hook_RegQueryValueExA(self, ql: Any) -> None:
        """Hook RegQueryValueExA."""
        hKey = ql.os.f_param_read(0)
        lpValueName = ql.os.f_param_read(1)
        value_name = ql.mem.string(lpValueName) if lpValueName else ""

        params = {"lpValueName": value_name}
        record = self._record_api_call("RegQueryValueExA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RegQueryValueExA", params
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

    def hook_RegSetValueExA(self, ql: Any) -> None:
        """Hook RegSetValueExA for persistence detection."""
        hKey = ql.os.f_param_read(0)
        lpValueName = ql.os.f_param_read(1)
        value_name = ql.mem.string(lpValueName) if lpValueName else ""

        params = {"lpValueName": value_name}
        record = self._record_api_call("RegSetValueExA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RegSetValueExA", params
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

    def hook_RegCreateKeyExA(self, ql: Any) -> None:
        """Hook RegCreateKeyExA."""
        lpSubKey = ql.os.f_param_read(1)
        sub_key = ql.mem.string(lpSubKey) if lpSubKey else ""

        params = {"lpSubKey": sub_key}
        record = self._record_api_call("RegCreateKeyExA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RegCreateKeyExA", params
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

    # File operation hooks
    def hook_CreateFileA(self, ql: Any) -> None:
        """Hook CreateFileA."""
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.string(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("CreateFileA", params)

        # Extract strings of interest
        if file_name:
            self.session.add_string(file_name)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateFileA", params
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

    def hook_CreateFileW(self, ql: Any) -> None:
        """Hook CreateFileW (Unicode)."""
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.wstring(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        self._record_api_call("CreateFileW", params)

        if file_name:
            self.session.add_string(file_name)

    def hook_ReadFile(self, ql: Any) -> None:
        """Hook ReadFile."""
        hFile = ql.os.f_param_read(0)
        nNumberOfBytesToRead = ql.os.f_param_read(2)

        params = {"hFile": hex(hFile) if hFile else "0x0", "nNumberOfBytesToRead": nNumberOfBytesToRead}
        self._record_api_call("ReadFile", params)

    def hook_WriteFile(self, ql: Any) -> None:
        """Hook WriteFile."""
        hFile = ql.os.f_param_read(0)
        nNumberOfBytesToWrite = ql.os.f_param_read(2)

        params = {"hFile": hex(hFile) if hFile else "0x0", "nNumberOfBytesToWrite": nNumberOfBytesToWrite}
        self._record_api_call("WriteFile", params)

    def hook_DeleteFileA(self, ql: Any) -> None:
        """Hook DeleteFileA."""
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.string(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("DeleteFileA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "DeleteFileA", params
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

    # Service hooks
    def hook_CreateServiceA(self, ql: Any) -> None:
        """Hook CreateServiceA."""
        lpServiceName = ql.os.f_param_read(2)
        service_name = ql.mem.string(lpServiceName) if lpServiceName else ""

        params = {"lpServiceName": service_name}
        record = self._record_api_call("CreateServiceA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateServiceA", params
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

    def hook_StartServiceA(self, ql: Any) -> None:
        """Hook StartServiceA."""
        hService = ql.os.f_param_read(0)
        params = {"hService": hex(hService) if hService else "0x0"}
        record = self._record_api_call("StartServiceA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "StartServiceA", params
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

    # Network hooks
    def hook_InternetOpenA(self, ql: Any) -> None:
        """Hook InternetOpenA."""
        lpszAgent = ql.os.f_param_read(0)
        agent = ql.mem.string(lpszAgent) if lpszAgent else ""

        params = {"lpszAgent": agent}
        record = self._record_api_call("InternetOpenA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "InternetOpenA", params
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

    def hook_InternetConnectA(self, ql: Any) -> None:
        """Hook InternetConnectA."""
        lpszServerName = ql.os.f_param_read(1)
        server_name = ql.mem.string(lpszServerName) if lpszServerName else ""

        params = {"lpszServerName": server_name}
        record = self._record_api_call("InternetConnectA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "InternetConnectA", params
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

    def hook_HttpOpenRequestA(self, ql: Any) -> None:
        """Hook HttpOpenRequestA."""
        lpszVerb = ql.os.f_param_read(1)
        lpszObjectName = ql.os.f_param_read(2)
        verb = ql.mem.string(lpszVerb) if lpszVerb else ""
        object_name = ql.mem.string(lpszObjectName) if lpszObjectName else ""

        params = {"lpszVerb": verb, "lpszObjectName": object_name}
        record = self._record_api_call("HttpOpenRequestA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "HttpOpenRequestA", params
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

    def hook_socket(self, ql: Any) -> None:
        """Hook socket."""
        family = ql.os.f_param_read(0)
        type_ = ql.os.f_param_read(1)
        protocol = ql.os.f_param_read(2)

        params = {"family": family, "type": type_, "protocol": protocol}
        record = self._record_api_call("socket", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "socket", params
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

    def hook_connect(self, ql: Any) -> None:
        """Hook connect."""
        sockfd = ql.os.f_param_read(0)
        # Address parsing would require more complex memory reading
        params = {"sockfd": sockfd}
        record = self._record_api_call("connect", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "connect", params
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

    # Crypto hooks
    def hook_CryptEncrypt(self, ql: Any) -> None:
        """Hook CryptEncrypt."""
        params = {"api": "CryptEncrypt"}
        record = self._record_api_call("CryptEncrypt", params)

        technique_id = "T1486"
        technique_name = "Data Encrypted for Impact"
        tactic = "impact"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="low",
            confidence_score=0.3,
            api_call=record,
        )

    def hook_CryptDecrypt(self, ql: Any) -> None:
        """Hook CryptDecrypt."""
        params = {"api": "CryptDecrypt"}
        record = self._record_api_call("CryptDecrypt", params)

        technique_id = "T1486"
        technique_name = "Data Encrypted for Impact"
        tactic = "impact"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="low",
            confidence_score=0.3,
            api_call=record,
        )

    # Privilege hooks
    def hook_AdjustTokenPrivileges(self, ql: Any) -> None:
        """Hook AdjustTokenPrivileges."""
        params = {"api": "AdjustTokenPrivileges"}
        record = self._record_api_call("AdjustTokenPrivileges", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "AdjustTokenPrivileges", params
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

    def hook_OpenProcessToken(self, ql: Any) -> None:
        """Hook OpenProcessToken."""
        params = {"api": "OpenProcessToken"}
        record = self._record_api_call("OpenProcessToken", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "OpenProcessToken", params
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

    # DLL loading hooks
    def hook_LoadLibraryA(self, ql: Any) -> None:
        """Hook LoadLibraryA."""
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.string(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("LoadLibraryA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "LoadLibraryA", params
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

        if file_name:
            self.session.add_string(file_name)

    def hook_LoadLibraryW(self, ql: Any) -> None:
        """Hook LoadLibraryW (Unicode)."""
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.wstring(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        self._record_api_call("LoadLibraryW", params)

        if file_name:
            self.session.add_string(file_name)

    def hook_GetProcAddress(self, ql: Any) -> None:
        """Hook GetProcAddress."""
        hModule = ql.os.f_param_read(0)
        lpProcName = ql.os.f_param_read(1)
        proc_name = ql.mem.string(lpProcName) if lpProcName else ""

        params = {"hModule": hex(hModule) if hModule else "0x0", "lpProcName": proc_name}
        record = self._record_api_call("GetProcAddress", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "GetProcAddress", params
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

    # Synchronization hooks
    def hook_CreateMutexA(self, ql: Any) -> None:
        """Hook CreateMutexA."""
        lpName = ql.os.f_param_read(2)
        mutex_name = ql.mem.string(lpName) if lpName else ""

        params = {"lpName": mutex_name}
        record = self._record_api_call("CreateMutexA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateMutexA", params
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

        if mutex_name:
            self.session.add_string(mutex_name)

    def hook_CreateMutexW(self, ql: Any) -> None:
        """Hook CreateMutexW (Unicode)."""
        lpName = ql.os.f_param_read(2)
        mutex_name = ql.mem.wstring(lpName) if lpName else ""

        params = {"lpName": mutex_name}
        self._record_api_call("CreateMutexW", params)

        if mutex_name:
            self.session.add_string(mutex_name)

    # Native API hooks
    def hook_NtCreateFile(self, ql: Any) -> None:
        """Hook NtCreateFile."""
        params = {"native_api": "NtCreateFile"}
        record = self._record_api_call("NtCreateFile", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "NtCreateFile", params
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

    def hook_NtOpenKey(self, ql: Any) -> None:
        """Hook NtOpenKey."""
        params = {"native_api": "NtOpenKey"}
        record = self._record_api_call("NtOpenKey", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "NtOpenKey", params
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

    def hook_NtSetValueKey(self, ql: Any) -> None:
        """Hook NtSetValueKey."""
        params = {"native_api": "NtSetValueKey"}
        record = self._record_api_call("NtSetValueKey", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "NtSetValueKey", params
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

    @staticmethod
    def _score_to_label(score: float) -> str:
        """Convert confidence score to label."""
        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        return "low"
