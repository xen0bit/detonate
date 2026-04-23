"""Windows API hooks for Qiling emulation."""

from datetime import datetime
from typing import Any

import structlog

from ..session import AnalysisSession, APICallRecord
from ...utils.cve_lookup import lookup_cve

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
            "CreateProcessWithLogonW": self.hook_CreateProcessWithLogonW,
            "CreateProcessWithTokenW": self.hook_CreateProcessWithTokenW,
            "ShellExecuteExW": self.hook_ShellExecuteExW,
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
            "RegCreateKeyExW": self.hook_RegCreateKeyExW,
            # File operations
            "CreateFileA": self.hook_CreateFileA,
            "CreateFileW": self.hook_CreateFileW,
            "ReadFile": self.hook_ReadFile,
            "WriteFile": self.hook_WriteFile,
            "DeleteFileA": self.hook_DeleteFileA,
            "DeleteFileW": self.hook_DeleteFileW,
            "FindFirstFileA": self.hook_FindFirstFileA,
            "FindFirstFileW": self.hook_FindFirstFileW,
            "FindNextFileA": self.hook_FindNextFileA,
            "SetFileTime": self.hook_SetFileTime,
            "RemoveDirectoryA": self.hook_RemoveDirectoryA,
            "RemoveDirectoryW": self.hook_RemoveDirectoryW,
            # Services
            "CreateServiceA": self.hook_CreateServiceA,
            "CreateServiceW": self.hook_CreateServiceW,
            "StartServiceA": self.hook_StartServiceA,
            "SchTasksCreate": self.hook_SchTasksCreate,
            # Network
            "InternetOpenA": self.hook_InternetOpenA,
            "InternetConnectA": self.hook_InternetConnectA,
            "InternetOpenUrlA": self.hook_InternetOpenUrlA,
            "HttpOpenRequestA": self.hook_HttpOpenRequestA,
            "HttpSendRequestA": self.hook_HttpSendRequestA,
            "FtpPutFileA": self.hook_FtpPutFileA,
            "socket": self.hook_socket,
            "connect": self.hook_connect,
            # Crypto
            "CryptEncrypt": self.hook_CryptEncrypt,
            "CryptDecrypt": self.hook_CryptDecrypt,
            # Privilege
            "AdjustTokenPrivileges": self.hook_AdjustTokenPrivileges,
            "OpenProcessToken": self.hook_OpenProcessToken,
            # Credential access
            "CredEnumerateA": self.hook_CredEnumerateA,
            "CredEnumerateW": self.hook_CredEnumerateW,
            "CredReadA": self.hook_CredReadA,
            "CredReadW": self.hook_CredReadW,
            "SamIConnect": self.hook_SamIConnect,
            "LsaOpenPolicy": self.hook_LsaOpenPolicy,
            "LsaQueryInformationPolicy": self.hook_LsaQueryInformationPolicy,
            # Discovery
            "GetSystemInfo": self.hook_GetSystemInfo,
            "GetVersionExA": self.hook_GetVersionExA,
            "GetVersionExW": self.hook_GetVersionExW,
            "NetShareEnum": self.hook_NetShareEnum,
            "NetGetJoinInformation": self.hook_NetGetJoinInformation,
            "DsGetDcNameW": self.hook_DsGetDcNameW,
            # Lateral movement / Token manipulation
            "WNetAddConnection2W": self.hook_WNetAddConnection2W,
            "ImpersonateLoggedOnUser": self.hook_ImpersonateLoggedOnUser,
            # Collection
            "GetClipboardData": self.hook_GetClipboardData,
            # Event log manipulation
            "ClearEventLogA": self.hook_ClearEventLogA,
            "BackupEventLogA": self.hook_BackupEventLogA,
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
        record = self._record_api_call("ShellExecuteW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ShellExecuteW", params
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
    # CVE indicator patterns: file paths/registry keys mapped to CVE IDs
    CVE_INDICATOR_PATTERNS: dict[str, str] = {
        # Eternalblue/smb
        "\\pipe\\srvsvc": "CVE-2017-0144",
        "\\pipe\\browser": "CVE-2017-0144",
        "\\pipe\\lanman": "CVE-2017-0144",
        # PrintNightmare
        "\\sysmon.sys": "CVE-2021-34527",
        "\\spooler": "CVE-2021-34527",
        "ntprint.dll": "CVE-2021-34527",
        "printfilterpipeline": "CVE-2021-34527",
        # zerologon
        "netlogon": "CVE-2020-1472",
        # noberus
        "lsass.exe": "CVE-2024-30085",
        # proxyshell
        "proxyshell": "CVE-2021-34473",
        # log4shell
        "log4j": "CVE-2021-44228",
        # shellshock
        "bash": "CVE-2014-6271",
        # bluekeep
        "termdd": "CVE-2019-0708",
        # smbghost
        "smbv1": "CVE-2020-0796",
        # petipotam
        "petipotam": "CVE-2020-0688",
        # exchange vulnerabilities
        "owa": "CVE-2021-26855",
        "ecp": "CVE-2021-26855",
        # adobe vulnerabilities
        "adobe": "CVE-2023-26369",
        # chrome vulnerabilities
        "chrome": "CVE-2023-2033",
        # windows kernel
        "ntoskrnl": "CVE-2023-36025",
        "win32k": "CVE-2023-36025",
        # crypto wallets (common target)
        "wallet": "CVE-2023-4863",
        "metamask": "CVE-2023-4863",
        # sensitive system files
        "sam": "CVE-2021-36934",
        "system": "CVE-2021-36934",
        "security": "CVE-2021-36934",
    }

    def hook_CreateFileA(self, ql: Any) -> None:
        """
        Hook CreateFileA with CVE detection.
        
        Detects file access patterns associated with known CVEs and
        performs live CVE lookup via NVD API when enabled.
        """
        lpFileName = ql.os.f_param_read(0)
        file_name = ql.mem.string(lpFileName) if lpFileName else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("CreateFileA", params)

        # Technique detection (existing logic)
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

        # CVE detection: check if file path matches known vulnerability indicators
        if file_name:
            file_name_lower = file_name.lower()
            matched_cve_ids: set[str] = set()
            
            for pattern, cve_id in self.CVE_INDICATOR_PATTERNS.items():
                if pattern.lower() in file_name_lower:
                    matched_cve_ids.add(cve_id)
            
            # Perform CVE lookup for each matched CVE
            for cve_id in matched_cve_ids:
                try:
                    cve_data = lookup_cve(cve_id)
                    if cve_data:
                        self.session.add_vulnerability(
                            cve_id=cve_id,
                            cve_data=cve_data,
                            related_api_call=record,
                            technique_id=technique_id if technique_id != "unknown" else None,
                        )
                except Exception:
                    # Fail gracefully if NVD API unavailable
                    pass

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
        record = self._record_api_call("ReadFile", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ReadFile", params
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

    def hook_WriteFile(self, ql: Any) -> None:
        """Hook WriteFile."""
        hFile = ql.os.f_param_read(0)
        nNumberOfBytesToWrite = ql.os.f_param_read(2)

        params = {"hFile": hex(hFile) if hFile else "0x0", "nNumberOfBytesToWrite": nNumberOfBytesToWrite}
        record = self._record_api_call("WriteFile", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "WriteFile", params
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
        """Hook InternetConnectA for C2 infrastructure detection."""
        lpszServerName = ql.os.f_param_read(1)
        server_name = ql.mem.string(lpszServerName) if lpszServerName else ""

        params = {"lpszServerName": server_name}
        record = self._record_api_call("InternetConnectA", params)

        # Track C2 infrastructure
        if server_name and not server_name.startswith("127."):
            self.session.add_infrastructure(
                name=f"C2 Server: {server_name}",
                infrastructure_types=["command-and-control"],
                related_api_call=record,
            )

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
        """Hook HttpOpenRequestA for C2 infrastructure detection."""
        lpszVerb = ql.os.f_param_read(1)
        lpszObjectName = ql.os.f_param_read(2)
        verb = ql.mem.string(lpszVerb) if lpszVerb else ""
        object_name = ql.mem.string(lpszObjectName) if lpszObjectName else ""

        params = {"lpszVerb": verb, "lpszObjectName": object_name}
        record = self._record_api_call("HttpOpenRequestA", params)

        # Track C2 infrastructure from object name (URL path)
        # Include verb for richer context (e.g., "POST /beacon")
        if object_name and ("/" in object_name or "." in object_name):
            infra_name = f"C2 Endpoint: {verb} {object_name}" if verb else f"C2 Endpoint: {object_name}"
            self.session.add_infrastructure(
                name=infra_name,
                infrastructure_types=["command-and-control"],
                related_api_call=record,
            )

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

    def _parse_sockaddr(self, addr_ptr: int, addrlen: int) -> str:
        """
        Parse sockaddr_in/sockaddr_in6 structure to extract IP:port.
        
        Args:
            addr_ptr: Pointer to sockaddr structure
            addrlen: Length of address structure
            
        Returns:
            String representation like "192.168.1.1:443" or "unknown"
        """
        if addr_ptr == 0 or addrlen < 2:
            return "unknown"
        
        try:
            # First 2 bytes are address family (AF_INET=2, AF_INET6=10)
            family_bytes = self.ql.mem.read(addr_ptr, 2)
            family = int.from_bytes(family_bytes, "little")
            
            if family == 2:  # AF_INET
                # sockaddr_in: sin_port (2), sin_addr (4), rest ignored
                # Port at offset 2, IP at offset 4
                port_bytes = self.ql.mem.read(addr_ptr + 2, 2)
                port = int.from_bytes(port_bytes, "big")  # Network byte order
                ip_bytes = self.ql.mem.read(addr_ptr + 4, 4)
                ip = ".".join(str(b) for b in ip_bytes)
                return f"{ip}:{port}"
            elif family == 10:  # AF_INET6
                # sockaddr_in6: sin6_port (2), sin6_flowinfo (4), sin6_addr (16), sin6_scope_id (4)
                port_bytes = self.ql.mem.read(addr_ptr + 2, 2)
                port = int.from_bytes(port_bytes, "big")
                ip_bytes = self.ql.mem.read(addr_ptr + 8, 16)
                ip = ":".join(f"{b:02x}" for b in ip_bytes)
                return f"[{ip}]:{port}"
        except Exception:
            pass
        
        return "unknown"

    def hook_connect(self, ql: Any) -> None:
        """Hook connect for C2 infrastructure detection."""
        sockfd = ql.os.f_param_read(0)
        addr_ptr = ql.os.f_param_read(1)
        addrlen = ql.os.f_param_read(2)
        
        # Parse sockaddr to extract destination IP:port
        dest_addr = self._parse_sockaddr(addr_ptr, addrlen)
        params = {"sockfd": sockfd, "address": dest_addr}
        record = self._record_api_call("connect", params)

        # Track C2 infrastructure (exclude localhost)
        if dest_addr and dest_addr != "unknown":
            is_localhost = (
                dest_addr.startswith("127.") or 
                dest_addr.startswith("[::1]") or
                "::00:00:00:01" in dest_addr
            )
            if not is_localhost:
                self.session.add_infrastructure(
                    name=f"C2 Server: {dest_addr}",
                    infrastructure_types=["command-and-control"],
                    related_api_call=record,
                )

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

    # ========================================================================
    # NEW CREDENTIAL ACCESS HOOKS
    # ========================================================================
    def hook_CredEnumerateA(self, ql: Any) -> None:
        """Hook CredEnumerateA for credential dumping detection."""
        Target_ptr = ql.os.f_param_read(0)
        target = ql.mem.string(Target_ptr) if Target_ptr else ""

        params = {"Target": target}
        record = self._record_api_call("CredEnumerateA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CredEnumerateA", params
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

    def hook_CredEnumerateW(self, ql: Any) -> None:
        """Hook CredEnumerateW (Unicode)."""
        Target_ptr = ql.os.f_param_read(0)
        target = ql.mem.wstring(Target_ptr) if Target_ptr else ""

        params = {"Target": target}
        record = self._record_api_call("CredEnumerateW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CredEnumerateW", params
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

    def hook_CredReadA(self, ql: Any) -> None:
        """Hook CredReadA."""
        Target_ptr = ql.os.f_param_read(0)
        target = ql.mem.string(Target_ptr) if Target_ptr else ""

        params = {"Target": target}
        record = self._record_api_call("CredReadA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CredReadA", params
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

    def hook_CredReadW(self, ql: Any) -> None:
        """Hook CredReadW (Unicode)."""
        Target_ptr = ql.os.f_param_read(0)
        target = ql.mem.wstring(Target_ptr) if Target_ptr else ""

        params = {"Target": target}
        record = self._record_api_call("CredReadW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CredReadW", params
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

    def hook_SamIConnect(self, ql: Any) -> None:
        """Hook SamIConnect for SAM database access detection."""
        params = {"api": "SamIConnect"}
        record = self._record_api_call("SamIConnect", params)

        technique_id = "T1003.002"
        technique_name = "OS Credential Dumping: Security Account Manager"
        tactic = "credential-access"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.9,
            api_call=record,
        )

    def hook_LsaOpenPolicy(self, ql: Any) -> None:
        """Hook LsaOpenPolicy for LSA secrets access detection."""
        params = {"api": "LsaOpenPolicy"}
        record = self._record_api_call("LsaOpenPolicy", params)

        technique_id = "T1003.004"
        technique_name = "OS Credential Dumping: LSA Secrets"
        tactic = "credential-access"

        self.session.add_technique_evidence(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            confidence="high",
            confidence_score=0.85,
            api_call=record,
        )

    def hook_LsaQueryInformationPolicy(self, ql: Any) -> None:
        """Hook LsaQueryInformationPolicy."""
        params = {"api": "LsaQueryInformationPolicy"}
        record = self._record_api_call("LsaQueryInformationPolicy", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "LsaQueryInformationPolicy", params
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

    # ========================================================================
    # NEW DISCOVERY HOOKS
    # ========================================================================
    def hook_GetSystemInfo(self, ql: Any) -> None:
        """Hook GetSystemInfo for system information discovery."""
        params = {"api": "GetSystemInfo"}
        record = self._record_api_call("GetSystemInfo", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "GetSystemInfo", params
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

    def hook_GetVersionExA(self, ql: Any) -> None:
        """Hook GetVersionExA."""
        params = {"api": "GetVersionExA"}
        record = self._record_api_call("GetVersionExA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "GetVersionExA", params
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

    def hook_GetVersionExW(self, ql: Any) -> None:
        """Hook GetVersionExW (Unicode)."""
        params = {"api": "GetVersionExW"}
        record = self._record_api_call("GetVersionExW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "GetVersionExW", params
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

    def hook_NetShareEnum(self, ql: Any) -> None:
        """Hook NetShareEnum for network share discovery."""
        params = {"api": "NetShareEnum"}
        record = self._record_api_call("NetShareEnum", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "NetShareEnum", params
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

    def hook_NetGetJoinInformation(self, ql: Any) -> None:
        """Hook NetGetJoinInformation."""
        params = {"api": "NetGetJoinInformation"}
        record = self._record_api_call("NetGetJoinInformation", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "NetGetJoinInformation", params
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

    def hook_DsGetDcNameW(self, ql: Any) -> None:
        """Hook DsGetDcNameW for domain controller discovery."""
        params = {"api": "DsGetDcNameW"}
        record = self._record_api_call("DsGetDcNameW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "DsGetDcNameW", params
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

    # ========================================================================
    # NEW LATERAL MOVEMENT HOOKS
    # ========================================================================
    def hook_WNetAddConnection2W(self, ql: Any) -> None:
        """Hook WNetAddConnection2W for SMB share connection."""
        lpRemoteName_ptr = ql.os.f_param_read(0)
        lpRemoteName = ql.mem.wstring(lpRemoteName_ptr) if lpRemoteName_ptr else ""

        params = {"lpRemoteName": lpRemoteName}
        record = self._record_api_call("WNetAddConnection2W", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "WNetAddConnection2W", params
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

    def hook_CreateProcessWithLogonW(self, ql: Any) -> None:
        """Hook CreateProcessWithLogonW for lateral movement via credentials."""
        lpUsername_ptr = ql.os.f_param_read(0)
        lpCommandLine_ptr = ql.os.f_param_read(2)

        username = ql.mem.wstring(lpUsername_ptr) if lpUsername_ptr else ""
        cmd_line = ql.mem.wstring(lpCommandLine_ptr) if lpCommandLine_ptr else ""

        params = {"lpUsername": username, "lpCommandLine": cmd_line}
        record = self._record_api_call("CreateProcessWithLogonW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateProcessWithLogonW", params
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

    def hook_ImpersonateLoggedOnUser(self, ql: Any) -> None:
        """Hook ImpersonateLoggedOnUser for token impersonation."""
        hToken = ql.os.f_param_read(0)

        params = {"hToken": hex(hToken) if hToken else "0x0"}
        record = self._record_api_call("ImpersonateLoggedOnUser", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ImpersonateLoggedOnUser", params
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

    # ========================================================================
    # NEW PERSISTENCE HOOKS
    # ========================================================================
    def hook_SchTasksCreate(self, ql: Any) -> None:
        """Hook SchTasksCreate for scheduled task persistence."""
        TaskName_ptr = ql.os.f_param_read(0)
        task_name = ql.mem.string(TaskName_ptr) if TaskName_ptr else ""

        params = {"TaskName": task_name}
        record = self._record_api_call("SchTasksCreate", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "SchTasksCreate", params
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

    def hook_RegCreateKeyExW(self, ql: Any) -> None:
        """Hook RegCreateKeyExW (Unicode)."""
        lpSubKey_ptr = ql.os.f_param_read(1)
        sub_key = ql.mem.wstring(lpSubKey_ptr) if lpSubKey_ptr else ""

        params = {"lpSubKey": sub_key}
        record = self._record_api_call("RegCreateKeyExW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RegCreateKeyExW", params
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

    def hook_CreateServiceW(self, ql: Any) -> None:
        """Hook CreateServiceW (Unicode)."""
        lpServiceName_ptr = ql.os.f_param_read(2)
        service_name = ql.mem.wstring(lpServiceName_ptr) if lpServiceName_ptr else ""

        params = {"lpServiceName": service_name}
        record = self._record_api_call("CreateServiceW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateServiceW", params
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

    # ========================================================================
    # NEW DEFENSE EVASION HOOKS
    # ========================================================================
    def hook_SetFileTime(self, ql: Any) -> None:
        """Hook SetFileTime for timestomping detection."""
        hFile = ql.os.f_param_read(0)

        params = {"hFile": hex(hFile) if hFile else "0x0"}
        record = self._record_api_call("SetFileTime", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "SetFileTime", params
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

    def hook_RemoveDirectoryA(self, ql: Any) -> None:
        """Hook RemoveDirectoryA."""
        lpPathName_ptr = ql.os.f_param_read(0)
        path_name = ql.mem.string(lpPathName_ptr) if lpPathName_ptr else ""

        params = {"lpPathName": path_name}
        record = self._record_api_call("RemoveDirectoryA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RemoveDirectoryA", params
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

    def hook_RemoveDirectoryW(self, ql: Any) -> None:
        """Hook RemoveDirectoryW (Unicode)."""
        lpPathName_ptr = ql.os.f_param_read(0)
        path_name = ql.mem.wstring(lpPathName_ptr) if lpPathName_ptr else ""

        params = {"lpPathName": path_name}
        record = self._record_api_call("RemoveDirectoryW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "RemoveDirectoryW", params
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

    def hook_ClearEventLogA(self, ql: Any) -> None:
        """Hook ClearEventLogA for event log clearing detection."""
        hEventLog = ql.os.f_param_read(0)

        params = {"hEventLog": hex(hEventLog) if hEventLog else "0x0"}
        record = self._record_api_call("ClearEventLogA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ClearEventLogA", params
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

    def hook_BackupEventLogA(self, ql: Any) -> None:
        """Hook BackupEventLogA."""
        hEventLog = ql.os.f_param_read(0)

        params = {"hEventLog": hex(hEventLog) if hEventLog else "0x0"}
        record = self._record_api_call("BackupEventLogA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "BackupEventLogA", params
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

    # ========================================================================
    # NEW EXECUTION HOOKS
    # ========================================================================
    def hook_CreateProcessWithTokenW(self, ql: Any) -> None:
        """Hook CreateProcessWithTokenW."""
        lpCommandLine_ptr = ql.os.f_param_read(1)
        cmd_line = ql.mem.wstring(lpCommandLine_ptr) if lpCommandLine_ptr else ""

        params = {"lpCommandLine": cmd_line}
        record = self._record_api_call("CreateProcessWithTokenW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "CreateProcessWithTokenW", params
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

    def hook_ShellExecuteExW(self, ql: Any) -> None:
        """Hook ShellExecuteExW (Unicode)."""
        lpFile_ptr = ql.os.f_param_read(1)
        file_name = ql.mem.wstring(lpFile_ptr) if lpFile_ptr else ""

        params = {"lpFile": file_name}
        record = self._record_api_call("ShellExecuteExW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "ShellExecuteExW", params
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

    # ========================================================================
    # NEW COLLECTION HOOKS
    # ========================================================================
    def hook_FindFirstFileA(self, ql: Any) -> None:
        """Hook FindFirstFileA."""
        lpFileName_ptr = ql.os.f_param_read(0)
        file_name = ql.mem.string(lpFileName_ptr) if lpFileName_ptr else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("FindFirstFileA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "FindFirstFileA", params
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

    def hook_FindFirstFileW(self, ql: Any) -> None:
        """Hook FindFirstFileW (Unicode)."""
        lpFileName_ptr = ql.os.f_param_read(0)
        file_name = ql.mem.wstring(lpFileName_ptr) if lpFileName_ptr else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("FindFirstFileW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "FindFirstFileW", params
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

    def hook_FindNextFileA(self, ql: Any) -> None:
        """Hook FindNextFileA."""
        hFindFile = ql.os.f_param_read(0)

        params = {"hFindFile": hex(hFindFile) if hFindFile else "0x0"}
        record = self._record_api_call("FindNextFileA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "FindNextFileA", params
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

    def hook_GetClipboardData(self, ql: Any) -> None:
        """Hook GetClipboardData for clipboard data collection."""
        uFormat = ql.os.f_param_read(0)

        params = {"uFormat": uFormat}
        record = self._record_api_call("GetClipboardData", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "GetClipboardData", params
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

    # ========================================================================
    # NEW EXFILTRATION HOOKS
    # ========================================================================
    def hook_InternetOpenUrlA(self, ql: Any) -> None:
        """Hook InternetOpenUrlA."""
        lpszUrl_ptr = ql.os.f_param_read(1)
        url = ql.mem.string(lpszUrl_ptr) if lpszUrl_ptr else ""

        params = {"lpszUrl": url}
        record = self._record_api_call("InternetOpenUrlA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "InternetOpenUrlA", params
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

    def hook_HttpSendRequestA(self, ql: Any) -> None:
        """Hook HttpSendRequestA."""
        lpszHeaders_ptr = ql.os.f_param_read(1)
        headers = ql.mem.string(lpszHeaders_ptr) if lpszHeaders_ptr else ""

        params = {"lpszHeaders": headers}
        record = self._record_api_call("HttpSendRequestA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "HttpSendRequestA", params
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

    def hook_FtpPutFileA(self, ql: Any) -> None:
        """Hook FtpPutFileA for FTP exfiltration detection."""
        lpszLocalFile_ptr = ql.os.f_param_read(1)
        lpszNewRemoteFile_ptr = ql.os.f_param_read(2)

        local_file = ql.mem.string(lpszLocalFile_ptr) if lpszLocalFile_ptr else ""
        remote_file = ql.mem.string(lpszNewRemoteFile_ptr) if lpszNewRemoteFile_ptr else ""

        params = {"lpszLocalFile": local_file, "lpszNewRemoteFile": remote_file}
        record = self._record_api_call("FtpPutFileA", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "FtpPutFileA", params
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

    # ========================================================================
    # ADDITIONAL IMPACT HOOKS
    # ========================================================================
    def hook_DeleteFileW(self, ql: Any) -> None:
        """Hook DeleteFileW (Unicode)."""
        lpFileName_ptr = ql.os.f_param_read(0)
        file_name = ql.mem.wstring(lpFileName_ptr) if lpFileName_ptr else ""

        params = {"lpFileName": file_name}
        record = self._record_api_call("DeleteFileW", params)

        technique_id, technique_name, tactic, confidence = self._detect_technique(
            "DeleteFileW", params
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
