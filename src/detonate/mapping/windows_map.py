"""Windows API to ATT&CK technique mapping."""

# API to technique mapping with parameter-based refinement
# Structure: {api_name: {technique_id, technique_name, tactic, confidence, param_checks}}

API_TO_TECHNIQUE: dict = {
    "CreateProcessA": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.5,
        "param_checks": {
            "lpCommandLine": {
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "cmd.exe": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "pwsh": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "-enc": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "mshta": {
                    "id": "T1059.005",
                    "name": "Visual Basic",
                    "tactic": "execution",
                    "confidence": 0.85,
                },
                "wscript": {
                    "id": "T1059.005",
                    "name": "Visual Basic",
                    "tactic": "execution",
                    "confidence": 0.85,
                },
                "cscript": {
                    "id": "T1059.005",
                    "name": "Visual Basic",
                    "tactic": "execution",
                    "confidence": 0.85,
                },
                "rundll32": {
                    "id": "T1059.007",
                    "name": "JavaScript",
                    "tactic": "execution",
                    "confidence": 0.7,
                },
                "regsvr32": {
                    "id": "T1218.010",
                    "name": "Regsvr32",
                    "tactic": "defense-evasion",
                    "confidence": 0.85,
                },
            }
        },
    },
    "CreateProcessW": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.5,
        "param_checks": {
            "lpCommandLine": {
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "pwsh": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
            }
        },
    },
    "ShellExecuteA": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.5,
        "param_checks": {
            "lpFile": {
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
            }
        },
    },
    "ShellExecuteW": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.5,
    },
    "WinExec": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.5,
        "param_checks": {
            "lpCmdLine": {
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
            }
        },
    },
    "VirtualAllocEx": {
        "technique_id": "T1055.012",
        "technique_name": "Process Hollowing",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "WriteProcessMemory": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.4,
    },
    "CreateRemoteThread": {
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "defense-evasion",
        "confidence": 0.85,
    },
    "NtCreateThreadEx": {
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "defense-evasion",
        "confidence": 0.9,
    },
    "SetThreadContext": {
        "technique_id": "T1055.012",
        "technique_name": "Process Hollowing",
        "tactic": "defense-evasion",
        "confidence": 0.85,
    },
    "RegOpenKeyExA": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.5,
        "param_checks": {
            "lpSubKey": {
                "currentversion\\run": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.9,
                },
                "currentversion\\runonce": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.9,
                },
                "microsoft\\windows\\currentversion\\run": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.95,
                },
            }
        },
    },
    "RegOpenKeyExW": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "RegQueryValueExA": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "RegSetValueExA": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "confidence": 0.7,
        "param_checks": {
            "lpValueName": {
                "run": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.9,
                }
            }
        },
    },
    "RegCreateKeyExA": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "confidence": 0.6,
    },
    "CreateFileA": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.3,
    },
    "CreateFileW": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.3,
    },
    "DeleteFileA": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "CreateServiceA": {
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    "StartServiceA": {
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic": "persistence",
        "confidence": 0.6,
    },
    "InternetOpenA": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
        "confidence": 0.6,
    },
    "InternetConnectA": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
        "confidence": 0.8,
    },
    "HttpOpenRequestA": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
        "confidence": 0.85,
    },
    "socket": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "confidence": 0.3,
    },
    "connect": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "confidence": 0.5,
    },
    "CryptEncrypt": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
        "confidence": 0.3,
    },
    "CryptDecrypt": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "impact",
        "confidence": 0.3,
    },
    "AdjustTokenPrivileges": {
        "technique_id": "T1134",
        "technique_name": "Access Token Manipulation",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "OpenProcessToken": {
        "technique_id": "T1134",
        "technique_name": "Access Token Manipulation",
        "tactic": "defense-evasion",
        "confidence": 0.4,
    },
    "LoadLibraryA": {
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "defense-evasion",
        "confidence": 0.3,
    },
    "LoadLibraryW": {
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "defense-evasion",
        "confidence": 0.3,
    },
    "GetProcAddress": {
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "defense-evasion",
        "confidence": 0.3,
    },
    "CreateMutexA": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.2,
    },
    "CreateMutexW": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.2,
    },
    "NtCreateFile": {
        "technique_id": "T1106",
        "technique_name": "Native API",
        "tactic": "execution",
        "confidence": 0.4,
    },
    "NtOpenKey": {
        "technique_id": "T1012",
        "technique_name": "Query Registry",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "NtSetValueKey": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    "ReadFile": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
    },
    "WriteFile": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
    },
    # ========================================================================
    # CREDENTIAL ACCESS APIs (NEW)
    # ========================================================================
    "CredEnumerateA": {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "credential-access",
        "confidence": 0.85,
        "param_checks": {
            "Target": {
                "Vault": {
                    "id": "T1003.001",
                    "name": "OS Credential Dumping: LSASS Memory",
                    "tactic": "credential-access",
                    "confidence": 0.95,
                }
            }
        },
    },
    "CredEnumerateW": {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "credential-access",
        "confidence": 0.85,
    },
    "CredReadA": {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "credential-access",
        "confidence": 0.8,
    },
    "CredReadW": {
        "technique_id": "T1003.001",
        "technique_name": "OS Credential Dumping: LSASS Memory",
        "tactic": "credential-access",
        "confidence": 0.8,
    },
    "SamIConnect": {
        "technique_id": "T1003.002",
        "technique_name": "OS Credential Dumping: Security Account Manager",
        "tactic": "credential-access",
        "confidence": 0.9,
    },
    "LsaOpenPolicy": {
        "technique_id": "T1003.004",
        "technique_name": "OS Credential Dumping: LSA Secrets",
        "tactic": "credential-access",
        "confidence": 0.85,
    },
    "LsaQueryInformationPolicy": {
        "technique_id": "T1003.004",
        "technique_name": "OS Credential Dumping: LSA Secrets",
        "tactic": "credential-access",
        "confidence": 0.8,
    },
    # ========================================================================
    # DISCOVERY APIs (NEW)
    # ========================================================================
    "GetSystemInfo": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "GetVersionExA": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "GetVersionExW": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "NetShareEnum": {
        "technique_id": "T1135",
        "technique_name": "Network Share Discovery",
        "tactic": "discovery",
        "confidence": 0.85,
    },
    "NetGetJoinInformation": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.7,
    },
    "DsGetDcNameW": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.75,
    },
    # ========================================================================
    # LATERAL MOVEMENT APIs (NEW)
    # ========================================================================
    "WNetAddConnection2W": {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "lateral-movement",
        "confidence": 0.85,
        "param_checks": {
            "lpRemoteName": {
                "\\\\": {
                    "id": "T1021.002",
                    "name": "Remote Services: SMB/Windows Admin Shares",
                    "tactic": "lateral-movement",
                    "confidence": 0.9,
                }
            }
        },
    },
    "CreateProcessWithLogonW": {
        "technique_id": "T1021.003",
        "technique_name": "Remote Services: Distributed Component Object Model",
        "tactic": "lateral-movement",
        "confidence": 0.9,
    },
    "ImpersonateLoggedOnUser": {
        "technique_id": "T1134.001",
        "technique_name": "Access Token Manipulation: Token Impersonation/Theft",
        "tactic": "defense-evasion",
        "confidence": 0.85,
    },
    # ========================================================================
    # PERSISTENCE APIs (NEW)
    # ========================================================================
    "SchTasksCreate": {
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "persistence",
        "confidence": 0.9,
        "param_checks": {
            "TaskName": {
                "run": {
                    "id": "T1053.005",
                    "name": "Scheduled Task/Job: Scheduled Task",
                    "tactic": "persistence",
                    "confidence": 0.95,
                }
            }
        },
    },
    "RegCreateKeyExW": {
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "confidence": 0.7,
        "param_checks": {
            "lpSubKey": {
                "currentversion\\run": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.9,
                },
                "currentversion\\runonce": {
                    "id": "T1547.001",
                    "name": "Registry Run Keys / Startup Folder",
                    "tactic": "persistence",
                    "confidence": 0.9,
                }
            }
        },
    },
    "CreateServiceW": {
        "technique_id": "T1543.003",
        "technique_name": "Windows Service",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    # ========================================================================
    # DEFENSE EVASION APIs (NEW)
    # ========================================================================
    "SetFileTime": {
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "defense-evasion",
        "confidence": 0.7,
    },
    "RemoveDirectoryA": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "RemoveDirectoryW": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "ClearEventLogA": {
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs",
        "tactic": "defense-evasion",
        "confidence": 0.9,
    },
    "BackupEventLogA": {
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs",
        "tactic": "defense-evasion",
        "confidence": 0.85,
    },
    # ========================================================================
    # EXECUTION APIs (NEW)
    # ========================================================================
    "CreateProcessWithTokenW": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "execution",
        "confidence": 0.7,
        "param_checks": {
            "lpCommandLine": {
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                }
            }
        },
    },
    "ShellExecuteExW": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
        "tactic": "execution",
        "confidence": 0.6,
        "param_checks": {
            "lpFile": {
                "powershell": {
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "tactic": "execution",
                    "confidence": 0.95,
                },
                "cmd": {
                    "id": "T1059.003",
                    "name": "Windows Command Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                }
            }
        },
    },
    # ========================================================================
    # COLLECTION APIs (NEW)
    # ========================================================================
    "FindFirstFileA": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "FindFirstFileW": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "FindNextFileA": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
    },
    "GetClipboardData": {
        "technique_id": "T1115",
        "technique_name": "Clipboard Data",
        "tactic": "collection",
        "confidence": 0.9,
    },
    # ========================================================================
    # EXFILTRATION APIs (NEW)
    # ========================================================================
    "InternetOpenUrlA": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
        "confidence": 0.85,
    },
    "HttpSendRequestA": {
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols",
        "tactic": "command-and-control",
        "confidence": 0.9,
    },
    "FtpPutFileA": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
        "confidence": 0.85,
    },
    # ========================================================================
    # IMPACT APIs (additional)
    # ========================================================================
    "DeleteFileW": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
}
