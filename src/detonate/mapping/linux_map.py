"""Linux syscall to ATT&CK technique mapping."""

# Syscall to technique mapping with parameter-based refinement
SYSCALL_TO_TECHNIQUE: dict = {
    "execve": {
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactic": "execution",
        "confidence": 0.5,
        "param_checks": {
            "filename": {
                "bash": {
                    "id": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "sh": {
                    "id": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "python": {
                    "id": "T1059.006",
                    "name": "Python",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "python3": {
                    "id": "T1059.006",
                    "name": "Python",
                    "tactic": "execution",
                    "confidence": 0.9,
                },
                "perl": {
                    "id": "T1059.007",
                    "name": "JavaScript",
                    "tactic": "execution",
                    "confidence": 0.7,
                },
                "ruby": {
                    "id": "T1059.007",
                    "name": "JavaScript",
                    "tactic": "execution",
                    "confidence": 0.7,
                },
                "curl": {
                    "id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "tactic": "command-and-control",
                    "confidence": 0.7,
                },
                "wget": {
                    "id": "T1105",
                    "name": "Ingress Tool Transfer",
                    "tactic": "command-and-control",
                    "confidence": 0.7,
                },
                "nc": {
                    "id": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "execution",
                    "confidence": 0.8,
                },
                "netcat": {
                    "id": "T1059.004",
                    "name": "Unix Shell",
                    "tactic": "execution",
                    "confidence": 0.8,
                },
            }
        },
    },
    "execveat": {
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactic": "execution",
        "confidence": 0.5,
    },
    "ptrace": {
        "technique_id": "T1055.008",
        "technique_name": "Ptrace System Calls",
        "tactic": "defense-evasion",
        "confidence": 0.9,
    },
    "process_vm_writev": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.85,
    },
    "open": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
        "param_checks": {
            "filename": {
                "/etc/passwd": {
                    "id": "T1003.008",
                    "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                    "tactic": "credential-access",
                    "confidence": 0.9,
                },
                "/etc/shadow": {
                    "id": "T1003.008",
                    "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                    "tactic": "credential-access",
                    "confidence": 0.95,
                },
                "/etc/sudoers": {
                    "id": "T1548.003",
                    "name": "Sudo and Sudo Caching",
                    "tactic": "privilege-escalation",
                    "confidence": 0.8,
                },
                ".ssh": {
                    "id": "T1552.004",
                    "name": "Private Keys",
                    "tactic": "credential-access",
                    "confidence": 0.85,
                },
                "id_rsa": {
                    "id": "T1552.004",
                    "name": "Private Keys",
                    "tactic": "credential-access",
                    "confidence": 0.9,
                },
            }
        },
    },
    "openat": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
        "param_checks": {
            "pathname": {
                "/etc/passwd": {
                    "id": "T1003.008",
                    "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                    "tactic": "credential-access",
                    "confidence": 0.9,
                },
                "/etc/shadow": {
                    "id": "T1003.008",
                    "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
                    "tactic": "credential-access",
                    "confidence": 0.95,
                },
            }
        },
    },
    "unlink": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
    },
    "unlinkat": {
        "technique_id": "T1070.004",
        "technique_name": "File Deletion",
        "tactic": "defense-evasion",
        "confidence": 0.6,
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
    "sendto": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "confidence": 0.6,
    },
    "recvfrom": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "confidence": 0.6,
    },
    "clone": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.4,
    },
    "fork": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.3,
    },
    "kill": {
        "technique_id": "T1543",
        "technique_name": "Create or Modify System Process",
        "tactic": "persistence",
        "confidence": 0.3,
    },
    "setuid": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "setgid": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "setreuid": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "privilege-escalation",
        "confidence": 0.85,
    },
    "setregid": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "privilege-escalation",
        "confidence": 0.85,
    },
    "mmap": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.4,
    },
    "mprotect": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.5,
    },
    "mremap": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "defense-evasion",
        "confidence": 0.4,
    },
    "read": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.2,
    },
    "write": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.2,
    },
}
