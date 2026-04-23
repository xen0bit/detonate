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
    # Credential Access - additional syscalls
    "getuid": {
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "credential-access",
        "confidence": 0.4,
    },
    "geteuid": {
        "technique_id": "T1003.008",
        "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "credential-access",
        "confidence": 0.4,
    },
    "setresuid": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "setresgid": {
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
    # Discovery syscalls
    "uname": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.7,
    },
    "getcwd": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "readlink": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "readlinkat": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.6,
    },
    "gethostname": {
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "tactic": "discovery",
        "confidence": 0.7,
    },
    "sysinfo": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.7,
    },
    "getuid32": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "getgid": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "getgid32": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "getgroups": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    "getgroups32": {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.5,
    },
    # Container Escape syscalls
    "mount": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.85,
        "param_checks": {
            "source": {
                "/proc": {
                    "id": "T1611",
                    "name": "Escape to Host",
                    "tactic": "privilege-escalation",
                    "confidence": 0.95,
                },
                "/sys": {
                    "id": "T1611",
                    "name": "Escape to Host",
                    "tactic": "privilege-escalation",
                    "confidence": 0.95,
                },
                "/dev": {
                    "id": "T1611",
                    "name": "Escape to Host",
                    "tactic": "privilege-escalation",
                    "confidence": 0.9,
                },
            }
        },
    },
    "umount": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.7,
    },
    "umount2": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.7,
    },
    "pivot_root": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "unshare": {
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.8,
    },
    # Persistence syscalls
    "renameat2": {
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "defense-evasion",
        "confidence": 0.6,
        "param_checks": {
            "oldpath": {
                ".bash_history": {
                    "id": "T1070.003",
                    "name": "Clear Command History",
                    "tactic": "defense-evasion",
                    "confidence": 0.9,
                },
                ".zsh_history": {
                    "id": "T1070.003",
                    "name": "Clear Command History",
                    "tactic": "defense-evasion",
                    "confidence": 0.9,
                },
                ".history": {
                    "id": "T1070.003",
                    "name": "Clear Command History",
                    "tactic": "defense-evasion",
                    "confidence": 0.85,
                },
            }
        },
    },
    "rename": {
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "defense-evasion",
        "confidence": 0.5,
        "param_checks": {
            "oldpath": {
                ".bash_history": {
                    "id": "T1070.003",
                    "name": "Clear Command History",
                    "tactic": "defense-evasion",
                    "confidence": 0.9,
                },
            }
        },
    },
    "fadvise64": {
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "defense-evasion",
        "confidence": 0.5,
    },
    "posix_fadvise": {
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "defense-evasion",
        "confidence": 0.5,
    },
    # Collection - extended syscalls
    "pread64": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
    },
    "pwrite64": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
    },
    "splice": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.4,
    },
    "vmsplice": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.4,
    },
    "tee": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.3,
    },
    # Exfiltration syscalls
    "sendmsg": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "confidence": 0.6,
    },
    "recvmsg": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "confidence": 0.6,
    },
    # Lateral Movement - SSH/SCP detection via execve param_checks already covers this
    # Additional network syscalls for lateral movement
    "accept": {
        "technique_id": "T1021.004",
        "technique_name": "SSH",
        "tactic": "lateral-movement",
        "confidence": 0.4,
    },
    "accept4": {
        "technique_id": "T1021.004",
        "technique_name": "SSH",
        "tactic": "lateral-movement",
        "confidence": 0.4,
    },
    # Additional file operations for persistence
    "access": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
        "param_checks": {
            "pathname": {
                "/etc/cron": {
                    "id": "T1053.003",
                    "name": "Cron",
                    "tactic": "persistence",
                    "confidence": 0.85,
                },
                "/var/spool/cron": {
                    "id": "T1053.003",
                    "name": "Cron",
                    "tactic": "persistence",
                    "confidence": 0.9,
                },
                "/etc/systemd/system": {
                    "id": "T1543.002",
                    "name": "Systemd Service",
                    "tactic": "persistence",
                    "confidence": 0.85,
                },
                ".bashrc": {
                    "id": "T1546.004",
                    "name": "Unix Shell Configuration Modification",
                    "tactic": "persistence",
                    "confidence": 0.8,
                },
                ".profile": {
                    "id": "T1546.004",
                    "name": "Unix Shell Configuration Modification",
                    "tactic": "persistence",
                    "confidence": 0.8,
                },
                ".bash_profile": {
                    "id": "T1546.004",
                    "name": "Unix Shell Configuration Modification",
                    "tactic": "persistence",
                    "confidence": 0.8,
                },
            }
        },
    },
    "faccessat": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
        "param_checks": {
            "pathname": {
                "/etc/cron": {
                    "id": "T1053.003",
                    "name": "Cron",
                    "tactic": "persistence",
                    "confidence": 0.85,
                },
                "/etc/systemd/system": {
                    "id": "T1543.002",
                    "name": "Systemd Service",
                    "tactic": "persistence",
                    "confidence": 0.85,
                },
            }
        },
    },
    "stat": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
    },
    "fstat": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
    },
    "lstat": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
    },
    "statx": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "discovery",
        "confidence": 0.4,
    },
    # Cloud metadata detection via connect param_checks
    # Additional credential access paths for openat
}

# Enhanced param_checks for existing syscalls
# Add cloud metadata endpoint detection to socket/connect
SYSCALL_TO_TECHNIQUE["connect"]["param_checks"] = {
    "address": {
        "169.254.169.254": {
            "id": "T1592.004",
            "name": "Cloud Service Dashboard",
            "tactic": "reconnaissance",
            "confidence": 0.9,
        },
        "metadata.google.internal": {
            "id": "T1592.004",
            "name": "Cloud Service Dashboard",
            "tactic": "reconnaissance",
            "confidence": 0.9,
        },
        "169.254.170.2": {
            "id": "T1592.004",
            "name": "Cloud Service Dashboard",
            "tactic": "reconnaissance",
            "confidence": 0.9,
        },
    }
}

# Enhance openat with more credential and persistence paths
SYSCALL_TO_TECHNIQUE["openat"]["param_checks"]["pathname"].update({
    "/etc/cron.d/": {
        "id": "T1053.003",
        "name": "Cron",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    "/var/spool/cron/": {
        "id": "T1053.003",
        "name": "Cron",
        "tactic": "persistence",
        "confidence": 0.9,
    },
    "/etc/systemd/system/": {
        "id": "T1543.002",
        "name": "Systemd Service",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    "/etc/init.d/": {
        "id": "T1543.002",
        "name": "Systemd Service",
        "tactic": "persistence",
        "confidence": 0.8,
    },
    ".bashrc": {
        "id": "T1546.004",
        "name": "Unix Shell Configuration Modification",
        "tactic": "persistence",
        "confidence": 0.8,
    },
    ".profile": {
        "id": "T1546.004",
        "name": "Unix Shell Configuration Modification",
        "tactic": "persistence",
        "confidence": 0.8,
    },
    "/var/run/docker.sock": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "/run/containerd/containerd.sock": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "/.dockerenv": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.85,
    },
    "/proc/self/environ": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "discovery",
        "confidence": 0.75,
    },
    "/proc/self/cmdline": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "discovery",
        "confidence": 0.75,
    },
})

# Enhance open with the same paths
SYSCALL_TO_TECHNIQUE["open"]["param_checks"]["filename"].update({
    "/etc/cron.d/": {
        "id": "T1053.003",
        "name": "Cron",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    "/var/spool/cron/": {
        "id": "T1053.003",
        "name": "Cron",
        "tactic": "persistence",
        "confidence": 0.9,
    },
    "/etc/systemd/system/": {
        "id": "T1543.002",
        "name": "Systemd Service",
        "tactic": "persistence",
        "confidence": 0.85,
    },
    ".bashrc": {
        "id": "T1546.004",
        "name": "Unix Shell Configuration Modification",
        "tactic": "persistence",
        "confidence": 0.8,
    },
    "/var/run/docker.sock": {
        "id": "T1611",
        "name": "Escape to Host",
        "tactic": "privilege-escalation",
        "confidence": 0.9,
    },
    "/proc/self/environ": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "discovery",
        "confidence": 0.75,
    },
})
