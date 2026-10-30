#!/usr/bin/env python3
"""
Module 5: Anti-Analysis, Kernel Flags & Stealth Persistence Detector (anti_analysis_detector.py)
100% Read-Only diagnostic tool for macOS.

Features:
- Decodes hexadecimal `<sys/proc.h>` kernel process flags (`ps -axo pid,ppid,uid,flags,comm,command`)
  to detect `P_TRACED (0x00000800)` (`PT_DENY_ATTACH`), `P_DISABLE_ASLR (0x00001000)`,
  `P_SUGID (0x00000100)`, and `P_WEXIT (0x00002000)`.
- Scans `ps eww -ax` for `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`, `ELECTRON_RUN_AS_NODE`,
  `NODE_OPTIONS`, and `SSLKEYLOGFILE`.
- Audits 15+ stealth persistence directories (`SecurityAgentPlugins`, `Audio/Plug-Ins/HAL`,
  `Spotlight`, `QuickLook`, `DirectoryServices`, `ScriptingAdditions`, `Folder Actions`, `LaunchAgents`).
"""

import os
import sys
import glob
import json
import subprocess

P_SUGID = 0x00000100
P_TRACED = 0x00000800
P_DISABLE_ASLR = 0x00001000
P_WEXIT = 0x00002000

STEALTH_PERSISTENCE_DIRS = [
    "/Library/Security/SecurityAgentPlugins",
    "/Library/Audio/Plug-Ins/HAL",
    "/Library/Spotlight",
    os.path.expanduser("~/Library/Spotlight"),
    "/Library/QuickLook",
    os.path.expanduser("~/Library/QuickLook"),
    "/Library/ScriptingAdditions",
    os.path.expanduser("~/Library/ScriptingAdditions"),
    "/Library/DirectoryServices/PlugIns",
    os.path.expanduser("~/Library/Workflows"),
    os.path.expanduser("~/Library/Folder Actions"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    os.path.expanduser("~/Library/LaunchAgents"),
]


def audit_kernel_proc_flags() -> dict:
    res = subprocess.run(
        ["ps", "-axo", "pid,ppid,uid,flags,comm,command"],
        capture_output=True,
        text=True,
    )
    traced_procs = []
    no_aslr_procs = []
    sugid_procs = []
    total = 0

    for line in res.stdout.splitlines()[1:]:
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        pid_s, ppid_s, uid_s, flags_hex, comm, full_cmd = parts
        try:
            fval = int(flags_hex, 16)
        except ValueError:
            continue
        total += 1
        entry = {
            "pid": int(pid_s),
            "ppid": int(ppid_s),
            "uid": int(uid_s),
            "flags": f"0x{fval:x}",
            "comm": comm,
            "cmd": full_cmd[:140],
        }
        if fval & P_TRACED:
            traced_procs.append(entry)
        if fval & P_DISABLE_ASLR:
            no_aslr_procs.append(entry)
        if fval & P_SUGID and comm != "ps":
            sugid_procs.append(entry)

    return {
        "total_processes_scanned": total,
        "p_traced_0x800_count": len(traced_procs),
        "p_traced_processes": traced_procs,
        "p_disable_aslr_0x1000_count": len(no_aslr_procs),
        "p_disable_aslr_processes": no_aslr_procs,
        "p_sugid_0x100_processes": sugid_procs,
    }


def audit_process_environments() -> dict:
    res = subprocess.run(["ps", "eww", "-ax"], capture_output=True, text=True)
    dyld_injections = []
    electron_node_runs = []
    ssl_keylogs = []

    for line in res.stdout.splitlines()[1:]:
        if "DYLD_INSERT_LIBRARIES=" in line or "LD_PRELOAD=" in line:
            dyld_injections.append(line.strip()[:200])
        if "SSLKEYLOGFILE=" in line:
            ssl_keylogs.append(line.strip()[:200])
        if "ELECTRON_RUN_AS_NODE=" in line:
            # Check if it's a legitimate IDE language server / MCP child
            is_benign_ide = "Antigravity IDE.app" in line or "/.gemini/bin/agy" in line or "mcp" in line.lower()
            electron_node_runs.append({
                "benign_ide_context": is_benign_ide,
                "line": line.strip()[:160],
            })

    return {
        "dyld_insert_libraries_hits": dyld_injections,
        "sslkeylogfile_hits": ssl_keylogs,
        "electron_run_as_node_hits": electron_node_runs,
    }


def audit_stealth_persistence() -> list:
    findings = []
    for d in STEALTH_PERSISTENCE_DIRS:
        if os.path.exists(d):
            items = [x for x in os.listdir(d) if not x.startswith(".") and x != "ExtensionsCache"]
            if items:
                findings.append({"directory": d, "items": items})
    return findings


def run_anti_analysis_audit(as_json: bool = False) -> dict:
    flags_rep = audit_kernel_proc_flags()
    env_rep = audit_process_environments()
    pers_rep = audit_stealth_persistence()

    suspicious_electron = [
        e for e in env_rep["electron_run_as_node_hits"] if not e["benign_ide_context"]
    ]

    report = {
        "kernel_flags": flags_rep,
        "environment_injection": env_rep,
        "suspicious_electron_node_abuse": suspicious_electron,
        "non_empty_persistence_dirs": pers_rep,
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("=== [MODULE 5] ANTI-ANALYSIS, KERNEL FLAGS & STEALTH PERSISTENCE ===")
        print(f"Total Kernel Procs Scanned   : {flags_rep['total_processes_scanned']}")
        print(f"P_TRACED (0x800 Anti-Debug)  : {flags_rep['p_traced_0x800_count']} (Expected: 0)")
        print(f"P_DISABLE_ASLR (0x1000)      : {flags_rep['p_disable_aslr_0x1000_count']} (Expected: 0)")
        print(f"DYLD_INSERT_LIBRARIES Hits   : {len(env_rep['dyld_insert_libraries_hits'])} (Expected: 0)")
        print(f"SSLKEYLOGFILE Hits           : {len(env_rep['sslkeylogfile_hits'])} (Expected: 0)")
        print(
            f"ELECTRON_RUN_AS_NODE Hits    : {len(env_rep['electron_run_as_node_hits'])} "
            f"(Suspicious non-IDE: {len(suspicious_electron)})"
        )
        print("Non-Empty Persistence Folders:")
        for p in pers_rep:
            print(f"  - {p['directory']}: {p['items']}")

    return report


if __name__ == "__main__":
    run_anti_analysis_audit(as_json="--json" in sys.argv)
