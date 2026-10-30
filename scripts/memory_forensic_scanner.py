#!/usr/bin/env python3
"""
Module 1: macOS Memory & RAM Fingerprint Forensic Scanner (memory_forensic_scanner.py)
100% Read-Only diagnostic tool for Apple Silicon (arm64e) and Intel Macs.

Features:
- Parses BOTH '==== Non-writable regions' and '==== Writable regions' sections of `vmmap -wide`.
- Splits `cur_prot/max_prot` strictly so non-executable guard/heap regions (`rw-/rwx` in
  PartitionAlloc `Memory Tag 253` or `STACK GUARD`) do not trigger false positives.
- Validates `Memory Tag 255` (`MAP_JIT` APRR hardware-protected JIT regions) and V8 Embedded Builtins
  remapping (`r-x/rwx` pointing to Brave/Electron Frameworks) against process roles & entitlements.
- Audits all non-system `.dylib` and Mach-O files mapped into process address spaces via `lsof` + `codesign`.
"""

import os
import re
import sys
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

VMMAP_LINE_RE = re.compile(
    r"^(.+?)\s+([0-9a-fA-F]+-[0-9a-fA-F]+)\s+\[\s*([^\]]+)\]\s+([rwx-]{3}/[rwx-]{3})\s+SM=(\S+)\s*(.*)$"
)

SYSTEM_PATH_PREFIXES = (
    "/System/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
    "/private/var/db/",
)


def is_jit_expected_process(cmd_line: str) -> bool:
    """Returns True if the process legitimately uses V8 / JS / WebKit JIT (`Memory Tag 255`)."""
    if "--type=renderer" in cmd_line or "--type=utility" in cmd_line and "node.mojom.NodeService" in cmd_line:
        return True
    if "Helper (Renderer)" in cmd_line or "Helper (Plugin)" in cmd_line:
        return True
    if "/Contents/MacOS/Electron" in cmd_line and "--type=" not in cmd_line:
        return True
    if (
        cmd_line.startswith(("node ", "npm "))
        or "/bin/node" in cmd_line
        or "/bin/npm" in cmd_line
        or "/Cellar/node/" in cmd_line
    ):
        return True
    if "WebKit.WebContent" in cmd_line or "JavaScriptCore" in cmd_line:
        return True
    return False


def inspect_pid_vmmap(pid: int, user: str, cmd: str) -> dict:
    """Runs `vmmap -wide <pid>` and inspects all executable regions across both sections."""
    try:
        res = subprocess.run(
            ["vmmap", "-wide", str(pid)],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except Exception as e:
        return {"pid": pid, "cmd": cmd, "accessible": False, "error": str(e)}

    if res.returncode != 0 or not res.stdout:
        return {"pid": pid, "cmd": cmd, "accessible": False}

    jit_allowed = is_jit_expected_process(cmd)
    text_count = 0
    rwx_jit_count = 0
    anomalies = []
    benign_notes = []

    in_regions = False
    for raw_line in res.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("==== Non-writable regions") or line.startswith("==== Writable regions"):
            in_regions = True
            continue
        if line.startswith("====") and in_regions:
            in_regions = False
            continue
        if not in_regions or not line or line.startswith("REGION TYPE"):
            continue

        m = VMMAP_LINE_RE.match(line)
        if not m:
            continue

        rtype, addr_range, size_str, prot, sm_mode, detail = m.groups()
        rtype = rtype.strip()
        detail = detail.strip()
        cur_prot, max_prot = prot.split("/")

        # Only inspect regions where CURRENT protection includes execute ('x')
        if "x" not in cur_prot:
            continue

        if rtype in ("__TEXT", "unused __TEXT"):
            text_count += 1
            continue

        # 1. Check standard Objective-C block trampolines
        if rtype == "mapped file" and "/usr/lib/libobjc-trampolines.dylib" in detail:
            benign_notes.append(f"libobjc-trampolines.dylib ({addr_range}, {prot})")
            continue

        # 2. Check V8 Embedded Builtins remapping (Brave Browser Framework / Electron Framework)
        if rtype == "mapped file" and (
            "Brave Browser Framework" in detail or "Electron Framework" in detail
        ):
            if jit_allowed:
                benign_notes.append(f"V8 Embedded Builtins remap ({addr_range}, {size_str}, {prot})")
                continue
            else:
                anomalies.append({
                    "type": "UNEXPECTED_V8_REMAP_IN_NON_JIT_PROC",
                    "region": rtype,
                    "address": addr_range,
                    "size": size_str,
                    "prot": prot,
                    "detail": detail,
                })
                continue

        # 3. Check Memory Tag 255 (MAP_JIT) or JS JIT generated code
        if rtype in ("Memory Tag 255", "JS JIT generated code", "WebAssembly memory"):
            rwx_jit_count += 1
            if not jit_allowed:
                anomalies.append({
                    "type": "UNEXPECTED_JIT_IN_NON_JIT_PROCESS",
                    "region": rtype,
                    "address": addr_range,
                    "size": size_str,
                    "prot": prot,
                    "sm": sm_mode,
                    "detail": detail,
                })
            continue

        # 4. Any other executable region (e.g. VM_ALLOCATE, MALLOC, Stack, or unknown RWX) is anomalous!
        anomalies.append({
            "type": "ANOMALOUS_EXECUTABLE_MEMORY",
            "region": rtype,
            "address": addr_range,
            "size": size_str,
            "prot": prot,
            "sm": sm_mode,
            "detail": detail,
        })

    return {
        "pid": pid,
        "user": user,
        "cmd": cmd[:140],
        "accessible": True,
        "jit_allowed_role": jit_allowed,
        "text_regions": text_count,
        "jit_rwx_regions": rwx_jit_count,
        "anomalies": anomalies,
        "benign_notes_count": len(benign_notes),
    }


def verify_codesign(path: str) -> dict:
    """Verifies code signature and extracts Authority, TeamIdentifier, and CDHash."""
    if not os.path.exists(path):
        return {"path": path, "status": "MISSING"}
    try:
        res_info = subprocess.run(
            ["codesign", "-dvvv", path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = res_info.stderr + res_info.stdout
        ident, team, cdhash, flags, auth = "", "", "", "", []
        for line in out.splitlines():
            if line.startswith("Identifier="):
                ident = line.split("=", 1)[1]
            elif line.startswith("TeamIdentifier="):
                team = line.split("=", 1)[1]
            elif line.startswith("CDHash="):
                cdhash = line.split("=", 1)[1]
            elif "flags=" in line and "CodeDirectory" in line:
                flags = line.strip()
            elif line.startswith("Authority="):
                auth.append(line.split("=", 1)[1])

        res_ver = subprocess.run(
            ["codesign", "--verify", "--verbose=2", path],
            capture_output=True,
            text=True,
            timeout=6,
        )
        valid = res_ver.returncode == 0
        return {
            "path": path,
            "valid": valid,
            "identifier": ident,
            "team_id": team,
            "cdhash": cdhash,
            "authority": auth[0] if auth else ("adhoc" if "adhoc" in out else "unsigned"),
            "flags": flags,
        }
    except Exception as e:
        return {"path": path, "valid": False, "error": str(e)}


def scan_mapped_non_system_binaries() -> list:
    """Uses `lsof` to find all non-system `txt` files mapped into running user processes."""
    res = subprocess.run(
        ["lsof", "-n", "-P", "-u", str(os.getuid())],
        capture_output=True,
        text=True,
    )
    mapped_paths = set()
    for line in res.stdout.splitlines():
        if " txt " not in line and " REG " not in line:
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        fd_col = parts[3]
        if fd_col != "txt":
            continue
        fpath = parts[8].strip()
        if not fpath.startswith("/"):
            continue
        if any(fpath.startswith(pfx) for pfx in SYSTEM_PATH_PREFIXES):
            continue
        # Only inspect Mach-O binaries / dylibs / frameworks / .node modules
        if (
            fpath.endswith((".dylib", ".node", ".so"))
            or "/Contents/MacOS/" in fpath
            or ".framework/" in fpath
        ) and not fpath.endswith((".car", ".dat", ".pak", ".bin", ".pma", ".db", ".sqlite", ".strings", ".loctable", ".icns", ".ttf", ".otf", ".asar")):
            mapped_paths.add(fpath)

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(verify_codesign, p): p for p in sorted(mapped_paths)}
        for fut in as_completed(futs):
            results.append(fut.result())
    return sorted(results, key=lambda x: x["path"])


def run_memory_audit(as_json: bool = False) -> dict:
    ps_res = subprocess.run(
        ["ps", "-axo", "pid,uid,user,command"],
        capture_output=True,
        text=True,
    )
    my_uid = str(os.getuid())
    targets = []
    for line in ps_res.stdout.splitlines()[1:]:
        parts = line.strip().split(None, 3)
        if len(parts) < 4:
            continue
        pid_str, uid_str, user, cmd = parts
        if uid_str == my_uid:
            targets.append((int(pid_str), user, cmd))

    vmmap_results = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        futs = [pool.submit(inspect_pid_vmmap, pid, user, cmd) for pid, user, cmd in targets]
        for fut in as_completed(futs):
            vmmap_results.append(fut.result())

    accessible = [r for r in vmmap_results if r.get("accessible")]
    anomalous_procs = [r for r in accessible if r.get("anomalies")]
    mapped_bins = scan_mapped_non_system_binaries()
    invalid_bins = [b for b in mapped_bins if not b.get("valid")]

    summary = {
        "total_user_processes": len(targets),
        "vmmap_inspected_processes": len(accessible),
        "anomalous_memory_processes_count": len(anomalous_procs),
        "anomalous_memory_processes": anomalous_procs,
        "mapped_non_system_binaries_count": len(mapped_bins),
        "invalid_mapped_binaries_count": len(invalid_bins),
        "invalid_mapped_binaries": invalid_bins,
    }

    if as_json:
        print(json.dumps(summary, indent=2))
    else:
        print("=== [MODULE 1] MEMORY & RAM FINGERPRINT FORENSIC SCANNER ===")
        print(f"Total User Processes Targeted : {summary['total_user_processes']}")
        print(f"Successfully Inspected (vmmap): {summary['vmmap_inspected_processes']}")
        print(f"Anomalous RWX / Shellcode PIDs: {summary['anomalous_memory_processes_count']}")
        print(f"Mapped Non-System Binaries    : {summary['mapped_non_system_binaries_count']}")
        print(f"Unsigned/Invalid Mapped Bins  : {summary['invalid_mapped_binaries_count']}")
        if anomalous_procs:
            print("\n[!] ANOMALOUS MEMORY REGIONS DETECTED:")
            for ap in anomalous_procs:
                print(f"  PID {ap['pid']} ({ap['cmd']}): {ap['anomalies']}")
        else:
            print("\n[PASS] Zero unauthorized RWX or unbacked executable memory regions detected.")

    return summary


if __name__ == "__main__":
    run_memory_audit(as_json="--json" in sys.argv)
