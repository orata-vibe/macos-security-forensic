#!/usr/bin/env python3
"""
Module 3: Active & Passive Application Bundle Auditor (app_bundle_auditor.py)
100% Read-Only diagnostic tool for macOS.

Features:
- Audits ALL `.app` bundles across `/Applications`, `/Applications/Utilities`, `~/Applications`,
  and `/Library/Application Support` (both active in RAM and passive/dormant on disk).
- Checks `Contents/Info.plist` `CFBundleExecutable` to ensure no Mach-O binary was replaced by a
  shell/python wrapper script.
- Performs two-tier cryptographic verification (`--strict` vs `--no-strict`), classifying benign
  Finder xattrs (`com.apple.FinderInfo`) or Python `.pyc` cache files vs ad-hoc patched binaries.
- Cross-references weak Hardened Runtime entitlements (`disable-library-validation`,
  `allow-dyld-environment-variables`) against user TCC grants in `TCC.db`.
"""

import os
import sys
import glob
import json
import sqlite3
import plistlib
import subprocess


def get_running_app_paths() -> set:
    res = subprocess.run(["ps", "-axo", "comm"], capture_output=True, text=True)
    active = set()
    for line in res.stdout.splitlines()[1:]:
        idx = line.find(".app/")
        if idx != -1:
            active.add(line[: idx + 4].strip())
    return active


def get_user_tcc_grants() -> dict:
    tcc_path = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    grants = {}
    if not os.path.exists(tcc_path):
        return grants
    try:
        conn = sqlite3.connect(f"file:{tcc_path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT client, service, auth_value FROM access WHERE auth_value = 2")
        for client, service, _ in cur.fetchall():
            grants.setdefault(client, []).append(service.replace("kTCCService", ""))
        conn.close()
    except Exception:
        pass
    return grants


def audit_single_bundle(app_path: str, active_apps: set, tcc_grants: dict) -> dict:
    info_plist = os.path.join(app_path, "Contents/Info.plist")
    bundle_id, exec_name = "", ""
    if os.path.exists(info_plist):
        try:
            with open(info_plist, "rb") as fp:
                pdata = plistlib.load(fp)
            bundle_id = pdata.get("CFBundleIdentifier", "")
            exec_name = pdata.get("CFBundleExecutable", "")
        except Exception:
            pass

    exec_path = os.path.join(app_path, "Contents/MacOS", exec_name) if exec_name else ""
    exec_file_type = ""
    is_script_wrapper = False
    if exec_path and os.path.exists(exec_path):
        f_res = subprocess.run(["file", "-b", exec_path], capture_output=True, text=True)
        exec_file_type = f_res.stdout.strip()
        if "Mach-O" not in exec_file_type and "script" in exec_file_type.lower():
            is_script_wrapper = True

    # Signature metadata
    cs_info = subprocess.run(
        ["codesign", "-dvvv", "--entitlements", ":-", app_path],
        capture_output=True,
        text=True,
    )
    info_out = cs_info.stderr + cs_info.stdout
    team_id, authority, flags = "", "", ""
    for line in info_out.splitlines():
        if line.startswith("TeamIdentifier="):
            team_id = line.split("=", 1)[1]
        elif line.startswith("Authority=") and not authority:
            authority = line.split("=", 1)[1]
        elif "flags=" in line and "CodeDirectory" in line:
            flags = line.strip()

    # Two-tier verification (--strict and --no-strict)
    v_strict = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=2", app_path],
        capture_output=True,
        text=True,
    )
    v_nostrict = subprocess.run(
        ["codesign", "--verify", "--deep", "--no-strict", "--verbose=2", app_path],
        capture_output=True,
        text=True,
    )

    strict_err = (v_strict.stderr + v_strict.stdout).strip()
    seal_status = "VALID_STRICT"
    if v_strict.returncode != 0:
        if v_nostrict.returncode == 0 and "FinderInfo" in strict_err:
            seal_status = "VALID_WITH_FINDER_XATTR"
        elif ".pyc" in strict_err and "__pycache__" in strict_err:
            seal_status = "VALID_WITH_PYTHON_PYC_CACHE"
        elif "adhoc" in info_out and "linker-signed" in info_out:
            seal_status = "LOCAL_DEV_LINKER_SIGNED"
        elif "Signature=adhoc" in info_out:
            seal_status = "ADHOC_PATCHED_OR_RESIGNED"
        else:
            seal_status = "SEAL_VERIFICATION_FAILED"

    risky_entitlements = []
    for ent in (
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.get-task-allow",
    ):
        if ent in cs_info.stdout:
            # Check if<true/> follows the key
            idx = cs_info.stdout.find(ent)
            snippet = cs_info.stdout[idx : idx + 160]
            if "<true/>" in snippet:
                risky_entitlements.append(ent.split(".")[-1])

    app_tcc = tcc_grants.get(bundle_id, [])

    return {
        "app_path": app_path,
        "bundle_id": bundle_id,
        "state": "ACTIVE" if app_path in active_apps else "PASSIVE",
        "executable": exec_name,
        "is_script_wrapper": is_script_wrapper,
        "team_id": team_id,
        "authority": authority or ("adhoc" if "adhoc" in info_out else "unsigned"),
        "seal_status": seal_status,
        "risky_entitlements": risky_entitlements,
        "tcc_grants": app_tcc,
    }


def run_bundle_audit(as_json: bool = False) -> dict:
    search_patterns = [
        "/Applications/*.app",
        "/Applications/Utilities/*.app",
        os.path.expanduser("~/Applications/*.app"),
        "/Library/Application Support/**/*.app",
    ]
    all_apps = set()
    for pat in search_patterns:
        for p in glob.glob(pat, recursive=True):
            # Skip nested helper apps inside another .app bundle
            if ".app/Contents/" not in p:
                all_apps.add(p)

    active_apps = get_running_app_paths()
    tcc_grants = get_user_tcc_grants()
    results = [audit_single_bundle(app, active_apps, tcc_grants) for app in sorted(all_apps)]

    summary = {
        "total_bundles_audited": len(results),
        "active_bundles_count": sum(1 for r in results if r["state"] == "ACTIVE"),
        "passive_bundles_count": sum(1 for r in results if r["state"] == "PASSIVE"),
        "wrapper_hijacks_detected": sum(1 for r in results if r["is_script_wrapper"]),
        "bundles": results,
    }

    if as_json:
        print(json.dumps(summary, indent=2))
    else:
        print("=== [MODULE 3] ACTIVE & PASSIVE APPLICATION BUNDLE AUDITOR ===")
        print(
            f"Total Bundles Audited: {summary['total_bundles_audited']} "
            f"(Active: {summary['active_bundles_count']}, Passive: {summary['passive_bundles_count']})"
        )
        print(f"CFBundleExecutable Script Hijacks: {summary['wrapper_hijacks_detected']}\n")
        for r in results:
            ent_str = f" | WeakEnts={r['risky_entitlements']}" if r["risky_entitlements"] else ""
            tcc_str = f" | TCC={r['tcc_grants']}" if r["tcc_grants"] else ""
            print(
                f"  [{r['state']:7}] {os.path.basename(r['app_path']):32} -> {r['seal_status']:26} "
                f"(Team={r['team_id'] or 'none'}){ent_str}{tcc_str}"
            )

    return summary


if __name__ == "__main__":
    run_bundle_audit(as_json="--json" in sys.argv)
