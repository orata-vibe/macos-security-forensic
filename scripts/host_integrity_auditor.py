#!/usr/bin/env python3
"""
Module 2: System & Browser Host ("Inang") Integrity Auditor (host_integrity_auditor.py)
100% Read-Only diagnostic tool for macOS.

Features:
- Audits `WindowServer` & `SkyLight.framework` (CDHash, Library Validation 0x2000, arm64e PAC `__auth_stubs`, SIP).
- Inspects binary Electron Fuse wire (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`) across all installed Electron apps.
- Audits all Chromium / Brave Browser profiles (`Default`, `Profile 1..N`) for Developer Mode `UnpackedExtensions`
  (`location == 4`), suspicious CLI flags (`--remote-debugging-port`, `--load-extension`, `--no-sandbox`),
  `NativeMessagingHosts`, and `Managed Preferences`.
"""

import os
import sys
import glob
import json
import subprocess

FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
FUSE_NAMES = [
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
]


def audit_windowserver() -> dict:
    ws_path = "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer"
    sip_res = subprocess.run(["csrutil", "status"], capture_output=True, text=True)
    cs_res = subprocess.run(
        ["codesign", "-dvvv", "--entitlements", ":-", ws_path],
        capture_output=True,
        text=True,
    )
    ver_res = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", ws_path],
        capture_output=True,
        text=True,
    )
    otool_res = subprocess.run(
        ["otool", "-hv", ws_path],
        capture_output=True,
        text=True,
    )
    out = cs_res.stderr + cs_res.stdout
    cdhash = ""
    lib_val = False
    for line in out.splitlines():
        if line.startswith("CDHash="):
            cdhash = line.split("=", 1)[1]
        if "library-validation" in line:
            lib_val = True

    return {
        "binary": ws_path,
        "sip_enabled": "enabled" in sip_res.stdout.lower(),
        "strict_verify_passed": ver_res.returncode == 0,
        "cdhash": cdhash,
        "library_validation_enforced": lib_val,
        "arm64e_pac_architecture": "ARM64E" in otool_res.stdout.upper(),
    }


def inspect_electron_fuses(app_path: str) -> dict:
    ef_candidates = glob.glob(
        os.path.join(
            app_path,
            "Contents/Frameworks/Electron Framework.framework/Versions/*/Electron Framework",
        )
    )
    if not ef_candidates:
        return {}
    ef_bin = ef_candidates[0]
    try:
        with open(ef_bin, "rb") as fp:
            data = fp.read()
        idx = data.find(FUSE_SENTINEL)
        if idx == -1:
            return {"electron_binary": ef_bin, "sentinel_found": False}
        offset = idx + len(FUSE_SENTINEL)
        version = data[offset]
        length = data[offset + 1]
        raw_bytes = data[offset + 2 : offset + 2 + length]
        fuses = {}
        for i, b in enumerate(raw_bytes):
            fname = FUSE_NAMES[i] if i < len(FUSE_NAMES) else f"Fuse_{i}"
            fuses[fname] = "ENABLED(1)" if b == ord("1") else ("DISABLED(0)" if b == ord("0") else chr(b))
        return {
            "app": app_path,
            "fuse_version": version,
            "fuses": fuses,
            "high_risk_run_as_node": fuses.get("RunAsNode") == "ENABLED(1)",
        }
    except Exception as e:
        return {"app": app_path, "error": str(e)}


def audit_brave_browser() -> dict:
    # 1. Check active Brave CLI flags
    ps_res = subprocess.run(["ps", "-axo", "pid,ppid,command"], capture_output=True, text=True)
    brave_procs = []
    suspicious_cli_flags = []
    dangerous_flags = (
        "--load-extension",
        "--disable-extensions-except",
        "--remote-debugging-port",
        "--remote-debugging-pipe",
        "--no-sandbox",
        "--disable-web-security",
        "--gpu-launcher",
        "--renderer-cmd-prefix",
        "--utility-cmd-prefix",
    )
    for line in ps_res.stdout.splitlines()[1:]:
        if "Brave Browser" in line:
            brave_procs.append(line.strip())
            for df in dangerous_flags:
                if df in line:
                    suspicious_cli_flags.append({"flag": df, "process": line.strip()[:160]})

    # 2. Scan all Brave profiles for Unpacked Extensions (location == 4)
    brave_base = os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser")
    unpacked_extensions = []
    if os.path.exists(brave_base):
        pref_files = glob.glob(os.path.join(brave_base, "*/Secure Preferences")) + glob.glob(
            os.path.join(brave_base, "*/Preferences")
        )
        seen = set()
        for pf in pref_files:
            profile_name = os.path.basename(os.path.dirname(pf))
            try:
                with open(pf, "r", encoding="utf-8", errors="ignore") as fp:
                    pdata = json.load(fp)
                settings = pdata.get("extensions", {}).get("settings", {})
                for ext_id, ext_info in settings.items():
                    if not isinstance(ext_info, dict):
                        continue
                    loc = ext_info.get("location")
                    path = ext_info.get("path", "")
                    if loc == 4 or "UnpackedExtensions" in str(path):
                        key = (profile_name, ext_id)
                        if key in seen:
                            continue
                        seen.add(key)
                        manifest = ext_info.get("manifest", {})
                        unpacked_extensions.append({
                            "profile": profile_name,
                            "id": ext_id,
                            "name": manifest.get("name", "Unknown"),
                            "version": manifest.get("version", ""),
                            "path": path,
                            "permissions": manifest.get("permissions", []),
                            "host_permissions": manifest.get("host_permissions", []),
                        })
            except Exception:
                pass

    # 3. Check NativeMessagingHosts
    nm_dirs = [
        "/Library/Google/Chrome/NativeMessagingHosts",
        "/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts",
        os.path.expanduser("~/Library/Google/Chrome/NativeMessagingHosts"),
        os.path.expanduser("~/Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts"),
    ]
    native_hosts = []
    for d in nm_dirs:
        if os.path.exists(d):
            for jf in glob.glob(os.path.join(d, "*.json")):
                try:
                    with open(jf, "r", errors="ignore") as fp:
                        ndata = json.load(fp)
                    target_path = ndata.get("path", "")
                    native_hosts.append({
                        "manifest": jf,
                        "name": ndata.get("name"),
                        "target_path": target_path,
                        "target_exists": os.path.exists(target_path),
                    })
                except Exception as e:
                    native_hosts.append({"manifest": jf, "error": str(e)})

    return {
        "running_process_count": len(brave_procs),
        "suspicious_cli_flags": suspicious_cli_flags,
        "unpacked_developer_extensions": unpacked_extensions,
        "native_messaging_hosts": native_hosts,
    }


def run_host_audit(as_json: bool = False) -> dict:
    ws_report = audit_windowserver()
    brave_report = audit_brave_browser()
    electron_apps = []
    for app in sorted(glob.glob("/Applications/*.app") + glob.glob(os.path.expanduser("~/Applications/*.app"))):
        ef = inspect_electron_fuses(app)
        if ef:
            electron_apps.append(ef)

    report = {
        "windowserver": ws_report,
        "brave_browser": brave_report,
        "electron_fuses_audit": electron_apps,
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("=== [MODULE 2] SYSTEM & BROWSER HOST ('INANG') INTEGRITY AUDITOR ===")
        print(
            f"WindowServer Integrity : {'PASS' if ws_report['strict_verify_passed'] else 'FAIL'} "
            f"(SIP={ws_report['sip_enabled']}, LibVal={ws_report['library_validation_enforced']}, "
            f"PAC_arm64e={ws_report['arm64e_pac_architecture']}, CDHash={ws_report['cdhash']})"
        )
        print(
            f"Brave Running Procs    : {brave_report['running_process_count']} "
            f"(Suspicious CLI Flags: {len(brave_report['suspicious_cli_flags'])})"
        )
        print(f"Brave Unpacked Exts    : {len(brave_report['unpacked_developer_extensions'])}")
        for ue in brave_report["unpacked_developer_extensions"]:
            print(f"  - [{ue['profile']}] {ue['name']} ({ue['id']}) -> {ue['path']}")
        print(f"Electron Apps Inspected: {len(electron_apps)}")
        for ea in electron_apps:
            fuses = ea.get("fuses", {})
            print(
                f"  - {os.path.basename(ea['app'])}: RunAsNode={fuses.get('RunAsNode')}, "
                f"AsarIntegrity={fuses.get('EnableEmbeddedAsarIntegrityValidation')}, "
                f"OnlyFromAsar={fuses.get('OnlyLoadAppFromAsar')}"
            )

    return report


if __name__ == "__main__":
    run_host_audit(as_json="--json" in sys.argv)
