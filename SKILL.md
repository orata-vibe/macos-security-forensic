---
name: macos-security-forensic
description: >-
  Deep macOS security and memory forensics suite for Apple Silicon (arm64e) and Intel Macs.
  Audits virtual memory regions (vmmap RWX/unbacked code & MAP_JIT validation), host process
  ("inang") integrity (WindowServer, Chromium/Brave, Electron Fuses wire inspection), all active
  and passive .app bundles (CFBundleExecutable wrapper checks, strict codesign CDHash, LC_RPATH,
  and TCC.db piggybacking correlation), kernel sockets (netstat -anvl TCP/UDP/QUIC, rx/tx exfiltration
  ratios, rootless utun & AF_UNIX PCB graph resolution), and anti-analysis evasion (P_TRACED 0x800,
  P_DISABLE_ASLR, DYLD_INSERT_LIBRARIES, ELECTRON_RUN_AS_NODE, and 15+ stealth persistence vectors).
---

# macOS Security & Memory Forensics Skill (`macos-security-forensic`)

This skill provides a zero-dependency, 100% read-only forensic auditing framework for macOS (optimized for Apple Silicon `arm64e` and macOS 14–26+). It is designed to detect sophisticated malware, memory-only shellcode, host process piggybacking (*inang*), Chromium/Electron hijacking, C2 traffic over QUIC/DoH, and anti-debugging (`PT_DENY_ATTACH`) techniques without triggering false positives on legitimate system or browser architectures.

## Directory Structure

```text
macos-security-forensic/
├── SKILL.md                              # Main skill instructions & multi-agent playbook
├── README.md                             # Public repository documentation & CLI quickstart
├── references/
│   └── macos_threat_matrix.md            # Apple Silicon PAC/APRR, Electron Fuses & MITRE ATT&CK matrix
└── scripts/
    ├── run_full_audit.py                 # Unified orchestrator running all 5 forensic modules
    ├── memory_forensic_scanner.py        # Module 1: RAM & vmmap RWX / unbacked code / dylib auditor
    ├── host_integrity_auditor.py         # Module 2: WindowServer, Chromium/Brave & Electron Fuse auditor
    ├── app_bundle_auditor.py             # Module 3: Active & passive .app bundle & TCC.db correlation scanner
    ├── network_c2_hunter.py              # Module 4: Kernel TCP/UDP/QUIC socket, utun & AF_UNIX PCB hunter
    └── anti_analysis_detector.py         # Module 5: Kernel proc flags (P_TRACED), env vars & stealth persistence
```

---

## 1. Quick Execution (Single Command Full Audit)

To execute all 5 forensic modules sequentially and generate a structured terminal + JSON report:

```bash
python3 ./scripts/run_full_audit.py
```

Or run individual forensic modules on demand:

1. **Memory & RAM Fingerprint Audit (`vmmap -wide` + `lsof`):**
   ```bash
   python3 ./scripts/memory_forensic_scanner.py
   ```
2. **System & Browser Host ("Inang") Integrity Audit (`WindowServer`, `Brave`, `Electron Fuses`):**
   ```bash
   python3 ./scripts/host_integrity_auditor.py
   ```
3. **All Active & Passive Application Bundle Audit (`/Applications`, `~/Applications`, `TCC.db`):**
   ```bash
   python3 ./scripts/app_bundle_auditor.py
   ```
4. **Deep Network Socket, QUIC & PCB Graph C2 Hunter (`netstat -anvl`):**
   ```bash
   python3 ./scripts/network_c2_hunter.py
   ```
5. **Anti-Analysis, Kernel Flags (`<sys/proc.h>`) & Stealth Persistence Detector:**
   ```bash
   python3 ./scripts/anti_analysis_detector.py
   ```

---

## 2. Multi-Agent Forensic Team Playbook

For high-assurance investigations, dispatch **5 parallel subagents** (each assigned to one module above) and consolidate their telemetry:

1. **Subagent 1 — Memory & RAM Fingerprint Investigator (`memory_forensic_scanner.py`):**
   - Parses both `==== Non-writable regions` and `==== Writable regions` of `vmmap -wide <pid>`.
   - Splits `cur_prot/max_prot` so non-executable guard/heap pages (`rw-/rwx` in `Memory Tag 253` `PartitionAlloc`) are never misclassified as `rwx`.
   - Validates `Memory Tag 255` (`MAP_JIT` APRR-protected V8 JIT pages) and V8 Embedded Builtins remapping (`r-x/rwx` pointing to `Brave Browser Framework` / `Electron Framework`) strictly against processes holding `com.apple.security.cs.allow-jit`.
2. **Subagent 2 — System & Browser Host Integrity Auditor (`host_integrity_auditor.py`):**
   - Audits `WindowServer` (`flags=0x2000(library-validation)`, `arm64e` PAC `__TEXT,__auth_stubs`, SIP status).
   - Inspects the binary Electron Fuse wire (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`) for `RunAsNode`, `EnableNodeOptionsEnvironmentVariable`, `EnableNodeCliInspectArguments`, `EnableEmbeddedAsarIntegrityValidation`, and `OnlyLoadAppFromAsar`.
   - Scans all Chromium/Brave profiles (`Default`, `Profile *`) for `UnpackedExtensions` (`location == 4`), dangerous CLI flags (`--remote-debugging-port`, `--load-extension`, `--no-sandbox`), `NativeMessagingHosts`, and `Service Worker` origins.
3. **Subagent 3 — Active & Passive Application Bundle Auditor (`app_bundle_auditor.py`):**
   - Audits every `.app` bundle on disk (whether running in RAM or dormant on disk).
   - Verifies `CFBundleExecutable` in `Contents/Info.plist` is a genuine Mach-O binary (not a shell/Python wrapper script with a renamed `.orig` binary).
   - Correlates weak Hardened Runtime entitlements (`cs.disable-library-validation`, `cs.allow-dyld-environment-variables`) against active grants in `~/Library/Application Support/com.apple.TCC/TCC.db`.
4. **Subagent 4 — Network Socket & C2 Traffic Hunter (`network_c2_hunter.py`):**
   - Uses `netstat -anvl` (with `-l` to prevent 17-char IPv6 truncation) to capture `rxbytes`, `txbytes`, and `process:pid` across TCP and UDP/QUIC (`:443`).
   - Flags data exfiltration candidates (`txbytes > 1 MB` and `txbytes / rxbytes > 2.0`).
   - Maps `utun0..N` VPN interfaces without root via `netstat -anv -f systm` (`com.apple.net.utun_control`) and resolves anonymous `AF_UNIX` socket connections via kernel PCB pointer graphs.
5. **Subagent 5 — Anti-Analysis & Stealth Persistence Specialist (`anti_analysis_detector.py`):**
   - Decodes hexadecimal kernel process flags (`<sys/proc.h>`) to detect `P_TRACED (0x00000800)` (`PT_DENY_ATTACH`), `P_DISABLE_ASLR (0x00001000)`, and `P_SUGID (0x00000100)`.
   - Audits `ps eww -ax` for `DYLD_INSERT_LIBRARIES`, `ELECTRON_RUN_AS_NODE`, `NODE_OPTIONS`, and `SSLKEYLOGFILE`.
   - Audits 15+ stealth persistence directories (`SecurityAgentPlugins`, `Audio/Plug-Ins/HAL`, `Spotlight`, `QuickLook`, `DirectoryServices/PlugIns`, `ScriptingAdditions`, `Folder Actions`, `zshenv`).

---

## 3. Reference Documentation

Read [references/macos_threat_matrix.md](./references/macos_threat_matrix.md) when interpreting low-level hardware/kernel indicators (PAC, APRR `MAP_JIT`, Electron fuse byte offsets, or XNU `<sys/proc.h>` bitmasks).
