# macOS Security & Memory Forensics Suite (`macos-security-forensic`)

A zero-dependency, 100% read-only forensic auditing toolkit and AI Agent Skill for macOS (Apple Silicon `arm64e` & Intel). Designed to hunt for **process injection**, **memory-only shellcode (`vmmap`)**, **host process piggybacking (*inang*)**, **Chromium/Brave & Electron tampering**, **QUIC/DoH C2 channels**, and **anti-analysis evasion (`PT_DENY_ATTACH`)**.

---

## Key Capabilities

1. **Memory & RAM Fingerprint Scanner (`scripts/memory_forensic_scanner.py`)**
   - Parses both `==== Non-writable regions` and `==== Writable regions` of `vmmap -wide`.
   - Accurately separates `current_prot` from `max_prot` (`cur_prot/max_prot`) to eliminate false positives on `PartitionAlloc` (`Memory Tag 253`) and `STACK GUARD` (`---/rwx` or `rw-/rwx`).
   - Validates Apple Silicon `MAP_JIT` (`Memory Tag 255`) and V8 Embedded Builtins remapping (`r-x/rwx`) against process entitlements (`com.apple.security.cs.allow-jit`), immediately flagging any `rwx` or unbacked `r-x` region in non-JIT processes (`Brave Browser` main, `NetworkService`, `GPU`, `Finder`, etc.).
   - Audits all non-system `.dylib` and Mach-O files mapped into process memory via `lsof` + `codesign`.

2. **System & Browser Host ("Inang") Integrity Auditor (`scripts/host_integrity_auditor.py`)**
   - Verifies `WindowServer` and core macOS daemons for SIP protection, `flags=0x2000(library-validation)`, and Apple Silicon `arm64e` Pointer Authentication (`__TEXT,__auth_stubs`).
   - Inspects the binary **Electron Fuse wire (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`)** inside `Electron Framework` to check `RunAsNode`, `nodeOptions`, `nodeCliInspect`, `EmbeddedAsarIntegrityValidation`, and `OnlyLoadAppFromAsar`.
   - Audits all Chromium/Brave profiles (`Default`, `Profile 1..N`) for Developer Mode `UnpackedExtensions` (`location == 4`), dangerous CLI flags (`--remote-debugging-port`, `--load-extension`, `--no-sandbox`), `NativeMessagingHosts`, and `Service Worker` origins.

3. **Active & Passive Application Bundle Auditor (`scripts/app_bundle_auditor.py`)**
   - Scans every `.app` bundle across `/Applications`, `/Applications/Utilities`, `~/Applications`, and `/Library/Application Support` (both active in RAM and dormant on disk).
   - Detects `CFBundleExecutable` wrapper script hijacking (`Contents/MacOS/`), suspicious `LC_RPATH` entries (`otool -l`), and ad-hoc re-signed/patched dylibs.
   - Cross-references weak Hardened Runtime entitlements (`disable-library-validation`, `allow-dyld-environment-variables`) with active user permissions in `~/Library/Application Support/com.apple.TCC/TCC.db`.

4. **Network Socket, QUIC & PCB Graph C2 Hunter (`scripts/network_c2_hunter.py`)**
   - Uses `netstat -anvl` (preventing 17-character IPv6 truncation) to capture per-socket `rxbytes`, `txbytes`, and `process:pid` across TCP and UDP/QUIC (`:443`) without requiring `sudo`.
   - Detects asymmetric data exfiltration (`txbytes > 1 MB` and `txbytes / rxbytes > 2.0`).
   - Maps `utun0..N` VPN interfaces without root via `netstat -anv -f systm` (`com.apple.net.utun_control`) and resolves anonymous `AF_UNIX` IPC sockets via kernel PCB pointer graphs.

5. **Anti-Analysis & Stealth Persistence Detector (`scripts/anti_analysis_detector.py`)**
   - Decodes hexadecimal `<sys/proc.h>` kernel flags from `ps -axo` to detect `P_TRACED (0x00000800)` (`PT_DENY_ATTACH`), `P_DISABLE_ASLR (0x00001000)`, `P_SUGID (0x00000100)`, and `P_WEXIT (0x00002000)`.
   - Scans process environments (`ps eww -ax`) for `DYLD_INSERT_LIBRARIES`, `ELECTRON_RUN_AS_NODE`, `NODE_OPTIONS`, and `SSLKEYLOGFILE`.
   - Audits 15+ stealth persistence vectors (`SecurityAgentPlugins`, `Audio/Plug-Ins/HAL`, `Spotlight`, `QuickLook`, `DirectoryServices/PlugIns`, `ScriptingAdditions`, `Folder Actions`, `zshenv`, and `LaunchAgents`/`LaunchDaemons`).

---

## Usage

### 1. Run Standalone via Terminal (0 AI Context Tokens)

Clone and run directly without installing into your AI agent's skill folder:

```bash
git clone https://github.com/orata-vibe/macos-security-forensic.git
cd macos-security-forensic

# Run the complete 5-module forensic audit
python3 scripts/run_full_audit.py

# Or run a specific module
python3 scripts/memory_forensic_scanner.py
python3 scripts/host_integrity_auditor.py
python3 scripts/app_bundle_auditor.py
python3 scripts/network_c2_hunter.py
python3 scripts/anti_analysis_detector.py
```

### 2. Install as an Agent Skill (On-Demand)

When you want your AI coding assistant (Antigravity / Gemini CLI / Claude Code) to use this skill:

```bash
git clone https://github.com/orata-vibe/macos-security-forensic.git ~/.gemini/skills/macos-security-forensic
```

To remove it from the active skill index when finished (saving 100% of prompt index tokens):

```bash
rm -rf ~/.gemini/skills/macos-security-forensic
```
