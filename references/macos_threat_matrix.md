# macOS Threat Matrix & Forensic Reference (`arm64e` / Apple Silicon)

## 1. Memory Forensics & Hardware Enforcement on Apple Silicon

### 1.1 Write XOR Execute (`W^X`) & APRR (`MAP_JIT`)
On Apple Silicon (`arm64` / `arm64e`), the XNU kernel and Apple Mobile File Integrity (AMFI) strictly enforce `W^X`:
- Standard `mach_vm_allocate` / `mach_vm_protect` calls requesting simultaneous `VM_PROT_WRITE | VM_PROT_EXECUTE` (`rwx`) are denied by the kernel unless the binary possesses explicit entitlements:
  - `com.apple.security.cs.allow-jit`: Allows a single `mmap(..., MAP_JIT, ...)` region tagged by XNU as **`Memory Tag 255`** (`VM_MAKE_TAG(255)`). Write vs. Execute permissions are toggled per-thread in hardware via the ARM64 **Access Permission Register (`APRR`)** (`pthread_jit_write_protect_np`).
  - `com.apple.security.cs.allow-unsigned-executable-memory` or `com.apple.security.cs.disable-executable-page-protection`.

### 1.2 Distinguishing Benign V8 / Objective-C Regions from Injected Shellcode in `vmmap -wide`
| `vmmap` Region Type | Current/Max Prot | Backing / Detail | Forensic Classification |
| :--- | :--- | :--- | :--- |
| `__TEXT` | `r-x/r-x` | Signed `.app` / `.dylib` / `.framework` on disk | **Benign** (Verify `codesign` of backing file) |
| `Memory Tag 255` | `rwx/rwx` | Anonymous (`SM=PRV` / `SM=ZER`) | **Benign ONLY IF** process has `cs.allow-jit` (e.g. `Renderer`, `Electron`, `node`). **CRITICAL ALERT** if in `Brave Main`, `NetworkService`, `GPU`, or system daemons. |
| `mapped file` (inside `150000000-160000000`) | `r-x/rwx` | `Brave Browser Framework` or `Electron Framework` (`SM=COW`) | **Benign V8 Embedded Builtins Remapping** (Placed in the middle of the V8 JIT CodeRange so ARM64 `BL` ±128MB instructions reach builtins directly). |
| `mapped file` (`48K`) | `r-x/rwx` | `/usr/lib/libobjc-trampolines.dylib` (`SM=COW`) | **Benign Objective-C Block Trampolines** (`imp_implementationWithBlock`). |
| `Memory Tag 253` | `---/rwx` or `rw-/rwx` | Chromium `PartitionAlloc` heap | **Benign** (`current_prot` has no `x`; never confuse `/rwx` max_prot with `rwx/` current_prot). |
| `VM_ALLOCATE` / `MALLOC*` | `r-x/*` or `rwx/*` | Anonymous (no Mach-O file backing) | **CRITICAL MALWARE IOC** (Reflective dylib loader / `mach_vm_protect` shellcode injection). |

---

## 2. Electron Fuse Wire Binary Specification

Electron embeds a compile-time fuse wire inside `Electron Framework.framework/Electron Framework` marked by the 32-byte ASCII sentinel:
```text
dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX
```
Immediately following the sentinel:
- **Byte 0**: `fuse_version` (typically `0x01`)
- **Byte 1**: `fuse_length` (number of fuse bytes, e.g., `6` to `8`)
- **Byte `2 + i`** (ASCII `'0'` = `0x30` Disabled, `'1'` = `0x31` Enabled, `'r'` = `0x72` Removed):
  - Index `0`: `RunAsNode` (`ELECTRON_RUN_AS_NODE` — if `1`, attacker can run arbitrary JS under the app's signed identity and inherit its TCC permissions!)
  - Index `1`: `EnableCookieEncryption`
  - Index `2`: `EnableNodeOptionsEnvironmentVariable` (`NODE_OPTIONS` injection)
  - Index `3`: `EnableNodeCliInspectArguments` (`--inspect` / `--inspect-brk` debugger attach)
  - Index `4`: `EnableEmbeddedAsarIntegrityValidation` (validates `app.asar` hash against `Info.plist`)
  - Index `5`: `OnlyLoadAppFromAsar` (prevents hijacking via unpacked `Contents/Resources/app/` folder)

---

## 3. Kernel Process Flags (`<sys/proc.h>`)

From XNU `bsd/sys/proc.h`, the hexadecimal `flags` column in `ps -axo pid,ppid,uid,flags,comm`:
- `0x00000004` (`P_LP64`): Process is 64-bit.
- `0x00000100` (`P_SUGID`): Process had setuid/setgid privileges since last exec.
- `0x00000800` (`P_TRACED`): Process is being traced OR called `ptrace(PT_DENY_ATTACH, 0, 0, 0)` to block debuggers/memory scanners.
- `0x00001000` (`P_DISABLE_ASLR`): Process was spawned with `_POSIX_SPAWN_DISABLE_ASLR`.
- `0x00002000` (`P_WEXIT`): Process is exiting / zombie (`<defunct>`).
- `0x00004000` (`P_EXEC`): Process called `exec`.
