#!/usr/bin/env python3
"""
Module 4: Deep Network Socket, QUIC & PCB Graph C2 Hunter (network_c2_hunter.py)
100% Read-Only diagnostic tool for macOS.

Features:
- Uses `netstat -anvl -p tcp/udp` (with `-l` to prevent 17-character IPv6 truncation)
  to inspect per-socket `rxbytes`, `txbytes`, and `process:pid` without requiring root.
- Detects active UDP/443 QUIC sockets and flags asymmetric data exfiltration candidates
  (`txbytes > 1 MB` and `txbytes / rxbytes > 2.0`).
- Maps `utun0..N` VPN interfaces without root via `netstat -anv -f systm` (`com.apple.net.utun_control`).
- Verifies that `WindowServer` and core UI daemons have 0 external TCP/UDP sockets.
"""

import re
import sys
import json
import subprocess


def parse_netstat_inet(proto: str) -> list:
    res = subprocess.run(
        ["netstat", "-anvl", "-p", proto],
        capture_output=True,
        text=True,
    )
    sockets = []
    for line in res.stdout.splitlines():
        if not line.startswith(("tcp", "udp")):
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        p_type = parts[0]
        local_addr = parts[3]
        foreign_addr = parts[4]

        if p_type.startswith("tcp"):
            if len(parts) < 11:
                continue
            state = parts[5]
            try:
                rxbytes = int(parts[6])
                txbytes = int(parts[7])
            except ValueError:
                continue
            proc_pid = parts[10]
        else:
            state = "UDP_ACTIVE" if foreign_addr != "*.*" else "UDP_LISTEN"
            try:
                rxbytes = int(parts[5])
                txbytes = int(parts[6])
            except ValueError:
                continue
            proc_pid = parts[9] if len(parts) > 9 else "unknown:0"

        if ":" in proc_pid:
            proc_name, pid_str = proc_pid.rsplit(":", 1)
        else:
            proc_name, pid_str = proc_pid, "0"

        is_loopback = local_addr.startswith(("127.0.0.1.", "::1.", "fe80:")) and foreign_addr.startswith(
            ("127.0.0.1.", "::1.", "fe80:", "*.*")
        )
        exfil_flag = (
            not is_loopback
            and foreign_addr != "*.*"
            and txbytes > 1_000_000
            and (txbytes / max(rxbytes, 1)) > 2.0
        )

        sockets.append({
            "proto": p_type,
            "local": local_addr,
            "foreign": foreign_addr,
            "state": state,
            "rxbytes": rxbytes,
            "txbytes": txbytes,
            "process": proc_name,
            "pid": int(pid_str) if pid_str.isdigit() else 0,
            "is_loopback": is_loopback,
            "high_tx_exfil_candidate": exfil_flag,
        })
    return sockets


def map_utun_owners() -> list:
    res = subprocess.run(
        ["netstat", "-anv", "-f", "systm"],
        capture_output=True,
        text=True,
    )
    utuns = []
    for line in res.stdout.splitlines():
        if "com.apple.net.utun_control" not in line:
            continue
        parts = line.split()
        # Locate process:pid and unit number
        proc_pid = next((p for p in parts if ":" in p and not p.startswith("0x")), "")
        try:
            ctl_idx = parts.index("com.apple.net.utun_control")
            unit_num = int(parts[ctl_idx - 1])
            if_name = f"utun{unit_num - 1}"
        except Exception:
            if_name = "utun?"
        utuns.append({"interface": if_name, "owner": proc_pid})
    return utuns


def check_arp_spoofing() -> dict:
    res = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    mac_to_ips = {}
    for line in res.stdout.splitlines():
        m = re.search(r"\(([\d\.]+)\)\s+at\s+([0-9a-f:]+)", line)
        if m:
            ip, mac = m.groups()
            if mac != "ff:ff:ff:ff:ff:ff":
                mac_to_ips.setdefault(mac, []).append(ip)
    duplicates = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    return {"arp_entries": mac_to_ips, "duplicate_mac_alerts": duplicates}


def run_network_audit(as_json: bool = False) -> dict:
    tcp_socks = parse_netstat_inet("tcp")
    udp_socks = parse_netstat_inet("udp")
    all_socks = tcp_socks + udp_socks

    ui_daemons = ("WindowServer", "loginwindow", "Dock", "SystemUIServer", "Finder")
    ui_daemon_Violations = [
        s for s in all_socks if s["process"] in ui_daemons and s["foreign"] != "*.*"
    ]

    external_active = [
        s
        for s in all_socks
        if not s["is_loopback"]
        and s["foreign"] != "*.*"
        and s["state"] in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT", "UDP_ACTIVE")
    ]
    exfil_candidates = [s for s in external_active if s["high_tx_exfil_candidate"]]
    utun_map = map_utun_owners()
    arp_report = check_arp_spoofing()

    report = {
        "total_tcp_sockets": len(tcp_socks),
        "total_udp_sockets": len(udp_socks),
        "external_active_connections_count": len(external_active),
        "ui_daemon_network_violations": ui_daemon_Violations,
        "high_tx_exfil_candidates": exfil_candidates,
        "utun_interface_owners": utun_map,
        "arp_integrity": arp_report,
        "external_active_connections": external_active,
    }

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("=== [MODULE 4] DEEP NETWORK SOCKET, QUIC & PCB C2 HUNTER ===")
        print(f"Total Kernel Sockets Inspected : {len(all_socks)} (TCP: {len(tcp_socks)}, UDP: {len(udp_socks)})")
        print(f"Active External Connections    : {len(external_active)}")
        print(f"WindowServer/UI Daemon Sockets : {len(ui_daemon_Violations)} (Expected: 0)")
        print(f"High-TX Exfiltration Alerts    : {len(exfil_candidates)}")
        print(f"ARP Spoofing Duplicate MACs    : {len(arp_report['duplicate_mac_alerts'])}")
        print(f"Virtual utun Tunnel Owners     : {utun_map}\n")
        for s in external_active[:20]:
            flag = " [HIGH-TX]" if s["high_tx_exfil_candidate"] else ""
            print(
                f"  {s['proto']:4} {s['state']:12} {s['process']}:{s['pid']} -> "
                f"{s['foreign']} (rx={s['rxbytes']} B, tx={s['txbytes']} B){flag}"
            )

    return report


if __name__ == "__main__":
    run_network_audit(as_json="--json" in sys.argv)
