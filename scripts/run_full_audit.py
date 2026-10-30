#!/usr/bin/env python3
"""
Unified Orchestrator: macOS Security & Memory Forensics Suite (run_full_audit.py)
Executes all 5 forensic modules and outputs a consolidated terminal or JSON report.
"""

import sys
import json
from datetime import datetime, timezone

from memory_forensic_scanner import run_memory_audit
from host_integrity_auditor import run_host_audit
from app_bundle_auditor import run_bundle_audit
from network_c2_hunter import run_network_audit
from anti_analysis_detector import run_anti_analysis_audit


def main():
    as_json = "--json" in sys.argv
    if not as_json:
        print("=====================================================================")
        print("   macOS DEEP SECURITY & MEMORY FORENSIC SUITE (READ-ONLY AUDIT)     ")
        print(f"   Timestamp: {datetime.now(timezone.utc).isoformat()}")
        print("=====================================================================\n")

    m1 = run_memory_audit(as_json=False) if not as_json else None
    if not as_json:
        print()
    m2 = run_host_audit(as_json=False) if not as_json else None
    if not as_json:
        print()
    m3 = run_bundle_audit(as_json=False) if not as_json else None
    if not as_json:
        print()
    m4 = run_network_audit(as_json=False) if not as_json else None
    if not as_json:
        print()
    m5 = run_anti_analysis_audit(as_json=False) if not as_json else None

    if as_json:
        combined = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "memory_forensics": run_memory_audit(as_json=False),
            "host_integrity": run_host_audit(as_json=False),
            "app_bundles": run_bundle_audit(as_json=False),
            "network_c2": run_network_audit(as_json=False),
            "anti_analysis": run_anti_analysis_audit(as_json=False),
        }
        print(json.dumps(combined, indent=2))
    else:
        print("\n=====================================================================")
        print("   AUDIT COMPLETE")
        print("=====================================================================")


if __name__ == "__main__":
    main()
