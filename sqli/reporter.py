"""
reporter.py — Output findings in structured formats.
"""

import json
import os
import datetime
from dataclasses import asdict, dataclass
from typing import Any
from pathlib import Path

from config import REPORT_DIR
from colors import Colors


@dataclass
class ScanResult:
    target_url: str
    scan_start: str
    scan_end: str
    total_params_tested: int
    findings: list[dict]

    @property
    def vuln_count(self) -> int:
        return len(self.findings)


class Reporter:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.findings: list[dict] = []
        self.params_tested: set[str] = set()
        self.start_time = datetime.datetime.utcnow().isoformat()

    def add_finding(self, finding: Any, technique: str) -> None:
        """Register a detection finding."""
        d = {
            "technique": technique,
            "param": finding.param,
            "method": finding.method,
            "payload": finding.payload if hasattr(finding, "payload") else "",
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "is_vulnerable": finding.is_vulnerable,
        }
        # Attach technique-specific fields
        if technique == "boolean":
            d["true_payload"]  = finding.true_payload
            d["false_payload"] = finding.false_payload
        elif technique == "error_based":
            d["dbms"] = finding.dbms
            d["matched_pattern"] = finding.matched_pattern
        elif technique == "time_based":
            d["dbms_hint"]        = finding.dbms_hint
            d["baseline_mean_s"]  = finding.baseline_mean
            d["observed_elapsed_s"] = finding.observed_elapsed

        self.findings.append(d)

    def mark_tested(self, param: str) -> None:
        self.params_tested.add(param)

    def build_result(self) -> ScanResult:
        return ScanResult(
            target_url=self.target_url,
            scan_start=self.start_time,
            scan_end=datetime.datetime.utcnow().isoformat(),
            total_params_tested=len(self.params_tested),
            findings=self.findings,
        )

    def save_json(self, path: str = None) -> str:
        result = self.build_result()
        os.makedirs(REPORT_DIR, exist_ok=True)
        if not path:
            ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(REPORT_DIR, f"scan_{ts}.json")
        with open(path, "w") as f:
            json.dump(asdict(result), f, indent=2)
        return path

    def print_summary(self) -> None:
        result = self.build_result()
        vulns = [f for f in result.findings if f["is_vulnerable"]]

        c = Colors
        print(f"\n{c.BLUE}" + "═" * 60)
        print(f"  {c.BOLD}SQLi Detector — Scan Summary{c.BLUE}")
        print("═" * 60 + f"{c.RESET}")
        print(f"  Target    : {c.WHITE}{result.target_url}{c.RESET}")
        print(f"  Params    : {c.CYAN}{result.total_params_tested}{c.RESET} tested")
        
        find_color = c.RED if len(vulns) > 0 else c.GREEN
        print(f"  Findings  : {find_color}{len(vulns)} confirmed{c.RESET}, "
              f"{c.YELLOW}{len(result.findings) - len(vulns)} low-confidence{c.RESET}")
        print(f"{c.BLUE}" + "═" * 60 + f"{c.RESET}")

        if not vulns:
            print(f"{c.GREEN}  No confirmed SQL injection found.{c.RESET}\n")
            return

        print(f"{c.RED}{c.BOLD}  CONFIRMED FINDINGS ({len(vulns)}){c.RESET}\n")
        for i, f in enumerate(vulns, 1):
            print(f"  {c.BOLD}[{i}]{c.RESET} Param     : {c.GREEN}{f['param']}{c.RESET} ({f['method']})")
            print(f"      Technique  : {c.MAGENTA}{f['technique']}{c.RESET}")
            print(f"      Confidence : {c.CYAN}{f['confidence']:.0%}{c.RESET}")
            
            if f.get('payload'):
                print(f"      Payload    : {c.YELLOW}{f['payload']}{c.RESET}")
            if f.get('true_payload') and f.get('false_payload'):
                print(f"      True Payld : {c.YELLOW}{f['true_payload']}{c.RESET}")
                print(f"      False Payld: {c.YELLOW}{f['false_payload']}{c.RESET}")
                
            print(f"      Evidence   : {c.RED}{f['evidence']}{c.RESET}")
            if f["technique"] == "error_based":
                print(f"      DBMS       : {c.WHITE}{f.get('dbms', '?')}{c.RESET}")
            if f["technique"] == "time_based":
                print(f"      DBMS hint  : {c.WHITE}{f.get('dbms_hint', '?')}{c.RESET}")
                print(f"      Baseline   : {c.CYAN}{f.get('baseline_mean_s', '?')}s{c.RESET}  "
                      f"Observed: {c.CYAN}{f.get('observed_elapsed_s', '?')}s{c.RESET}")
            print()

        print(f"{c.GREEN}  Recommendation: Report findings to the application owner.")
        print(f"     Do NOT attempt to exploit these vulnerabilities.{c.RESET}\n")
