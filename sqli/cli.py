#!/usr/bin/env python3
"""
cli.py — SQLi Detector CLI

A detection-only, read-only SQL injection scanner.
Proves vulnerability exists WITHOUT exploiting it.

Usage:
    python cli.py --url "http://testphp.vulnweb.com/listproducts.php?cat=1" \
                  --scope "testphp.vulnweb.com"

    python cli.py --url "http://target.com/login" \
                  --method POST \
                  --data "username=admin&password=test" \
                  --scope "target.com" \
                  --techniques error boolean

LEGAL NOTICE:
    Only scan systems you own or have explicit written permission to test.
    Unauthorized scanning may violate computer crime laws.
"""

import argparse
import json
import logging
import sys
import os
from urllib.parse import urlparse, parse_qs
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from scope import Scope, OutOfScopeError
from requester import Requester, RequestConfig
from analyzer import compile_signatures
from boolean import detect_boolean
from error_based import detect_error_based
from time_based import detect_time_based
from reporter import Reporter
from config import DEFAULT_TIMEOUT, DEFAULT_DELAY, MAX_PARAM_VALUE_LENGTH
from colors import Colors

PAYLOAD_PATH = Path(__file__).parent / "payloads.json"


def load_payloads() -> dict:
    with open(PAYLOAD_PATH) as f:
        return json.load(f)


def extract_get_params(url: str) -> dict[str, str]:
    """Extract GET parameters from URL, returning {name: first_value}."""
    qs = parse_qs(urlparse(url).query, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}


def parse_post_data(raw: str) -> dict[str, str]:
    """Parse 'key=val&key2=val2' into dict."""
    result = {}
    for pair in raw.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            result[k.strip()] = v.strip()
    return result


def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║          SQLi Detector  —  Detection Only                ║
║  Proves vulnerability exists. Never exploits.            ║
║  Only use on systems you are authorized to test.         ║
╚══════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def confirm_authorization(url: str) -> bool:
    """Interactive authorization check."""
    print(f"{Colors.YELLOW}You are about to scan: {Colors.WHITE}{url}{Colors.RESET}")
    print(f"{Colors.YELLOW}   This tool sends test payloads to the target server.{Colors.RESET}")
    ans = input(f"{Colors.CYAN}   Do you have explicit authorization to test this target? [yes/no]: {Colors.RESET}")
    return ans.strip().lower() in ("yes", "y")


def run_scan(args: argparse.Namespace) -> int:
    """Main scan orchestration. Returns exit code."""

    # ── Setup logging ─────────────────────────────────────────────────────────
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=log_level,
    )

    banner()

    # ── Authorization gate ────────────────────────────────────────────────────
    if not args.yes:
        if not confirm_authorization(args.url):
            print(f"{Colors.RED}Scan aborted. Only test systems you are authorized to test.{Colors.RESET}")
            return 1

    # ── Scope check ───────────────────────────────────────────────────────────
    scope_hosts = args.scope or []
    scope = Scope(scope_hosts)
    try:
        scope.check(args.url)
    except OutOfScopeError as e:
        print(f"{Colors.RED}Scope error: {e}{Colors.RESET}")
        return 1

    # ── Load payloads ─────────────────────────────────────────────────────────
    payloads = load_payloads()
    compile_signatures(payloads["error_based"]["signatures"])

    # ── Build requester ───────────────────────────────────────────────────────
    cfg = RequestConfig(
        timeout=args.timeout,
        delay=args.delay,
        headers=dict(h.split(":", 1) for h in args.headers) if args.headers else {},
        cookies=dict(c.split("=", 1) for c in args.cookies) if args.cookies else {},
        verify_ssl=not args.no_ssl_verify,
    )
    requester = Requester(cfg)
    reporter  = Reporter(args.url)

    # ── Identify parameters to test ───────────────────────────────────────────
    method = args.method.upper()
    post_data = {}

    if method == "GET":
        params = extract_get_params(args.url)
        if not params:
            print(f"{Colors.RED}No GET parameters found in URL. "
                  f"Use --data for POST or add ?param=value to the URL.{Colors.RESET}")
            return 1
    else:
        if not args.data:
            print(f"{Colors.RED}POST method requires --data 'param=value&...'{Colors.RESET}")
            return 1
        post_data = parse_post_data(args.data)
        params = post_data

    if not params:
        print(f"{Colors.RED}No parameters found to test.{Colors.RESET}")
        return 1

    techniques = args.techniques or ["error", "boolean", "time"]
    print(f"{Colors.CYAN}Testing {len(params)} parameter(s): {Colors.WHITE}{list(params.keys())}{Colors.RESET}")
    print(f"{Colors.CYAN}   Techniques: {Colors.WHITE}{', '.join(techniques)}{Colors.RESET}\n")

    # ── Per-parameter scan ────────────────────────────────────────────────────
    for param, original_value in params.items():

        # Skip huge values — unlikely to be injectable and wastes time
        if len(original_value) > MAX_PARAM_VALUE_LENGTH:
            print(f"{Colors.YELLOW}   Skipping param '{param}' (value too long){Colors.RESET}")
            continue

        reporter.mark_tested(param)
        print(f"{Colors.BLUE}   Testing param: '{param}' (value='{original_value[:30]}'){Colors.RESET}")
        
        param_vulnerable = False

        # ── Error-based ───────────────────────────────────────────────────────
        if "error" in techniques:
            finding = detect_error_based(
                url=args.url,
                param=param,
                original_value=original_value,
                probes=payloads["error_based"]["probes"],
                requester=requester,
                method=method,
                post_data=post_data or None,
            )
            if finding and finding.is_vulnerable:
                reporter.add_finding(finding, "error_based")
                print(f"{Colors.RED}{Colors.BOLD}   [ERROR-BASED] FOUND — {Colors.RESET}{Colors.RED}{finding.evidence}{Colors.RESET}")
                param_vulnerable = True

        # ── Boolean-based ─────────────────────────────────────────────────────
        if "boolean" in techniques:
            finding = detect_boolean(
                url=args.url,
                param=param,
                original_value=original_value,
                true_payloads=payloads["boolean"]["true_conditions"],
                false_payloads=payloads["boolean"]["false_conditions"],
                requester=requester,
                method=method,
                post_data=post_data or None,
            )
            if finding and finding.is_vulnerable:
                reporter.add_finding(finding, "boolean")
                print(f"{Colors.RED}{Colors.BOLD}   [BOOLEAN]     FOUND — {Colors.RESET}{Colors.RED}{finding.evidence}{Colors.RESET}")
                param_vulnerable = True

        # ── Time-based ────────────────────────────────────────────────────────
        if "time" in techniques:
            finding = detect_time_based(
                url=args.url,
                param=param,
                original_value=original_value,
                probes_by_dbms=payloads["time_based"]["probes"],
                requester=requester,
                method=method,
                post_data=post_data or None,
            )
            if finding and finding.is_vulnerable:
                reporter.add_finding(finding, "time_based")
                print(f"{Colors.RED}{Colors.BOLD}   [TIME-BASED]  FOUND — {Colors.RESET}{Colors.RED}{finding.evidence}{Colors.RESET}")
                param_vulnerable = True

        if not param_vulnerable:
            print(f"{Colors.GREEN}   param '{param}': no injection detected{Colors.RESET}")

    # ── Output ────────────────────────────────────────────────────────────────
    reporter.print_summary()

    if args.output:
        path = reporter.save_json(args.output)
    else:
        path = reporter.save_json()
    print(f"{Colors.CYAN}Report saved to: {Colors.WHITE}{path}{Colors.RESET}\n")

    return 0 if reporter.build_result().vuln_count == 0 else 2


def main():
    parser = argparse.ArgumentParser(
        description="SQLi Detector — Detection-only SQL injection scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--url",       required=True,  help="Target URL")
    parser.add_argument("--method",    default="GET",  choices=["GET","POST"],
                        help="HTTP method (default: GET)")
    parser.add_argument("--data",      default=None,
                        help="POST body: 'param=value&param2=value2'")
    parser.add_argument("--scope",     nargs="+", default=[],
                        help="Allowed hosts/patterns (e.g. example.com *.staging.example.com)")
    parser.add_argument("--techniques", nargs="+",
                        choices=["error","boolean","time"],
                        default=["error","boolean","time"],
                        help="Detection techniques to use (default: all)")
    parser.add_argument("--headers",   nargs="+",
                        help="Custom headers: 'X-Header: value'")
    parser.add_argument("--cookies",   nargs="+",
                        help="Cookies: 'name=value'")
    parser.add_argument("--timeout",   type=float, default=DEFAULT_TIMEOUT,
                        help=f"Request timeout seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--delay",     type=float, default=DEFAULT_DELAY,
                        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("--output",    default=None,
                        help="Output JSON report path")
    parser.add_argument("--no-ssl-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip authorization confirmation prompt")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose debug logging")

    args = parser.parse_args()
    sys.exit(run_scan(args))


if __name__ == "__main__":
    main()
