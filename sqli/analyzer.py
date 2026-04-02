"""
analyzer.py — Response analysis and differential comparison.

Compares baseline vs injected responses to detect anomalies
without ever needing to execute destructive SQL.
"""

import re
import logging
from difflib import SequenceMatcher
from dataclasses import dataclass
from typing import Optional

from config import BOOLEAN_DIFF_THRESHOLD

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    similarity: float           # 0.0 to 1.0 (1.0 = identical)
    length_ratio: float         # injected_len / baseline_len
    length_diff_pct: float      # absolute % difference in length
    status_changed: bool
    significant: bool           # True if diff exceeds threshold


def diff_responses(baseline_body: str, baseline_status: int,
                   injected_body: str, injected_status: int,
                   threshold: float = BOOLEAN_DIFF_THRESHOLD) -> DiffResult:
    """
    Compare two responses. Returns DiffResult indicating how different they are.
    A 'significant' diff suggests the injection altered application behavior.
    """
    b_len = len(baseline_body) or 1
    i_len = len(injected_body) or 1

    length_ratio = i_len / b_len
    length_diff_pct = abs(b_len - i_len) / b_len

    # SequenceMatcher gives a rough structural similarity score
    # We truncate to 5000 chars each side for performance
    similarity = SequenceMatcher(
        None,
        baseline_body[:5000],
        injected_body[:5000],
        autojunk=False,
    ).ratio()

    status_changed = baseline_status != injected_status

    significant = (
        length_diff_pct > threshold
        or similarity < (1 - threshold)
        or status_changed
    )

    return DiffResult(
        similarity=round(similarity, 4),
        length_ratio=round(length_ratio, 4),
        length_diff_pct=round(length_diff_pct, 4),
        status_changed=status_changed,
        significant=significant,
    )


# ── Error signature matching ──────────────────────────────────────────────────

_COMPILED_SIGNATURES: dict[str, list[re.Pattern]] = {}


def compile_signatures(signatures: dict[str, list[str]]) -> None:
    """Pre-compile all DB error signatures for fast matching."""
    global _COMPILED_SIGNATURES
    _COMPILED_SIGNATURES = {
        dbms: [re.compile(sig, re.IGNORECASE) for sig in sigs]
        for dbms, sigs in signatures.items()
    }


def find_error_signature(body: str) -> Optional[tuple[str, str]]:
    """
    Search response body for known DB error strings.
    Returns (dbms_name, matched_pattern) or None.
    """
    for dbms, patterns in _COMPILED_SIGNATURES.items():
        for pattern in patterns:
            m = pattern.search(body)
            if m:
                return (dbms, m.group(0)[:80])   # cap match length
    return None


# ── Timing analysis ───────────────────────────────────────────────────────────

def is_significant_delay(baseline_times: list[float],
                         observed: float,
                         expected_delay: float = 5.0,
                         threshold: float = 4.5) -> bool:
    """
    Returns True if `observed` is significantly longer than the baseline,
    adjusted for expected injection delay.

    We use mean + 2*stdev of baseline as the upper bound, then check
    if observed exceeds (upper_bound + threshold).
    """
    if not baseline_times:
        return observed >= threshold

    mean = sum(baseline_times) / len(baseline_times)
    variance = sum((t - mean) ** 2 for t in baseline_times) / len(baseline_times)
    stdev = variance ** 0.5

    upper_bound = mean + (2 * stdev)
    return observed >= (upper_bound + threshold)
