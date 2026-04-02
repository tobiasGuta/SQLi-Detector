"""
boolean.py — Boolean-based blind SQL injection detection.

Strategy:
  1. Fetch a baseline response for the original parameter value.
  2. Inject a TRUE condition  → response should look like baseline.
  3. Inject a FALSE condition → response should differ from baseline.
  4. If TRUE ≈ baseline AND FALSE ≠ baseline → SQLi confirmed.

All payloads are read-only. No data is modified.
"""

import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, parse_qs

from requester import Requester, Response, inject_param_get, inject_param_post
from analyzer import diff_responses, DiffResult
from config import BOOLEAN_DIFF_THRESHOLD

logger = logging.getLogger(__name__)


@dataclass
class BooleanFinding:
    param: str
    method: str               # GET | POST
    true_payload: str
    false_payload: str
    true_diff: DiffResult     # diff of TRUE response vs baseline
    false_diff: DiffResult    # diff of FALSE response vs baseline
    confidence: float         # 0.0–1.0
    dbms_hint: Optional[str] = None
    evidence: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.confidence >= 0.6


def detect_boolean(
    url: str,
    param: str,
    original_value: str,
    true_payloads: list[str],
    false_payloads: list[str],
    requester: Requester,
    method: str = "GET",
    post_data: dict = None,
) -> Optional[BooleanFinding]:
    """
    Run boolean-based detection on a single parameter.
    Returns a BooleanFinding if injection is detected, else None.
    """

    # ── 1. Baseline ───────────────────────────────────────────────────────────
    logger.debug(f"[boolean] Baseline for param={param} url={url}")
    if method == "GET":
        baseline = requester.get(url, param=param, payload=original_value)
    else:
        baseline = requester.post(url, data=post_data, param=param, payload=original_value)

    if baseline.error or baseline.status_code == 0:
        logger.warning(f"[boolean] Baseline request failed: {baseline.error}")
        return None

    # ── 2. Try payload pairs ──────────────────────────────────────────────────
    findings = []

    for true_pl, false_pl in zip(true_payloads, false_payloads):
        true_val  = original_value + true_pl
        false_val = original_value + false_pl

        if method == "GET":
            true_url  = inject_param_get(url, param, true_val)
            false_url = inject_param_get(url, param, false_val)
            true_resp  = requester.get(true_url,  param=param, payload=true_pl)
            false_resp = requester.get(false_url, param=param, payload=false_pl)
        else:
            true_data  = inject_param_post(post_data, param, true_val)
            false_data = inject_param_post(post_data, param, false_val)
            true_resp  = requester.post(url, data=true_data,  param=param, payload=true_pl)
            false_resp = requester.post(url, data=false_data, param=param, payload=false_pl)

        if true_resp.error or false_resp.error:
            continue

        true_diff  = diff_responses(
            baseline.body, baseline.status_code,
            true_resp.body, true_resp.status_code,
        )
        false_diff = diff_responses(
            baseline.body, baseline.status_code,
            false_resp.body, false_resp.status_code,
        )

        # Key logic: TRUE and FALSE payloads must produce different results relative to baseline
        true_looks_same  = not true_diff.significant
        false_looks_diff = false_diff.significant

        if true_looks_same != (not false_looks_diff):
            # One matches the baseline, the other does not.
            
            # If TRUE matched the baseline, score based on FALSE difference (AND logic)
            # If FALSE matched the baseline, score based on TRUE difference (OR logic)
            diff_score = false_diff.length_diff_pct if true_looks_same else true_diff.length_diff_pct
            sim_score = true_diff.similarity if true_looks_same else false_diff.similarity
            
            confidence = min(
                0.95,
                0.5 + diff_score + (1 - sim_score) * 0.3
            )
            
            # Formulate the evidence text dynamically based on which logic succeeded (AND vs OR)
            if true_looks_same:
                 evidence = f"AND Logic: TRUE response ≈ baseline ({true_diff.similarity:.3f}), FALSE response ≠ baseline (diff={false_diff.length_diff_pct:.1%})"
            else:
                 evidence = f"OR Logic: TRUE response ≠ baseline (diff={true_diff.length_diff_pct:.1%}), FALSE response ≈ baseline ({false_diff.similarity:.3f})"
                 
            findings.append((confidence, true_pl, false_pl, true_diff, false_diff, evidence))
            logger.info(
                f"[boolean] HIT param={param} conf={confidence:.2f} "
                f"true_sim={true_diff.similarity:.3f} "
                f"false_diff={false_diff.length_diff_pct:.3f}"
            )

    if not findings:
        return None

    # Return the highest-confidence finding
    findings.sort(key=lambda x: x[0], reverse=True)
    conf, true_pl, false_pl, true_diff, false_diff, ev_text = findings[0]

    return BooleanFinding(
        param=param,
        method=method,
        true_payload=true_pl,
        false_payload=false_pl,
        true_diff=true_diff,
        false_diff=false_diff,
        confidence=conf,
        evidence=ev_text,
    )
