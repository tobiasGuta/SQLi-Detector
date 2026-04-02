"""
error_based.py — Error-based SQL injection detection.

Strategy:
  Inject characters that break SQL string context (quotes, backslash, etc.)
  and look for known DBMS error messages in the response.

  This is purely observational — we read what the server returns.
  No data is modified.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from requester import Requester, inject_param_get, inject_param_post
from analyzer import find_error_signature

logger = logging.getLogger(__name__)


@dataclass
class ErrorFinding:
    param: str
    method: str
    payload: str
    dbms: str
    matched_pattern: str
    confidence: float
    evidence: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.confidence >= 0.6


def detect_error_based(
    url: str,
    param: str,
    original_value: str,
    probes: list[str],
    requester: Requester,
    method: str = "GET",
    post_data: dict = None,
) -> Optional[ErrorFinding]:
    """
    Run error-based detection on a single parameter.
    Returns an ErrorFinding if a DB error signature is found, else None.
    """

    # First get baseline body so we don't false-positive on errors
    # that already exist in the page
    if method == "GET":
        baseline = requester.get(url, param=param)
    else:
        baseline = requester.post(url, data=post_data, param=param)

    if baseline.error:
        logger.warning(f"[error] Baseline failed for param={param}: {baseline.error}")
        return None

    # Pre-check: if baseline already has error signatures, skip
    if find_error_signature(baseline.body):
        logger.debug(f"[error] Skipping param={param}: error signatures in baseline")
        return None

    for probe in probes:
        injected_val = original_value + probe

        if method == "GET":
            inj_url = inject_param_get(url, param, injected_val)
            resp = requester.get(inj_url, param=param, payload=probe)
        else:
            inj_data = inject_param_post(post_data, param, injected_val)
            resp = requester.post(url, data=inj_data, param=param, payload=probe)

        if resp.error or not resp.body:
            continue

        match = find_error_signature(resp.body)
        if match:
            dbms, pattern = match
            # Confidence depends on specificity: Generic is lower confidence
            confidence = 0.90 if dbms != "Generic" else 0.65

            logger.info(
                f"[error] HIT param={param} dbms={dbms} "
                f"pattern='{pattern}' payload='{probe}'"
            )
            return ErrorFinding(
                param=param,
                method=method,
                payload=probe,
                dbms=dbms,
                matched_pattern=pattern,
                confidence=confidence,
                evidence=(
                    f"DB error signature detected: '{pattern}' "
                    f"(DBMS fingerprint: {dbms})"
                ),
            )

    return None
