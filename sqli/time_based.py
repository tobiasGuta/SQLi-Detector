"""
time_based.py — Time-delay SQL injection detection.

Strategy:
  1. Measure baseline response times (multiple samples).
  2. Inject time-delay payloads (SLEEP, pg_sleep, WAITFOR DELAY).
  3. If observed delay significantly exceeds baseline + threshold → SQLi.

SLEEP/pg_sleep/WAITFOR are read-only. No data is modified or deleted.
We test with a 5-second delay which is clearly distinguishable from noise.
"""

import logging
import statistics
from dataclasses import dataclass
from typing import Optional

from requester import Requester, inject_param_get, inject_param_post
from analyzer import is_significant_delay
from config import TIME_BASELINE_SAMPLES, TIME_DELAY_THRESHOLD

logger = logging.getLogger(__name__)

EXPECTED_DELAY = 5.0   # seconds we ask the DB to sleep


@dataclass
class TimeFinding:
    param: str
    method: str
    payload: str
    dbms_hint: str
    baseline_mean: float
    observed_elapsed: float
    confidence: float
    evidence: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.confidence >= 0.6


def detect_time_based(
    url: str,
    param: str,
    original_value: str,
    probes_by_dbms: dict[str, list[str]],
    requester: Requester,
    method: str = "GET",
    post_data: dict = None,
) -> Optional[TimeFinding]:
    """
    Run time-based detection on a single parameter.
    Returns a TimeFinding if a significant delay is detected, else None.
    """

    # ── 1. Collect baseline timing samples ────────────────────────────────────
    logger.debug(f"[time] Collecting {TIME_BASELINE_SAMPLES} baseline samples for param={param}")
    baseline_times = []
    for _ in range(TIME_BASELINE_SAMPLES):
        if method == "GET":
            resp = requester.get(url, param=param, payload=original_value)
        else:
            resp = requester.post(url, data=post_data, param=param)
        if not resp.error:
            baseline_times.append(resp.elapsed)

    if not baseline_times:
        logger.warning(f"[time] Could not get baseline for param={param}")
        return None

    baseline_mean = statistics.mean(baseline_times)
    logger.debug(f"[time] Baseline mean={baseline_mean:.2f}s for param={param}")

    # ── 2. Try delay payloads per DBMS ────────────────────────────────────────
    for dbms, probes in probes_by_dbms.items():
        for probe in probes:
            injected_val = original_value + probe

            if method == "GET":
                inj_url = inject_param_get(url, param, injected_val)
                resp = requester.get(inj_url, param=param, payload=probe)
            else:
                inj_data = inject_param_post(post_data, param, injected_val)
                resp = requester.post(url, data=inj_data, param=param, payload=probe)

            # A timeout that matches our delay window is also a signal
            significant = is_significant_delay(
                baseline_times,
                observed=resp.elapsed,
                expected_delay=EXPECTED_DELAY,
                threshold=TIME_DELAY_THRESHOLD,
            )

            if significant:
                # Confidence scales with how much larger the delay is vs baseline
                ratio = resp.elapsed / max(baseline_mean, 0.01)
                confidence = min(0.95, 0.50 + min(ratio / 10, 0.45))

                logger.info(
                    f"[time] HIT param={param} dbms={dbms} "
                    f"elapsed={resp.elapsed:.2f}s baseline={baseline_mean:.2f}s "
                    f"conf={confidence:.2f}"
                )
                return TimeFinding(
                    param=param,
                    method=method,
                    payload=probe,
                    dbms_hint=dbms,
                    baseline_mean=round(baseline_mean, 3),
                    observed_elapsed=round(resp.elapsed, 3),
                    confidence=confidence,
                    evidence=(
                        f"Response delayed {resp.elapsed:.1f}s vs baseline "
                        f"{baseline_mean:.1f}s using {dbms} delay probe"
                    ),
                )

    return None
