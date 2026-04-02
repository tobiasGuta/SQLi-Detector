"""
Global configuration for SQLi Detector.
All values can be overridden via CLI flags.
"""

# ── Request settings ──────────────────────────────────────────────────────────
DEFAULT_TIMEOUT       = 10        # seconds per request
DEFAULT_DELAY         = 0.5       # seconds between requests (be polite)
DEFAULT_RETRIES       = 2
DEFAULT_USER_AGENT    = (
    "SQLiDetector/1.0 (Security Research; detection-only; "
    "https://github.com/your-org/sqli-detector)"
)

# ── Detection thresholds ──────────────────────────────────────────────────────
BOOLEAN_DIFF_THRESHOLD    = 0.10   # >10% body length diff = suspicious
TIME_DELAY_THRESHOLD      = 4.5    # seconds — must exceed baseline by this much
TIME_BASELINE_SAMPLES     = 3      # number of baseline timing samples
MIN_CONFIDENCE            = 0.6    # minimum confidence to report a finding

# ── Scope ─────────────────────────────────────────────────────────────────────
ALLOWED_SCHEMES           = {"http", "https"}
MAX_PARAM_VALUE_LENGTH    = 512    # don't inject into huge values

# ── Output ────────────────────────────────────────────────────────────────────
REPORT_DIR                = "./reports"
