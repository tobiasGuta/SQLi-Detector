"""
requester.py — HTTP engine for SQLi Detector.

Handles:
  - Session management
  - Rate limiting (be a good citizen)
  - Retries with backoff
  - Custom headers / cookies
  - Response normalization
"""

import time
import random
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import (
    DEFAULT_TIMEOUT,
    DEFAULT_DELAY,
    DEFAULT_RETRIES,
    DEFAULT_USER_AGENT,
)

logger = logging.getLogger(__name__)


@dataclass
class Response:
    url: str
    status_code: int
    body: str
    headers: dict
    elapsed: float          # seconds
    payload: str = ""
    param: str = ""
    error: Optional[str] = None

    @property
    def body_length(self) -> int:
        return len(self.body)


@dataclass
class RequestConfig:
    timeout: float = DEFAULT_TIMEOUT
    delay: float = DEFAULT_DELAY
    retries: int = DEFAULT_RETRIES
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    proxies: dict = field(default_factory=dict)
    verify_ssl: bool = True
    jitter: bool = True       # add random delay jitter to avoid pattern detection


class Requester:
    def __init__(self, config: RequestConfig):
        self.config = config
        self.session = self._build_session()
        self._last_request_time = 0.0

    def _build_session(self) -> requests.Session:
        session = requests.Session()

        # Retry on connection errors and 5xx — NOT on 4xx (those are meaningful)
        retry = Retry(
            total=self.config.retries,
            backoff_factor=1.0,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": self.config.user_agent,
            **self.config.headers,
        })
        session.cookies.update(self.config.cookies)
        session.verify = self.config.verify_ssl

        if self.config.proxies:
            session.proxies = self.config.proxies

        return session

    def _rate_limit(self):
        """Enforce minimum delay between requests."""
        elapsed = time.time() - self._last_request_time
        delay = self.config.delay
        if self.config.jitter:
            delay += random.uniform(0, delay * 0.3)   # up to 30% jitter
        if elapsed < delay:
            time.sleep(delay - elapsed)

    def get(self, url: str, params: dict = None,
            payload: str = "", param: str = "") -> Response:
        self._rate_limit()
        start = time.time()
        try:
            r = self.session.get(
                url,
                params=params,
                timeout=self.config.timeout,
            )
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return Response(
                url=r.url,
                status_code=r.status_code,
                body=r.text,
                headers=dict(r.headers),
                elapsed=elapsed,
                payload=payload,
                param=param,
            )
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            self._last_request_time = time.time()
            # Timeout IS a signal for time-based detection — return it
            return Response(
                url=url, status_code=0, body="",
                headers={}, elapsed=elapsed,
                payload=payload, param=param,
                error="timeout",
            )
        except requests.exceptions.RequestException as e:
            self._last_request_time = time.time()
            return Response(
                url=url, status_code=0, body="",
                headers={}, elapsed=0,
                payload=payload, param=param,
                error=str(e),
            )

    def post(self, url: str, data: dict = None,
             json: dict = None, payload: str = "",
             param: str = "") -> Response:
        self._rate_limit()
        start = time.time()
        try:
            r = self.session.post(
                url,
                data=data,
                json=json,
                timeout=self.config.timeout,
            )
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return Response(
                url=r.url,
                status_code=r.status_code,
                body=r.text,
                headers=dict(r.headers),
                elapsed=elapsed,
                payload=payload,
                param=param,
            )
        except requests.exceptions.Timeout:
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return Response(
                url=url, status_code=0, body="",
                headers={}, elapsed=elapsed,
                payload=payload, param=param,
                error="timeout",
            )
        except requests.exceptions.RequestException as e:
            self._last_request_time = time.time()
            return Response(
                url=url, status_code=0, body="",
                headers={}, elapsed=0,
                payload=payload, param=param,
                error=str(e),
            )


def inject_param_get(url: str, param: str, value: str) -> str:
    """Return a new URL with `param` replaced by `value`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def inject_param_post(data: dict, param: str, value: str) -> dict:
    """Return a new POST body dict with `param` replaced by `value`."""
    new_data = dict(data)
    new_data[param] = value
    return new_data
