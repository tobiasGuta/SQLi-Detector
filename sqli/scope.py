from urllib.parse import urlparse
from config import ALLOWED_SCHEMES

class OutOfScopeError(Exception):
    pass

class Scope:
    def __init__(self, allowed_hosts: list[str]):
        self.allowed_hosts = [h.lower() for h in allowed_hosts]

    def check(self, url: str) -> None:
        parsed = urlparse(url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            raise OutOfScopeError(f"Scheme '{parsed.scheme}' not allowed")

        if not self.allowed_hosts:
            return

        host = parsed.hostname

        if not host:
            raise OutOfScopeError(f"Invalid URL: {url}")
            
        if host.lower() not in self.allowed_hosts:
            raise OutOfScopeError(f"Host '{host}' is not in the allowed scope: {self.allowed_hosts}")
