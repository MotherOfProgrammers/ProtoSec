from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


SECURITY_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)
RATE_LIMIT_HEADERS = (
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _validated_origin(url: str, authorized: bool) -> tuple[str, str]:
    try:
        parsed = urlsplit(url.strip())
        host = (parsed.hostname or "").rstrip(".").casefold()
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS origin.") from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Enter only an HTTP or HTTPS origin without credentials, path, or query.")
    is_local = host in _LOCAL_HOSTS or host.endswith(".localhost")
    if not is_local and not authorized:
        raise PermissionError(
            "For non-local hosts, confirm that you own or are authorized to check this staging site."
        )
    origin = f"{parsed.scheme.lower()}://{parsed.netloc}"
    return origin, parsed.scheme.lower()


def probe_security_headers(url: str, authorized: bool = False) -> dict:
    """Make one HEAD request and report security headers without fetching a body."""
    origin, scheme = _validated_origin(url, authorized)
    request = Request(
        origin,
        method="HEAD",
        headers={"User-Agent": "ProtoSec passive header check"},
    )
    opener = build_opener(_NoRedirectHandler)
    try:
        response = opener.open(request, timeout=5)
        try:
            status = response.status
            response_headers = response.headers
        finally:
            response.close()
    except HTTPError as response:
        try:
            status = response.code
            response_headers = response.headers
        finally:
            response.close()
    except URLError as exc:
        raise RuntimeError(f"Could not reach the supplied origin: {exc.reason}") from exc

    headers = {
        name: response_headers.get(name)
        for name in (*SECURITY_HEADERS, "Strict-Transport-Security", *RATE_LIMIT_HEADERS)
    }
    checks = [
        {
            "header": name,
            "present": bool(headers[name]),
            "value": headers[name],
        }
        for name in SECURITY_HEADERS
    ]
    hsts = headers["Strict-Transport-Security"]
    checks.append({
        "header": "Strict-Transport-Security",
        "present": bool(hsts) if scheme == "https" else None,
        "value": hsts,
        "note": "Not applicable to plain HTTP." if scheme != "https" else "",
    })
    return {
        "origin": origin,
        "status": status,
        "method": "HEAD",
        "body_fetched": False,
        "checks": checks,
        "rate_limit_headers": {
            name: headers[name] for name in RATE_LIMIT_HEADERS if headers[name]
        },
        "rate_limit_enforcement_tested": False,
    }
