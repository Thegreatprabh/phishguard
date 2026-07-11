from __future__ import annotations

import re
import ssl
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .html_analysis import analyze_html
from .models import ScanResult
from .url_analysis import analyze_url, normalize_url


URL_RE = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>'\")\]]+|\b[a-z0-9][a-z0-9.-]+\.(?:com|net|org|io|dev|app|xyz|top|click|zip|mov|live|support|work|info|co)\b[^\s<>'\")\]]*"
)


def scan_url(url: str, fetch: bool = False, timeout: float = 8.0) -> ScanResult:
    result = analyze_url(url)
    if not fetch:
        return result
    try:
        html = fetch_html(url, timeout=timeout)
    except RuntimeError as exc:
        result.add("fetch_failed", str(exc), 4)
        return result
    result.merge(analyze_html(html, page_url=normalize_url(url)))
    return result


def scan_html(html: str, page_url: str | None = None) -> ScanResult:
    return analyze_html(html, page_url=page_url)


def scan_text(text: str, target: str = "[text]") -> ScanResult:
    result = ScanResult(target=target, kind="text")
    urls = extract_urls(text)
    for url in urls:
        result.merge(analyze_url(url))
    lowered = text.lower()
    if any(term in lowered for term in ("verify your account", "account suspended", "urgent action required")):
        result.add("urgent_account_language", "Text contains common account takeover urgency language.", 14)
    if any(term in lowered for term in ("password", "otp", "recovery code", "personal access token")) and urls:
        result.add("credential_request_with_link", "Text requests sensitive credentials and includes a link.", 24)
    return result


def scan_file(path: Path, page_url: str | None = None) -> ScanResult:
    data = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".html", ".htm"}:
        return scan_html(data, page_url=page_url)
    return scan_text(data, target=str(path))


def extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        url = match.group(0).rstrip(".,;:")
        if url.startswith("www."):
            url = f"https://{url}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def fetch_html(url: str, timeout: float = 8.0) -> str:
    request = Request(
        normalize_url(url),
        headers={
            "User-Agent": "PhishGuard/0.1 (+https://github.com/)",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type and "text/plain" not in content_type:
                raise RuntimeError(f"unexpected content type: {content_type or 'unknown'}")
            body = response.read(1_000_000)
    except URLError as exc:
        raise RuntimeError(f"could not fetch URL: {exc}") from exc
    return body.decode("utf-8", errors="replace")

