from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


WIKI_SUMMARY_API = "https://en.wikipedia.org/api/rest_v1/page/summary/{}"
WIKI_SEARCH_API = "https://en.wikipedia.org/w/api.php"


@dataclass
class BrandInfo:
    title: str
    description: str | None
    summary: str
    url: str


def _http_get_json(url: str, timeout: float = 8.0) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "PhishGuard/0.1 (brand-lookup)"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _search_title(query: str, timeout: float = 8.0) -> str | None:
    params = {
        "action": "query",
        "list": "search",
        "srsearch": query,
        "format": "json",
        "srlimit": "1",
    }
    url = f"{WIKI_SEARCH_API}?{urllib.parse.urlencode(params)}"
    data = _http_get_json(url, timeout=timeout)
    results = data.get("query", {}).get("search", [])
    if not results:
        return None
    return results[0]["title"]


def lookup_brand(name: str, timeout: float = 8.0) -> BrandInfo:
    name = name.strip()
    if not name:
        raise ValueError("Enter a company or brand name.")

    try:
        title = _search_title(name, timeout=timeout) or name
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("No internet connection or Wikipedia is unreachable.") from exc

    encoded = urllib.parse.quote(title.replace(" ", "_"))
    try:
        data = _http_get_json(WIKI_SUMMARY_API.format(encoded), timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(f"No information found for '{name}'.") from exc
        raise RuntimeError(f"Lookup failed for '{name}' (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("No internet connection or Wikipedia is unreachable.") from exc

    if data.get("type") == "disambiguation":
        raise RuntimeError(f"'{name}' is ambiguous. Try a more specific name, e.g. add 'company'.")

    return BrandInfo(
        title=data.get("title", title),
        description=data.get("description"),
        summary=data.get("extract") or "No summary available.",
        url=data.get("content_urls", {}).get("desktop", {}).get("page")
        or f"https://en.wikipedia.org/wiki/{encoded}",
    )
