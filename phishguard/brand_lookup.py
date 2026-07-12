from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


WIKI_SUMMARY_API = "https://en.wikipedia.org/api/rest_v1/page/summary/{}"
WIKI_ACTION_API = "https://en.wikipedia.org/w/api.php"

LABEL_MATCHERS = [
    ("chief executive", "CEO"),
    ("ceo", "CEO"),
    ("founder", "Founder"),
    ("parent", "Parent Company"),
    ("industry", "Industry"),
    ("type", "Type"),
    ("founded", "Founded"),
    ("foundation", "Founded"),
    ("headquarters", "Headquarters"),
    ("net income", "Net Income"),
    ("total assets", "Total Assets"),
    ("revenue", "Revenue"),
    ("number of employees", "Employees"),
    ("employees", "Employees"),
    ("key people", "Key People"),
]

FIELD_ORDER = [
    "CEO",
    "Founder",
    "Parent Company",
    "Industry",
    "Type",
    "Founded",
    "Headquarters",
    "Revenue",
    "Net Income",
    "Total Assets",
    "Employees",
    "Key People",
]


@dataclass
class BrandInfo:
    title: str
    description: str | None
    summary: str
    url: str
    facts: dict[str, str] = field(default_factory=dict)
    verdict: str = "approved"
    verdict_reason: str = ""


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
    url = f"{WIKI_ACTION_API}?{urllib.parse.urlencode(params)}"
    data = _http_get_json(url, timeout=timeout)
    results = data.get("query", {}).get("search", [])
    if not results:
        return None
    return results[0]["title"]


def _strip_html(text: str) -> str:
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<sup[^>]*>.*?</sup>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"^(Increase|Decrease|Steady)\s+", "", text.strip())
    text = re.sub(r"\s+", " ", text).strip(" ,;")
    return text


def _fetch_infobox(title: str, timeout: float = 8.0) -> dict[str, str]:
    params = {
        "action": "parse",
        "page": title,
        "prop": "text",
        "section": "0",
        "format": "json",
        "formatversion": "2",
    }
    url = f"{WIKI_ACTION_API}?{urllib.parse.urlencode(params)}"
    try:
        data = _http_get_json(url, timeout=timeout)
        page_html = data.get("parse", {}).get("text", "")
    except Exception:
        return {}

    table_match = re.search(r'<table class="infobox[^"]*"[^>]*>(.*?)</table>', page_html, re.DOTALL)
    if not table_match:
        return {}

    rows = re.findall(r"<tr>(.*?)</tr>", table_match.group(1), re.DOTALL)
    raw_facts: dict[str, str] = {}
    for row in rows:
        th_match = re.search(r"<th[^>]*>(.*?)</th>", row, re.DOTALL)
        td_match = re.search(r"<td[^>]*>(.*?)</td>", row, re.DOTALL)
        if not th_match or not td_match:
            continue
        label = _strip_html(th_match.group(1)).lower()
        value = _strip_html(td_match.group(1))
        if not label or not value:
            continue
        for keyword, canonical in LABEL_MATCHERS:
            if keyword in label:
                if canonical not in raw_facts:
                    raw_facts[canonical] = value[:160]
                break

    return {label: raw_facts[label] for label in FIELD_ORDER if label in raw_facts}


def lookup_brand(name: str, timeout: float = 8.0) -> BrandInfo:
    name = name.strip()
    if not name:
        raise ValueError("Enter a company or brand name.")

    try:
        title = _search_title(name, timeout=timeout)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("No internet connection or Wikipedia is unreachable.") from exc

    if title is None:
        return BrandInfo(
            title=name,
            description=None,
            summary="No matching company or brand was found on Wikipedia.",
            url="",
            verdict="rejected",
            verdict_reason="Not a recognized, verifiable company or brand name.",
        )

    encoded = urllib.parse.quote(title.replace(" ", "_"))
    try:
        data = _http_get_json(WIKI_SUMMARY_API.format(encoded), timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return BrandInfo(
                title=name,
                description=None,
                summary="No matching company or brand was found on Wikipedia.",
                url="",
                verdict="rejected",
                verdict_reason="Not a recognized, verifiable company or brand name.",
            )
        raise RuntimeError(f"Lookup failed for '{name}' (HTTP {exc.code}).") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("No internet connection or Wikipedia is unreachable.") from exc

    if data.get("type") == "disambiguation":
        return BrandInfo(
            title=name,
            description=None,
            summary=f"'{name}' matches multiple entries and cannot be uniquely verified.",
            url=data.get("content_urls", {}).get("desktop", {}).get("page", ""),
            verdict="doubtful",
            verdict_reason="Ambiguous name. Try a more specific name, e.g. add 'company'.",
        )

    facts = _fetch_infobox(title, timeout=timeout)
    extract = data.get("extract") or ""

    if len(facts) >= 2 and len(extract) > 200:
        verdict = "approved"
        reason = "Found as a documented, verifiable entity on Wikipedia."
    elif extract:
        verdict = "doubtful"
        reason = "Found on Wikipedia, but with limited verifiable details."
    else:
        verdict = "doubtful"
        reason = "Matched a page, but could not confirm this is an established company."

    return BrandInfo(
        title=data.get("title", title),
        description=data.get("description"),
        summary=extract or "No summary available.",
        url=data.get("content_urls", {}).get("desktop", {}).get("page")
        or f"https://en.wikipedia.org/wiki/{encoded}",
        facts=facts,
        verdict=verdict,
        verdict_reason=reason,
    )
