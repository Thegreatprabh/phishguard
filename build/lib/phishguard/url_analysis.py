from __future__ import annotations

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, unquote, urlparse

from .brands import BRANDS
from .models import BrandProfile, ScanResult


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "rb.gy",
    "s.id",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "work",
    "support",
    "quest",
    "rest",
    "cam",
    "icu",
    "live",
}

BAIT_WORDS = {
    "login",
    "signin",
    "verify",
    "secure",
    "security",
    "account",
    "password",
    "reset",
    "update",
    "unlock",
    "appeal",
    "copyright",
    "support",
    "wallet",
    "airdrop",
    "bonus",
    "free",
    "gift",
    "nitro",
}


def analyze_url(raw_url: str) -> ScanResult:
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().strip(".")
    path_query = unquote(f"{parsed.path}?{parsed.query}").lower()
    result = ScanResult(target=raw_url, kind="url")

    if not parsed.scheme or parsed.scheme not in {"http", "https"}:
        result.add("unsupported_scheme", "URL does not use http or https.", 15)
    if parsed.scheme == "http":
        result.add("plain_http", "URL uses unencrypted HTTP.", 12)
    if "@" in parsed.netloc:
        result.add("userinfo_trick", "URL contains an @ sign before the host.", 30)
    if host.startswith("xn--") or ".xn--" in host:
        result.add("punycode_domain", "Domain uses punycode, which can hide lookalike characters.", 25)
    if _is_ip_address(host):
        result.add("ip_host", "URL host is an IP address instead of a domain.", 18)
    if host.count(".") >= 4:
        result.add("deep_subdomain", "URL uses many subdomain levels.", 12)
    if parsed.port and parsed.port not in {80, 443}:
        result.add("unusual_port", f"URL uses unusual port {parsed.port}.", 10)
    if host in SHORTENER_DOMAINS:
        result.add("url_shortener", "URL uses a known link shortener.", 16)
    if _tld(host) in SUSPICIOUS_TLDS:
        result.add("risky_tld", f"Domain uses .{_tld(host)} TLD often abused in phishing.", 10)
    if len(raw_url) > 120:
        result.add("long_url", "URL is unusually long.", 8)
    if "%" in raw_url or any(item in raw_url.lower() for item in ("%2f", "%40", "%3a")):
        result.add("encoded_payload", "URL contains encoded characters often used to hide payloads.", 10)

    bait_hits = sorted(word for word in BAIT_WORDS if word in path_query or word in host)
    if len(bait_hits) >= 2:
        result.add("bait_keywords", f"URL contains phishing bait words: {', '.join(bait_hits[:6])}.", 12)

    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        joined = f"{key}={value}".lower()
        if any(term in joined for term in ("password", "token", "otp", "code", "session", "redirect", "continue")):
            result.add("sensitive_query", f"Query parameter looks sensitive: {key}.", 12)
            break

    brand = detect_brand_in_url(host, path_query)
    if brand and not is_trusted_brand_host(host, brand):
        result.brand = brand.name
        result.category = "brand_impersonation"
        result.add(
            "brand_on_untrusted_domain",
            f"{brand.name} terms found on non-official domain {host or '[missing host]'}.",
            35,
        )
        if len(bait_hits) >= 2:
            result.add(
                "brand_bait_combo",
                f"{brand.name} impersonation appears with login or verification bait.",
                18,
            )

    lookalike = detect_lookalike_brand(host)
    if lookalike and not is_trusted_brand_host(host, lookalike):
        result.brand = result.brand or lookalike.name
        result.category = "brand_impersonation"
        result.add("lookalike_domain", f"Domain appears similar to {lookalike.name}.", 32)

    return result


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw_url, flags=re.I):
        return f"https://{raw_url}"
    return raw_url


def is_trusted_brand_host(host: str, brand: BrandProfile) -> bool:
    host = host.lower().strip(".")
    return any(host == domain or host.endswith(f".{domain}") for domain in brand.trusted_domains)


def detect_brand_in_url(host: str, path_query: str) -> BrandProfile | None:
    haystack = f"{host} {path_query}".lower()
    for brand in BRANDS:
        if any(keyword in haystack for keyword in brand.keywords):
            return brand
    return None


def detect_lookalike_brand(host: str) -> BrandProfile | None:
    if not host:
        return None
    registrable = _registrable_domain(host).split(".")[0].lower()
    candidates = [registrable]
    candidates.extend(part for part in re.split(r"[-_]", registrable) if part)
    compact_candidates = [re.sub(r"[^a-z0-9]", "", item) for item in candidates]
    compact_candidates = [item for item in compact_candidates if len(item) >= 4]
    if not compact_candidates:
        return None
    for brand in BRANDS:
        for domain in brand.trusted_domains:
            official = domain.split(".")[0].replace("-", "")
            for compact in compact_candidates:
                if compact == official:
                    continue
                ratio = SequenceMatcher(None, compact, official).ratio()
                if ratio >= 0.82:
                    return brand
    return None


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _tld(host: str) -> str:
    parts = host.rsplit(".", 1)
    return parts[-1] if len(parts) == 2 else ""


def _registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])
