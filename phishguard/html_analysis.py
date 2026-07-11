from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .brands import BRANDS
from .models import BrandProfile, ScanResult
from .url_analysis import analyze_url, is_trusted_brand_host


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.text_parts: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.current_form: dict[str, object] | None = None
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.external_scripts: list[str] = []
        self.links: list[str] = []
        self._in_title = False
        self._skip_text = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in {"script", "style"}:
            self._skip_text = True
            if tag == "script" and attr.get("src"):
                self.external_scripts.append(attr["src"])
        elif tag == "form":
            self.current_form = {"action": attr.get("action", ""), "inputs": []}
            self.forms.append(self.current_form)
        elif tag == "input":
            input_type = attr.get("type", "text").lower()
            input_name = attr.get("name") or attr.get("id") or ""
            if input_type == "password":
                self.password_inputs += 1
            if input_type == "hidden":
                self.hidden_inputs += 1
            if self.current_form is not None:
                inputs = self.current_form.setdefault("inputs", [])
                assert isinstance(inputs, list)
                inputs.append({"type": input_type, "name": input_name})
        elif tag == "a" and attr.get("href"):
            self.links.append(attr["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag in {"script", "style"}:
            self._skip_text = False
        elif tag == "form":
            self.current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if not self._skip_text and data.strip():
            self.text_parts.append(data.strip())

    @property
    def visible_text(self) -> str:
        return " ".join(self.text_parts)


def analyze_html(html: str, page_url: str | None = None) -> ScanResult:
    target = page_url or "[html]"
    result = ScanResult(target=target, kind="html")
    parser = PageParser()
    parser.feed(html)

    if page_url:
        result.merge(analyze_url(page_url))

    text = _squash(f"{parser.title} {parser.visible_text}")
    host = (urlparse(page_url).hostname or "").lower() if page_url else ""

    brand = detect_brand_in_html(text)
    if brand and (not host or not is_trusted_brand_host(host, brand)):
        result.brand = brand.name
        result.category = "fake_social_login"
        result.add(
            "brand_page_on_untrusted_domain",
            f"{brand.name} page text found outside official domains.",
            30,
        )

    if parser.password_inputs:
        result.add("password_form", f"Page contains {parser.password_inputs} password input(s).", 22)
    if parser.hidden_inputs >= 3:
        result.add("many_hidden_inputs", "Page contains multiple hidden inputs.", 8)

    credential_terms = _find_terms(
        text,
        (
            "password",
            "passcode",
            "otp",
            "one time password",
            "two-factor",
            "2fa",
            "recovery code",
            "backup code",
            "personal access token",
            "seed phrase",
        ),
    )
    if len(credential_terms) >= 2:
        result.add("credential_collection_text", f"Page asks for sensitive values: {', '.join(credential_terms[:5])}.", 20)

    bait_terms: list[str] = []
    for profile in BRANDS:
        bait_terms.extend(profile.bait_terms)
    bait_hits = _find_terms(text, tuple(sorted(set(bait_terms))))
    if bait_hits:
        result.add("social_engineering_bait", f"Page uses bait phrase(s): {', '.join(bait_hits[:4])}.", 14)

    suspicious_actions = _suspicious_form_actions(parser.forms, page_url, brand)
    for action in suspicious_actions[:3]:
        result.add("suspicious_form_action", action, 24)

    if _looks_obfuscated(html):
        result.add("obfuscated_script", "Page contains JavaScript patterns often used for obfuscation.", 14)

    if result.brand and parser.password_inputs and result.risk != "dangerous":
        result.add("brand_login_combo", "Brand impersonation is combined with a password form.", 18)

    return result


def detect_brand_in_html(text: str) -> BrandProfile | None:
    lowered = text.lower()
    best: tuple[int, BrandProfile] | None = None
    for brand in BRANDS:
        hits = sum(1 for keyword in brand.keywords if keyword in lowered)
        hits += sum(1 for term in brand.login_terms if term in lowered)
        hits += sum(1 for term in brand.bait_terms if term in lowered)
        if hits and (best is None or hits > best[0]):
            best = (hits, brand)
    return best[1] if best else None


def _suspicious_form_actions(
    forms: list[dict[str, object]],
    page_url: str | None,
    brand: BrandProfile | None,
) -> list[str]:
    messages: list[str] = []
    page_host = (urlparse(page_url).hostname or "").lower() if page_url else ""
    for form in forms:
        action = str(form.get("action") or "").strip()
        inputs = form.get("inputs") or []
        has_password = any(isinstance(item, dict) and item.get("type") == "password" for item in inputs)
        if not has_password:
            continue
        if not action:
            continue
        absolute = urljoin(page_url or "https://local.invalid/", action)
        action_host = (urlparse(absolute).hostname or "").lower()
        if action_host and page_host and action_host != page_host:
            messages.append(f"Password form submits to a different host: {action_host}.")
        if brand and action_host and not is_trusted_brand_host(action_host, brand):
            messages.append(f"Password form action is not an official {brand.name} domain: {action_host}.")
    return messages


def _find_terms(text: str, terms: tuple[str, ...]) -> list[str]:
    lowered = text.lower()
    return sorted({term for term in terms if term in lowered})


def _looks_obfuscated(html: str) -> bool:
    lowered = html.lower()
    if "eval(" in lowered and ("atob(" in lowered or "fromcharcode" in lowered):
        return True
    base64_chunks = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", html)
    return len(base64_chunks) >= 2


def _squash(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()

