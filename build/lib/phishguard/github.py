from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ScanResult
from .scanner import scan_text


TEXT_KEYS = {
    "body",
    "title",
    "name",
    "message",
    "description",
    "comment",
    "text",
    "content",
}


def scan_github_event(path: Path) -> ScanResult:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    fragments = list(_walk_text(data))
    return scan_text("\n".join(fragments), target=str(path))


def _walk_text(value: Any, key: str | None = None) -> list[str]:
    if isinstance(value, dict):
        found: list[str] = []
        for item_key, item_value in value.items():
            found.extend(_walk_text(item_value, str(item_key)))
        return found
    if isinstance(value, list):
        found = []
        for item in value:
            found.extend(_walk_text(item, key))
        return found
    if isinstance(value, str) and (key in TEXT_KEYS or "url" in (key or "").lower()):
        return [value]
    return []

