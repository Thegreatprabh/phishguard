from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    label: str
    detail: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "detail": self.detail, "score": self.score}


@dataclass
class ScanResult:
    target: str
    kind: str
    score: int = 0
    risk: str = "safe"
    category: str = "clean"
    brand: str | None = None
    evidence: list[Evidence] = field(default_factory=list)

    def add(self, label: str, detail: str, score: int) -> None:
        self.evidence.append(Evidence(label=label, detail=detail, score=score))
        self.score += score
        self._refresh()

    def merge(self, other: "ScanResult") -> None:
        if other.brand and not self.brand:
            self.brand = other.brand
        if other.category != "clean":
            self.category = other.category
        self.evidence.extend(other.evidence)
        self.score += other.score
        self._refresh()

    def _refresh(self) -> None:
        self.score = min(max(self.score, 0), 100)
        if self.score >= 70:
            self.risk = "dangerous"
        elif self.score >= 35:
            self.risk = "suspicious"
        else:
            self.risk = "safe"
        if self.category == "clean" and self.risk != "safe":
            self.category = "phishing_indicator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "risk": self.risk,
            "score": self.score,
            "category": self.category,
            "brand": self.brand,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class BrandProfile:
    name: str
    trusted_domains: tuple[str, ...]
    keywords: tuple[str, ...]
    login_terms: tuple[str, ...] = ("login", "log in", "signin", "sign in", "password")
    bait_terms: tuple[str, ...] = (
        "verify account",
        "security alert",
        "copyright appeal",
        "account suspended",
        "unlock account",
        "confirm identity",
        "two-factor",
        "2fa",
        "otp",
        "recovery code",
        "blue badge",
    )

