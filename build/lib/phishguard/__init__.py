"""PhishGuard phishing detection toolkit."""

from .scanner import scan_html, scan_text, scan_url

__all__ = ["scan_html", "scan_text", "scan_url"]
__version__ = "0.1.0"

