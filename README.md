# PhishGuard

PhishGuard is a lightweight phishing detection toolkit for suspicious URLs, fake social media login pages, GitHub links, and text messages. It is built for Kali Linux, Termux, GitHub Actions, and regular Python 3.9+ environments with no mandatory third-party dependencies.

> Defensive security tool for learning, awareness, and safer link review.

## GitHub Repository Description

Use this as the short GitHub repo description:

```text
PhishGuard - a lightweight CLI tool to detect phishing URLs, fake social login pages, and suspicious GitHub/social engineering links.
```

Suggested GitHub topics:

```text
phishing cybersecurity osint termux kali-linux github-actions python security-tools url-scanner
```

## What To Say About This Project

PhishGuard helps users quickly check whether a link, message, or HTML page looks suspicious before opening it or trusting it. It detects common phishing signals like fake Instagram/Facebook/GitHub login pages, lookalike domains, password/OTP collection forms, suspicious TLDs, short links, punycode domains, and social engineering bait such as account verification or security alerts.

This tool is useful for:

- Students learning cybersecurity and phishing detection.
- Kali and Termux users who want a simple command-line scanner.
- Developers who want a GitHub Action to catch suspicious links in issues, PRs, docs, or comments.
- Anyone who wants an offline first phishing risk score with clear evidence.

## Features

- URL risk scoring for suspicious domains, typosquatting, punycode, IP hosts, shorteners, odd ports, encoded payloads, and bait keywords.
- Fake social media login page detection for Instagram, Facebook, Google, GitHub, X/Twitter, LinkedIn, Microsoft, and Discord.
- HTML form analysis for password fields, OTP/token collection, suspicious form actions, hidden inputs, obfuscated scripts, and brand impersonation.
- Text scanning for GitHub PRs, issues, markdown, code comments, chat exports, and email-like content.
- JSON output for automation, scripts, and CI.
- GitHub Action workflow included.
- Works without API keys or paid threat-intelligence services.

## Risk Levels

- `safe`: no strong phishing signal found.
- `suspicious`: warning signs found; review before trusting.
- `dangerous`: strong evidence of phishing, fake login, or brand impersonation.

## Install On Kali Linux

```bash
sudo apt update
sudo apt install python3 python3-pip git
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
python3 -m pip install .
phishguard --help
```

Development mode:

```bash
python3 -m pip install -e .
python3 -m unittest discover -v
```

## Install On Termux

```bash
pkg update && pkg upgrade
pkg install python git
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
python -m pip install .
phishguard --help
```

Development mode:

```bash
python -m pip install -e .
python -m unittest discover -v
```

If Termux says the `phishguard` command is not found after install, run:

```bash
python -m phishguard --help
```

## Basic Usage

Scan a URL:

```bash
phishguard scan-url "https://example-login-security.com/instagram/verify"
```

Scan a fake-looking GitHub login link:

```bash
phishguard scan-url "https://github-login-security.xyz/verify"
```

Scan a local HTML page:

```bash
phishguard scan-html suspicious.html --url "https://instagrarn-help.example/login"
```

Scan text, messages, markdown, or copied email content:

```bash
phishguard scan-text message.txt
```

Scan multiple files and fail when a dangerous finding appears:

```bash
phishguard scan-files README.md docs/*.md --fail-on dangerous
```

Print JSON output:

```bash
phishguard scan-url "https://example.com" --json
```

Fetch and analyze live HTML content:

```bash
phishguard scan-url "https://example.com/login" --fetch
```

## Example Output

```text
DANGEROUS  score= 75 kind=url target=https://github-login-security.xyz/verify
  category=brand_impersonation brand=GitHub
  +10 risky_tld: Domain uses .xyz TLD often abused in phishing.
  +12 bait_keywords: URL contains phishing bait words: login, security, verify.
  +35 brand_on_untrusted_domain: GitHub terms found on non-official domain github-login-security.xyz.
  +18 brand_bait_combo: GitHub impersonation appears with login or verification bait.
```

## GitHub Action

This repository includes `.github/workflows/phishguard.yml`.

It scans GitHub event text and repository text-like files, then fails the workflow if a dangerous phishing indicator is found.

The workflow is useful for:

- PR descriptions
- issue bodies
- issue comments
- markdown docs
- pasted links in repository files

## Upload This Project To Your GitHub Profile

If GitHub CLI is installed:

```bash
git init
git add .
git commit -m "Initial PhishGuard release"
gh repo create phishguard --public --source=. --remote=origin --push \
  --description "PhishGuard - a lightweight CLI tool to detect phishing URLs, fake social login pages, and suspicious GitHub/social engineering links."
```

If you do not have GitHub CLI:

1. Create a new public repository named `phishguard` on GitHub.
2. Copy the repository URL.
3. Run:

```bash
git init
git add .
git commit -m "Initial PhishGuard release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/phishguard.git
git push -u origin main
```

Replace `YOUR_USERNAME` with your GitHub username.

## Project Structure

```text
phishguard/
  brands.py         Brand profiles for social/login impersonation checks
  cli.py            Command-line interface
  github.py         GitHub event scanner
  html_analysis.py  Fake login page and suspicious form detection
  models.py         Scan result and evidence models
  scanner.py        High-level scan functions
  url_analysis.py   URL and domain heuristics
tests/
  test_phishguard.py
```

## Safety And Ethics

PhishGuard is a defensive tool. Use it only for education, awareness, link review, CI checks, and protecting systems you own or have permission to test. It does not create phishing pages, steal credentials, bypass authentication, or exploit websites.

PhishGuard uses deterministic heuristics. It can produce false positives or false negatives, so always combine results with human review and trusted threat-intelligence sources when the decision matters.

